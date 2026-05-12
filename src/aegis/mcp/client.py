"""Minimal stdio MCP JSON-RPC client."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import select
import subprocess
import time
from typing import Any


@dataclass(frozen=True)
class McpToolCallResult:
    server_id: str
    server_name: str
    tool: str
    result: dict[str, Any]
    sanitized_context: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "server_name": self.server_name,
            "tool": self.tool,
            "result": self.result,
            "sanitized_context": self.sanitized_context,
        }


class McpProtocolError(RuntimeError):
    pass


class McpStdioClient:
    def __init__(self, argv: list[str], *, timeout_seconds: float = 10.0, max_response_bytes: int = 1_000_000) -> None:
        self.argv = argv
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self._next_id = 1

    def list_tools(self) -> list[dict[str, Any]]:
        with _process(self.argv) as process:
            self._initialize(process)
            result = self._request(process, "tools/list", {})
        tools = result.get("tools", []) if isinstance(result, dict) else []
        if not isinstance(tools, list):
            raise McpProtocolError("MCP tools/list result is invalid")
        return [tool for tool in tools if isinstance(tool, dict)]

    def capabilities(self) -> dict[str, Any]:
        with _process(self.argv) as process:
            result = self._initialize(process)
        capabilities = result.get("capabilities", {}) if isinstance(result, dict) else {}
        if not isinstance(capabilities, dict):
            raise McpProtocolError("MCP initialize capabilities are invalid")
        return capabilities

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with _process(self.argv) as process:
            self._initialize(process)
            result = self._request(process, "tools/call", {"name": name, "arguments": arguments})
        if not isinstance(result, dict):
            raise McpProtocolError("MCP tools/call result is invalid")
        return result

    def list_resources(self) -> dict[str, Any]:
        with _process(self.argv) as process:
            self._initialize(process)
            result = self._request(process, "resources/list", {})
        if not isinstance(result.get("resources", []), list):
            raise McpProtocolError("MCP resources/list result is invalid")
        return result

    def read_resource(self, uri: str) -> dict[str, Any]:
        with _process(self.argv) as process:
            self._initialize(process)
            result = self._request(process, "resources/read", {"uri": uri})
        if not isinstance(result.get("contents", []), list):
            raise McpProtocolError("MCP resources/read result is invalid")
        return result

    def list_prompts(self) -> dict[str, Any]:
        with _process(self.argv) as process:
            self._initialize(process)
            result = self._request(process, "prompts/list", {})
        if not isinstance(result.get("prompts", []), list):
            raise McpProtocolError("MCP prompts/list result is invalid")
        return result

    def get_prompt(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with _process(self.argv) as process:
            self._initialize(process)
            result = self._request(process, "prompts/get", {"name": name, "arguments": arguments})
        if not isinstance(result.get("messages", []), list):
            raise McpProtocolError("MCP prompts/get result is invalid")
        return result

    def _initialize(self, process: subprocess.Popen[bytes]) -> dict[str, Any]:
        return self._request(
            process,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "aegis-agent", "version": "0.1.0"},
            },
        )

    def _request(self, process: subprocess.Popen[bytes], method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        _write_message(process, payload)
        response = _read_message(process, timeout_seconds=self.timeout_seconds, max_response_bytes=self.max_response_bytes)
        if response.get("id") != request_id:
            raise McpProtocolError("MCP response id mismatch")
        if "error" in response:
            raise McpProtocolError(f"MCP error response: {response['error']}")
        result = response.get("result", {})
        if not isinstance(result, dict):
            raise McpProtocolError("MCP response result is invalid")
        return result


class _process:
    def __init__(self, argv: list[str]) -> None:
        self.argv = argv
        self.process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> subprocess.Popen[bytes]:
        self.process = subprocess.Popen(  # noqa: S603 - argv is policy-allowlisted before this client is constructed.
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env={"PATH": os.environ.get("PATH", "")},
        )
        return self.process

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()


def _write_message(process: subprocess.Popen[bytes], payload: dict[str, Any]) -> None:
    if process.stdin is None:
        raise McpProtocolError("MCP process stdin is unavailable")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    frame = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
    process.stdin.write(frame)
    process.stdin.flush()


def _read_message(process: subprocess.Popen[bytes], *, timeout_seconds: float, max_response_bytes: int) -> dict[str, Any]:
    if process.stdout is None:
        raise McpProtocolError("MCP process stdout is unavailable")
    deadline = time.monotonic() + timeout_seconds
    header = _read_until(process.stdout, b"\r\n\r\n", deadline, max_response_bytes=8192)
    length = _content_length(header)
    if length > max_response_bytes:
        raise McpProtocolError("MCP response exceeds maximum size")
    body = _read_exact(process.stdout, length, deadline)
    decoded = json.loads(body.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise McpProtocolError("MCP response must be a JSON object")
    return decoded


def _read_until(stream, delimiter: bytes, deadline: float, *, max_response_bytes: int) -> bytes:  # noqa: ANN001
    chunks = bytearray()
    while delimiter not in chunks:
        if len(chunks) > max_response_bytes:
            raise McpProtocolError("MCP response headers exceed maximum size")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MCP response timed out")
        readable, _, _ = select.select([stream], [], [], remaining)
        if not readable:
            raise TimeoutError("MCP response timed out")
        chunk = os.read(stream.fileno(), 1)
        if not chunk:
            raise McpProtocolError("MCP process closed stdout")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_exact(stream, length: int, deadline: float) -> bytes:  # noqa: ANN001
    chunks = bytearray()
    while len(chunks) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MCP response timed out")
        readable, _, _ = select.select([stream], [], [], remaining)
        if not readable:
            raise TimeoutError("MCP response timed out")
        chunk = os.read(stream.fileno(), length - len(chunks))
        if not chunk:
            raise McpProtocolError("MCP process closed stdout")
        chunks.extend(chunk)
    return bytes(chunks)


def _content_length(header: bytes) -> int:
    for line in header.decode("ascii", errors="replace").splitlines():
        if line.lower().startswith("content-length:"):
            return int(line.split(":", 1)[1].strip())
    raise McpProtocolError("MCP response missing Content-Length header")
