"""Minimal MCP JSON-RPC clients for stdio and Streamable HTTP."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import select
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

from aegis.connectors.http import _open_without_redirects


MCP_PROTOCOL_VERSION = "2025-06-18"


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


class McpStreamableHttpClient:
    def __init__(
        self,
        endpoint_url: str,
        *,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 1_000_000,
        protocol_version: str = MCP_PROTOCOL_VERSION,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.protocol_version = protocol_version
        self._negotiated_protocol_version = protocol_version
        self._session_id: str | None = None
        self._next_id = 1

    def list_tools(self) -> list[dict[str, Any]]:
        result = self._with_session("tools/list", {})
        tools = result.get("tools", []) if isinstance(result, dict) else []
        if not isinstance(tools, list):
            raise McpProtocolError("MCP tools/list result is invalid")
        return [tool for tool in tools if isinstance(tool, dict)]

    def capabilities(self) -> dict[str, Any]:
        result = self._initialize()
        self._initialized()
        capabilities = result.get("capabilities", {}) if isinstance(result, dict) else {}
        if not isinstance(capabilities, dict):
            raise McpProtocolError("MCP initialize capabilities are invalid")
        return capabilities

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self._with_session("tools/call", {"name": name, "arguments": arguments})
        if not isinstance(result, dict):
            raise McpProtocolError("MCP tools/call result is invalid")
        return result

    def list_resources(self) -> dict[str, Any]:
        result = self._with_session("resources/list", {})
        if not isinstance(result.get("resources", []), list):
            raise McpProtocolError("MCP resources/list result is invalid")
        return result

    def read_resource(self, uri: str) -> dict[str, Any]:
        result = self._with_session("resources/read", {"uri": uri})
        if not isinstance(result.get("contents", []), list):
            raise McpProtocolError("MCP resources/read result is invalid")
        return result

    def list_prompts(self) -> dict[str, Any]:
        result = self._with_session("prompts/list", {})
        if not isinstance(result.get("prompts", []), list):
            raise McpProtocolError("MCP prompts/list result is invalid")
        return result

    def get_prompt(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self._with_session("prompts/get", {"name": name, "arguments": arguments})
        if not isinstance(result.get("messages", []), list):
            raise McpProtocolError("MCP prompts/get result is invalid")
        return result

    def _with_session(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._initialize()
        self._initialized()
        return self._request(method, params)

    def _initialize(self) -> dict[str, Any]:
        self._session_id = None
        self._negotiated_protocol_version = self.protocol_version
        self._next_id = 1
        result = self._request(
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "aegis-agent", "version": "0.1.0"},
            },
        )
        negotiated = result.get("protocolVersion") if isinstance(result, dict) else None
        if negotiated:
            self._negotiated_protocol_version = str(negotiated)
        return result

    def _initialized(self) -> None:
        self._notification("notifications/initialized", {})

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        response = self._post_json(payload, request_id=request_id)
        if response.get("id") != request_id:
            raise McpProtocolError("MCP response id mismatch")
        if "error" in response:
            raise McpProtocolError(f"MCP error response: {response['error']}")
        result = response.get("result", {})
        if not isinstance(result, dict):
            raise McpProtocolError("MCP response result is invalid")
        return result

    def _notification(self, method: str, params: dict[str, Any]) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        self._post_json(payload, request_id=None)

    def _post_json(self, payload: dict[str, Any], *, request_id: int | None) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": self._negotiated_protocol_version,
            "User-Agent": "Aegis-Agent/0.1",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        request = Request(self.endpoint_url, data=body, headers=headers, method="POST")
        try:
            response_context = _open_without_redirects(request, timeout=self.timeout_seconds)
        except HTTPError as exc:
            raise McpProtocolError(f"MCP HTTP request failed with status {exc.code}") from exc
        except URLError as exc:
            raise McpProtocolError(f"MCP HTTP request failed: {exc.reason}") from exc
        with response_context as response:
            session_id = response.headers.get("Mcp-Session-Id")
            if session_id:
                self._session_id = session_id
            status = response.getcode()
            if request_id is None and status == 202:
                return {}
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            body_bytes = response.read(self.max_response_bytes + 1)
        if len(body_bytes) > self.max_response_bytes:
            raise McpProtocolError("MCP HTTP response exceeds maximum size")
        if content_type == "application/json":
            return _decode_json_rpc_message(body_bytes)
        if content_type == "text/event-stream":
            if request_id is None:
                return {}
            return _decode_sse_response(body_bytes, request_id=request_id)
        raise McpProtocolError(f"MCP HTTP response content type {content_type!r} is unsupported")


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


def _decode_json_rpc_message(body: bytes) -> dict[str, Any]:
    decoded = json.loads(body.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise McpProtocolError("MCP response must be a JSON object")
    return decoded


def _decode_sse_response(body: bytes, *, request_id: int) -> dict[str, Any]:
    events: list[str] = []
    data_lines: list[str] = []
    for raw_line in body.decode("utf-8", errors="replace").splitlines():
        line = raw_line.rstrip("\r")
        if not line:
            if data_lines:
                events.append("\n".join(data_lines))
                data_lines = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        events.append("\n".join(data_lines))
    for event in events:
        decoded = _decode_json_rpc_message(event.encode("utf-8"))
        if decoded.get("id") == request_id:
            return decoded
    raise McpProtocolError("MCP SSE stream ended before the JSON-RPC response")
