"""Governed local background process registry."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
from typing import Any
from uuid import uuid4
import base64

from aegis.agent.policy_gate import PolicyGate
from aegis.audit.logger import AuditLogger, redact
from aegis.security.context_firewall import redact_secret_values
from aegis.security.policy_engine import PolicyDecisionType, PolicyRequest
from aegis.security.taint import RiskLevel, Sensitivity, now_utc
from aegis.storage.state import ensure_private_dir, ensure_private_file


PROCESS_WRAPPER_CODE = r"""
import base64
try:
    import fcntl
    import pty
    import select
    import struct
    import termios
except Exception:
    fcntl = None
    pty = None
    select = None
    struct = None
    termios = None
import json
import os
import re
import subprocess
import sys
import time

SECRET_PATTERNS = (
    re.compile(r"\b(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\r\n,;]+", re.I),
    re.compile(r"\b((?:Cookie|Set-Cookie)\s*:\s*)[^\r\n]+", re.I),
    re.compile(r"([\"']?(?:api[_ -]?key|password|secret|token|refresh[_ -]?token)[\"']?\s*[:=]\s*)[\"']?([^\"'\s,;}]+)", re.I),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
)

def redact_text(value):
    text = str(value)
    text = SECRET_PATTERNS[0].sub(lambda match: f"{match.group(1)}[REDACTED_VALUE]", text)
    text = SECRET_PATTERNS[1].sub(lambda match: f"{match.group(1)}[REDACTED_VALUE]", text)
    text = SECRET_PATTERNS[2].sub(lambda match: f"{match.group(1)}[REDACTED_VALUE]", text)
    for pattern in SECRET_PATTERNS[3:]:
        text = pattern.sub("[REDACTED_VALUE]", text)
    return text

payload_path = sys.argv[1]
with open(payload_path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
try:
    os.unlink(payload_path)
except OSError:
    pass
argv = payload["argv"]
cwd = payload["cwd"]
log_path = payload["log_path"]
max_log_bytes = int(payload.get("max_log_bytes", 65536))
control_path = payload.get("control_path")
use_pty = bool(payload.get("pty", False))
rows = int(payload.get("rows", 24))
cols = int(payload.get("cols", 80))
env = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"}

def append_log(log, text, written):
    safe = redact_text(text)
    if written < max_log_bytes:
        remaining = max_log_bytes - written
        log.write(safe[:remaining])
        written += min(len(safe), remaining)
        if written >= max_log_bytes:
            log.write("\n[AEGIS_LOG_TRUNCATED]\n")
        log.flush()
    return written

def set_winsize(fd, next_rows, next_cols):
    if fcntl is None or termios is None or struct is None:
        return
    safe_rows = max(1, min(int(next_rows), 1000))
    safe_cols = max(1, min(int(next_cols), 1000))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", safe_rows, safe_cols, 0, 0))

def read_control_events(offset):
    if not control_path:
        return offset, []
    try:
        with open(control_path, "r", encoding="utf-8", errors="replace") as control:
            control.seek(offset)
            lines = control.readlines()
            return control.tell(), lines
    except OSError:
        return offset, []

def apply_control_event(master_fd, line):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return
    kind = event.get("type")
    if kind == "stdin":
        try:
            data = base64.b64decode(str(event.get("data") or ""), validate=True)
        except Exception:
            data = b""
        if data:
            os.write(master_fd, data)
    elif kind == "resize":
        set_winsize(master_fd, int(event.get("rows") or 24), int(event.get("cols") or 80))

def run_pipe(log):
    written = 0
    log.write("aegis_process_started pty=false\n")
    log.flush()
    process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", env=env)
    while True:
        chunk = process.stdout.readline() if process.stdout else ""
        if chunk:
            written = append_log(log, chunk, written)
        elif process.poll() is not None:
            break
    if process.stdout:
        for chunk in process.stdout:
            written = append_log(log, chunk, written)
    return process.returncode or 0

def run_pty(log):
    if pty is None or select is None:
        log.write("aegis_process_error pty_unavailable\n")
        log.flush()
        return 127
    written = 0
    log.write("aegis_process_started pty=true\n")
    log.flush()
    master_fd, slave_fd = pty.openpty()
    set_winsize(master_fd, rows, cols)
    process = subprocess.Popen(argv, cwd=cwd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, text=False, env=env, close_fds=True)
    os.close(slave_fd)
    control_offset = 0
    try:
        while True:
            ready, _, _ = select.select([master_fd], [], [], 0.05)
            if master_fd in ready:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    chunk = b""
                if chunk:
                    written = append_log(log, chunk.decode("utf-8", errors="replace"), written)
            control_offset, lines = read_control_events(control_offset)
            for line in lines:
                apply_control_event(master_fd, line)
            if process.poll() is not None:
                while True:
                    ready, _, _ = select.select([master_fd], [], [], 0)
                    if master_fd not in ready:
                        break
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    written = append_log(log, chunk.decode("utf-8", errors="replace"), written)
                break
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
    return process.returncode or 0

with open(log_path, "a", encoding="utf-8", errors="replace") as log:
    returncode = run_pty(log) if use_pty else run_pipe(log)
    log.write(f"\naegis_process_exited returncode={returncode}\n")
    log.flush()
sys.exit(returncode)
"""


class ProcessRegistry:
    _PROCESS_HANDLES: dict[int, subprocess.Popen[Any]] = {}

    def __init__(
        self,
        state_path: str | Path,
        audit_logger: AuditLogger,
        *,
        allowed_executables: tuple[str, ...],
        workspace: str | Path,
        policy_gate: PolicyGate | None = None,
        max_log_bytes: int = 65536,
    ) -> None:
        self.state_path = Path(state_path)
        self.audit_logger = audit_logger
        self.allowed_executables = tuple(allowed_executables)
        self.workspace = Path(workspace).expanduser().resolve()
        self.policy_gate = policy_gate
        self.max_log_bytes = max(4096, min(int(max_log_bytes), 1_048_576))
        self._handles = self._PROCESS_HANDLES
        ensure_private_file(self.state_path)
        self.log_dir = ensure_private_dir(self.state_path.parent / "process-logs")

    def status(self, *, limit: int = 20) -> dict[str, Any]:
        rows = self._refresh_rows()
        active = [row for row in rows if row.get("status") in {"running", "stop_requested"}]
        return {
            "status": "process_registry_ready",
            "execution_mode": "argv_background_processes",
            "process_count": len(rows),
            "active_process_count": len(active),
            "processes": [_process_summary(row) for row in rows[: max(0, limit)]],
            "allowed_executables": list(self.allowed_executables),
            "allowed_commands": list(self.allowed_executables),
            "raw_command_included": False,
            "raw_shell_history_included": False,
            "raw_secret_values_included": False,
            "pty_supported": _pty_supported(),
            "stdin_streaming_supported": _pty_supported(),
            "terminal_resize_supported": _pty_supported(),
            "pty_attached": any(bool(row.get("pty_attached")) for row in active),
            "implemented_controls": [
                "approval_required_start",
                "argv_only_execution",
                "executable_allowlist",
                "private_redacted_logs",
                "metadata_only_registry",
                "stop_receipts",
                "interactive_pty_attach",
                "stdin_streaming",
                "terminal_resize_events",
            ],
            "remaining_depth_work": [] if _pty_supported() else ["interactive_pty_attach", "stdin_streaming", "terminal_resize_events"],
        }

    def start(
        self,
        argv: list[str] | tuple[str, ...],
        *,
        approved: bool = False,
        actor: str = "operator",
        label: str = "",
        pty: bool = False,
        rows: int = 24,
        cols: int = 80,
    ) -> dict[str, Any]:
        clean_argv = _clean_argv(argv)
        if not approved:
            return {
                "status": "approval_required",
                "reason": "background process start requires explicit approval",
                "approval_required": True,
                "argv_only": True,
                "pty_requested": bool(pty),
                "raw_command_included": False,
                "raw_secret_values_included": False,
            }
        executable = self._validate_executable(clean_argv[0])
        _reject_secret_like_args(clean_argv)
        safe_rows, safe_cols = _validate_terminal_size(rows, cols)
        if pty and not _pty_supported():
            raise RuntimeError("PTY-backed process controls are not available on this platform")
        self._evaluate_policy(actor=actor, operation="start")
        process_id = str(uuid4())
        created_at = now_utc()
        process_dir = ensure_private_dir(self.log_dir / process_id)
        log_path = ensure_private_file(process_dir / "combined.log")
        payload_path = ensure_private_file(process_dir / "payload.json")
        control_path = ensure_private_file(process_dir / "control.jsonl") if pty else None
        wrapper_argv = [sys.executable, "-I", "-c", PROCESS_WRAPPER_CODE, str(payload_path)]
        payload = {
            "argv": [executable, *clean_argv[1:]],
            "cwd": str(self.workspace),
            "log_path": str(log_path),
            "max_log_bytes": self.max_log_bytes,
            "pty": bool(pty),
            "rows": safe_rows,
            "cols": safe_cols,
            "control_path": str(control_path) if control_path is not None else None,
        }
        payload_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        payload_path.chmod(0o600)
        log_path.write_text("", encoding="utf-8")
        log_path.chmod(0o600)
        if control_path is not None:
            control_path.write_text("", encoding="utf-8")
            control_path.chmod(0o600)
        process = subprocess.Popen(  # noqa: S603 - wrapper argv is fixed and validated.
            wrapper_argv,
            cwd=self.workspace,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8"},
        )
        self._handles[process.pid] = process
        row = {
            "id": process_id,
            "pid": process.pid,
            "label": _safe_label(label) or Path(clean_argv[0]).name,
            "status": "running",
            "actor": _safe_label(actor, limit=80) or "operator",
            "executable": Path(clean_argv[0]).name,
            "resolved_executable_sha256": hashlib.sha256(executable.encode("utf-8")).hexdigest(),
            "argv_sha256": _argv_sha256(clean_argv),
            "argv_count": len(clean_argv),
            "workspace": str(self.workspace),
            "log_path": str(log_path),
            "control_path": str(control_path) if control_path is not None else None,
            "max_log_bytes": self.max_log_bytes,
            "created_at": created_at,
            "updated_at": created_at,
            "raw_command_included": False,
            "raw_secret_values_included": False,
            "pty_attached": bool(pty),
            "stdin_streaming": bool(pty),
            "resize_events": bool(pty),
            "terminal_rows": safe_rows if pty else None,
            "terminal_cols": safe_cols if pty else None,
            "stdin_event_count": 0,
            "resize_event_count": 0,
        }
        rows = [row, *[existing for existing in self._read_rows() if existing.get("id") != process_id]]
        self._write_rows(rows)
        receipt = _process_receipt(row, event_type="process.started")
        audit_entry = self.audit_logger.append("process.started", receipt)
        return {
            "ok": True,
            "process": _process_summary(row),
            "receipt": receipt,
            "audit_event_hash": audit_entry["event_hash"],
            "processes": self.status(limit=20),
        }

    def send_input(self, process_id: str, text: str, *, append_newline: bool = True, actor: str = "operator") -> dict[str, Any]:
        row = self._require_row(process_id)
        self._evaluate_policy(actor=actor, operation="stdin")
        refreshed = self._refresh_row(row)
        if refreshed.get("status") not in {"running", "stop_requested"}:
            raise RuntimeError(f"process {process_id!r} is not running")
        if not refreshed.get("pty_attached"):
            raise ValueError("stdin streaming requires a PTY-backed process")
        value = str(text)
        if redact_secret_values(value) != value:
            raise ValueError("secret-like values are not allowed in process stdin")
        payload = value + ("\n" if append_newline else "")
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        self._append_control_event(refreshed, {"type": "stdin", "data": encoded, "created_at": now_utc()})
        refreshed["stdin_event_count"] = int(refreshed.get("stdin_event_count") or 0) + 1
        refreshed["updated_at"] = now_utc()
        self._replace_row(refreshed)
        receipt = {
            **_process_receipt(refreshed, event_type="process.stdin_sent"),
            "actor": _safe_label(actor, limit=80),
            "input_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "input_bytes": len(payload.encode("utf-8")),
            "append_newline": bool(append_newline),
            "raw_input_included": False,
        }
        audit_entry = self.audit_logger.append("process.stdin_sent", receipt)
        return {"ok": True, "process": _process_summary(refreshed), "receipt": receipt, "audit_event_hash": audit_entry["event_hash"]}

    def resize(self, process_id: str, *, rows: int, cols: int, actor: str = "operator") -> dict[str, Any]:
        row = self._require_row(process_id)
        self._evaluate_policy(actor=actor, operation="resize")
        refreshed = self._refresh_row(row)
        if refreshed.get("status") not in {"running", "stop_requested"}:
            raise RuntimeError(f"process {process_id!r} is not running")
        if not refreshed.get("pty_attached"):
            raise ValueError("terminal resize requires a PTY-backed process")
        safe_rows, safe_cols = _validate_terminal_size(rows, cols)
        self._append_control_event(refreshed, {"type": "resize", "rows": safe_rows, "cols": safe_cols, "created_at": now_utc()})
        refreshed["terminal_rows"] = safe_rows
        refreshed["terminal_cols"] = safe_cols
        refreshed["resize_event_count"] = int(refreshed.get("resize_event_count") or 0) + 1
        refreshed["updated_at"] = now_utc()
        self._replace_row(refreshed)
        receipt = {
            **_process_receipt(refreshed, event_type="process.resized"),
            "actor": _safe_label(actor, limit=80),
            "rows": safe_rows,
            "cols": safe_cols,
        }
        audit_entry = self.audit_logger.append("process.resized", receipt)
        return {"ok": True, "process": _process_summary(refreshed), "receipt": receipt, "audit_event_hash": audit_entry["event_hash"]}

    def logs(self, process_id: str, *, max_bytes: int = 4096) -> dict[str, Any]:
        row = self._require_row(process_id)
        path = Path(str(row.get("log_path") or ""))
        if self.log_dir not in (path.resolve(), *path.resolve().parents):
            raise PermissionError("process log path escapes private log directory")
        byte_limit = max(1, min(int(max_bytes), 65536))
        content = ""
        if path.exists():
            data = path.read_bytes()[-byte_limit:]
            content = data.decode("utf-8", errors="replace")
        return {
            "ok": True,
            "process": _process_summary(self._refresh_row(row)),
            "log": str(redact(content)),
            "max_bytes": byte_limit,
            "raw_secret_values_included": False,
        }

    def stop(self, process_id: str, *, actor: str = "operator") -> dict[str, Any]:
        row = self._require_row(process_id)
        self._evaluate_policy(actor=actor, operation="stop")
        refreshed = self._refresh_row(row)
        if refreshed.get("status") not in {"running", "stop_requested"}:
            receipt = {**_process_receipt(refreshed, event_type="process.stop_noop"), "actor": _safe_label(actor, limit=80)}
            audit_entry = self.audit_logger.append("process.stop_noop", receipt)
            return {"ok": True, "status": refreshed.get("status"), "process": _process_summary(refreshed), "receipt": receipt, "audit_event_hash": audit_entry["event_hash"]}
        pid = int(refreshed["pid"])
        try:
            if os.name == "posix":
                os.killpg(pid, signal.SIGTERM)
            else:
                os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            refreshed["status"] = "exited"
        else:
            refreshed["status"] = "stopped" if self._wait_for_stop(pid) else "stop_requested"
        refreshed["stopped_at"] = now_utc()
        refreshed["updated_at"] = now_utc()
        self._replace_row(refreshed)
        receipt = {**_process_receipt(refreshed, event_type="process.stop_requested"), "actor": _safe_label(actor, limit=80)}
        audit_entry = self.audit_logger.append("process.stop_requested", receipt)
        return {
            "ok": True,
            "status": refreshed["status"],
            "process": _process_summary(refreshed),
            "receipt": receipt,
            "audit_event_hash": audit_entry["event_hash"],
            "processes": self.status(limit=20),
        }

    def _wait_for_stop(self, pid: int, *, timeout_seconds: float = 2.0) -> bool:
        deadline = time.time() + timeout_seconds
        handle = self._handles.get(pid)
        while time.time() < deadline:
            if handle is not None and handle.poll() is not None:
                try:
                    handle.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    pass
                self._handles.pop(pid, None)
                return True
            if handle is None and not _pid_alive(pid):
                return True
            time.sleep(0.05)
        if handle is not None and handle.poll() is not None:
            self._handles.pop(pid, None)
            return True
        return not _pid_alive(pid)

    def _append_control_event(self, row: dict[str, Any], event: dict[str, Any]) -> None:
        path = Path(str(row.get("control_path") or ""))
        resolved = path.resolve()
        if self.log_dir not in (resolved, *resolved.parents):
            raise PermissionError("process control path escapes private log directory")
        ensure_private_file(resolved)
        with resolved.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        resolved.chmod(0o600)

    def _evaluate_policy(self, *, actor: str, operation: str) -> None:
        if self.policy_gate is None:
            return
        decision = self.policy_gate.evaluate(
            PolicyRequest(
                user_role=_safe_label(actor, limit=80) or "local-user",
                workspace=str(self.workspace),
                task_type="background process",
                risk_level=RiskLevel.HIGH,
                connector="process",
                operation="execute" if operation == "start" else operation,
                requested_scopes=("execute",),
                data_sensitivity=Sensitivity.INTERNAL,
                approval_state="approved",
            )
        )
        if decision.decision != PolicyDecisionType.ALLOW:
            raise PermissionError("; ".join(decision.reasons))

    def _validate_executable(self, executable: str) -> str:
        name = Path(executable).name
        path_qualified = executable != name
        if path_qualified and executable in self.allowed_executables and Path(executable).exists():
            return str(Path(executable).resolve())
        if name not in self.allowed_executables:
            raise PermissionError(f"background process executable {executable!r} is not allowlisted")
        resolved = shutil.which(name)
        if not resolved:
            raise FileNotFoundError(name)
        return resolved

    def _require_row(self, process_id: str) -> dict[str, Any]:
        for row in self._refresh_rows():
            if row.get("id") == process_id:
                return row
        raise KeyError(process_id)

    def _refresh_rows(self) -> list[dict[str, Any]]:
        rows = [self._refresh_row(row) for row in self._read_rows()]
        self._write_rows(rows)
        return rows

    def _refresh_row(self, row: dict[str, Any]) -> dict[str, Any]:
        next_row = dict(row)
        status = str(next_row.get("status") or "unknown")
        try:
            pid = int(next_row.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        if status in {"running", "stop_requested"} and pid > 0 and not self._process_alive(pid):
            next_row["status"] = "exited"
            next_row["exited_at"] = next_row.get("exited_at") or now_utc()
            next_row["updated_at"] = now_utc()
        return next_row

    def _process_alive(self, pid: int) -> bool:
        handle = self._handles.get(pid)
        if handle is not None and handle.poll() is not None:
            try:
                handle.wait(timeout=0)
            except subprocess.TimeoutExpired:
                return True
            self._handles.pop(pid, None)
            return False
        return _pid_alive(pid)

    def _replace_row(self, row: dict[str, Any]) -> None:
        rows = [row if existing.get("id") == row.get("id") else existing for existing in self._read_rows()]
        self._write_rows(rows)

    def _read_rows(self) -> list[dict[str, Any]]:
        if not self.state_path.exists():
            return []
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {}
        rows = payload.get("processes", []) if isinstance(payload, dict) else []
        return [dict(row) for row in rows if isinstance(row, dict)]

    def _write_rows(self, rows: list[dict[str, Any]]) -> None:
        ensure_private_file(self.state_path)
        self.state_path.write_text(json.dumps({"processes": rows[:100]}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.state_path.chmod(0o600)


def _clean_argv(argv: list[str] | tuple[str, ...]) -> list[str]:
    values = [str(part) for part in argv]
    if values and values[0] == "--":
        values = values[1:]
    if not values:
        raise ValueError("background process argv is required")
    return values


def _reject_secret_like_args(argv: list[str]) -> None:
    for arg in argv:
        if redact_secret_values(arg) != arg:
            raise ValueError("secret-like values are not allowed in background process argv")


def _pty_supported() -> bool:
    return os.name == "posix"


def _validate_terminal_size(rows: int, cols: int) -> tuple[int, int]:
    try:
        safe_rows = int(rows)
        safe_cols = int(cols)
    except (TypeError, ValueError) as exc:
        raise ValueError("terminal rows and cols must be integers") from exc
    if safe_rows < 1 or safe_rows > 1000 or safe_cols < 1 or safe_cols > 1000:
        raise ValueError("terminal rows and cols must be between 1 and 1000")
    return safe_rows, safe_cols


def _pid_alive(pid: int) -> bool:
    proc_stat = Path(f"/proc/{pid}/stat")
    if proc_stat.exists():
        try:
            parts = proc_stat.read_text(encoding="utf-8", errors="replace").split()
        except OSError:
            parts = []
        if len(parts) > 2 and parts[2] == "Z":
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _argv_sha256(argv: list[str]) -> str:
    return hashlib.sha256(json.dumps(argv, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _safe_label(value: str, *, limit: int = 120) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())[:limit]


def _process_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "pid": row.get("pid"),
        "label": row.get("label"),
        "status": row.get("status"),
        "executable": row.get("executable"),
        "argv_sha256": row.get("argv_sha256"),
        "argv_count": row.get("argv_count"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "stopped_at": row.get("stopped_at"),
        "exited_at": row.get("exited_at"),
        "raw_command_included": False,
        "raw_secret_values_included": False,
        "pty_attached": bool(row.get("pty_attached")),
        "stdin_streaming": bool(row.get("stdin_streaming")),
        "resize_events": bool(row.get("resize_events")),
        "terminal_rows": row.get("terminal_rows"),
        "terminal_cols": row.get("terminal_cols"),
        "stdin_event_count": int(row.get("stdin_event_count") or 0),
        "resize_event_count": int(row.get("resize_event_count") or 0),
    }


def _process_receipt(row: dict[str, Any], *, event_type: str) -> dict[str, Any]:
    return {
        "receipt_schema": "aegis.process.v1",
        "event_type": event_type,
        "process_id": row.get("id"),
        "pid": row.get("pid"),
        "status": row.get("status"),
        "executable": row.get("executable"),
        "argv_sha256": row.get("argv_sha256"),
        "argv_count": row.get("argv_count"),
        "log_artifact_sha256": hashlib.sha256(str(row.get("log_path", "")).encode("utf-8")).hexdigest(),
        "raw_command_included": False,
        "raw_secret_values_included": False,
        "pty_attached": bool(row.get("pty_attached")),
        "stdin_streaming": bool(row.get("stdin_streaming")),
        "resize_events": bool(row.get("resize_events")),
        "terminal_rows": row.get("terminal_rows"),
        "terminal_cols": row.get("terminal_cols"),
        "created_at": now_utc(),
    }
