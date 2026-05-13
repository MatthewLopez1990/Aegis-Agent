"""Local governed lifecycle hooks."""

from __future__ import annotations

from pathlib import Path
from time import monotonic
from typing import Any
from uuid import uuid4
import json
import os
import re
import subprocess

from aegis.audit.logger import AuditLogger, redact
from aegis.security.taint import now_utc
from aegis.storage.state import ensure_private_file


HOOK_EVENTS = (
    "manual",
    "task.created",
    "task.completed",
    "task.failed",
    "approval.requested",
    "model.routed",
)
DEFAULT_HOOK_TIMEOUT_SECONDS = 10
MAX_HOOK_TIMEOUT_SECONDS = 60
DEFAULT_HOOK_OUTPUT_BYTES = 4096
MAX_HOOK_OUTPUT_BYTES = 65536
_HOOK_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


class HookManager:
    """Stores and runs local hooks without shell expansion or secret env inheritance."""

    def __init__(
        self,
        path: str | Path,
        audit_logger: AuditLogger,
        *,
        allowed_executables: tuple[str, ...],
        workspace: str | Path,
    ) -> None:
        self.path = Path(path)
        self.audit_logger = audit_logger
        self.allowed_executables = tuple(str(item) for item in allowed_executables)
        self.workspace = Path(workspace).expanduser().resolve()

    def list_hooks(self) -> list[dict[str, Any]]:
        hooks = [_public_hook(hook, redact_command=True) for hook in self._read_store()["hooks"].values()]
        return sorted(hooks, key=lambda hook: (str(hook["event"]), str(hook["id"])))

    def register_hook(
        self,
        *,
        event: str,
        command: list[str] | tuple[str, ...],
        hook_id: str | None = None,
        enabled: bool = False,
        approval_required: bool = True,
        timeout_seconds: int = DEFAULT_HOOK_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_HOOK_OUTPUT_BYTES,
    ) -> dict[str, Any]:
        normalized_event = _normalize_event(event)
        normalized_command = _normalize_command(command)
        _validate_command_allowed(normalized_command, self.allowed_executables)
        hook_id = hook_id or f"hook_{uuid4().hex[:12]}"
        if not _HOOK_ID_RE.fullmatch(hook_id):
            raise ValueError("hook id must be 1-80 characters of letters, digits, dot, underscore, or dash")
        hook = {
            "id": hook_id,
            "event": normalized_event,
            "command": normalized_command,
            "enabled": bool(enabled),
            "approval_required": bool(approval_required),
            "timeout_seconds": _clamp_int(timeout_seconds, minimum=1, maximum=MAX_HOOK_TIMEOUT_SECONDS),
            "max_output_bytes": _clamp_int(max_output_bytes, minimum=256, maximum=MAX_HOOK_OUTPUT_BYTES),
            "created_at": now_utc(),
            "updated_at": now_utc(),
        }
        store = self._read_store()
        if hook_id in store["hooks"]:
            raise KeyError(hook_id)
        store["hooks"][hook_id] = hook
        self._write_store(store)
        self.audit_logger.append("hook.registered", _hook_audit_payload(hook))
        return _public_hook(hook, redact_command=True)

    def set_enabled(self, hook_id: str, enabled: bool) -> dict[str, Any]:
        store = self._read_store()
        hook = store["hooks"].get(hook_id)
        if hook is None:
            raise KeyError(hook_id)
        hook["enabled"] = bool(enabled)
        hook["updated_at"] = now_utc()
        self._write_store(store)
        self.audit_logger.append("hook.enabled" if enabled else "hook.disabled", _hook_audit_payload(hook))
        return _public_hook(hook, redact_command=True)

    def remove_hook(self, hook_id: str) -> dict[str, Any]:
        store = self._read_store()
        hook = store["hooks"].pop(hook_id, None)
        if hook is None:
            raise KeyError(hook_id)
        self._write_store(store)
        self.audit_logger.append("hook.removed", _hook_audit_payload(hook))
        return _public_hook(hook, redact_command=True)

    def run_event(
        self,
        event: str,
        *,
        context: dict[str, Any] | None = None,
        approved: bool = False,
        task_id: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        normalized_event = _normalize_event(event)
        hooks = [hook for hook in self._read_store()["hooks"].values() if hook["event"] == normalized_event and bool(hook["enabled"])]
        results = [
            self._run_hook(hook, context=context or {}, approved=approved, task_id=task_id, correlation_id=correlation_id)
            for hook in hooks
        ]
        return {
            "event": normalized_event,
            "hook_count": len(hooks),
            "ran_count": sum(1 for result in results if result["status"] in {"completed", "failed"}),
            "skipped_count": sum(1 for result in results if result["status"] == "skipped"),
            "results": results,
        }

    def _run_hook(
        self,
        hook: dict[str, Any],
        *,
        context: dict[str, Any],
        approved: bool,
        task_id: str | None,
        correlation_id: str | None,
    ) -> dict[str, Any]:
        if hook.get("approval_required") and not approved:
            result = {
                "hook_id": hook["id"],
                "event": hook["event"],
                "status": "skipped",
                "reason": "approval_required",
                "approval_required": True,
                "command": redact(hook["command"]),
            }
            self.audit_logger.append("hook.skipped", result, task_id=task_id, correlation_id=correlation_id)
            return result

        command = _normalize_command(hook["command"])
        try:
            _validate_command_allowed(command, self.allowed_executables)
        except (PermissionError, ValueError) as exc:
            result = {
                "hook_id": hook["id"],
                "event": hook["event"],
                "status": "skipped",
                "reason": str(exc),
                "approval_required": bool(hook.get("approval_required")),
                "command": redact(command),
            }
            self.audit_logger.append("hook.skipped", result, task_id=task_id, correlation_id=correlation_id)
            return result

        payload = json.dumps({"event": hook["event"], "hook_id": hook["id"], "context": context}, sort_keys=True)
        started = monotonic()
        try:
            completed = subprocess.run(
                command,
                input=payload,
                text=True,
                capture_output=True,
                timeout=int(hook["timeout_seconds"]),
                check=False,
                cwd=self.workspace,
                env=_hook_env(str(hook["event"])),
            )  # noqa: S603 - hook command is argv-only and executable allowlisted.
            duration_ms = int((monotonic() - started) * 1000)
            stdout, stdout_truncated = _truncate_text(completed.stdout, int(hook["max_output_bytes"]))
            stderr, stderr_truncated = _truncate_text(completed.stderr, int(hook["max_output_bytes"]))
            result = {
                "hook_id": hook["id"],
                "event": hook["event"],
                "status": "completed" if completed.returncode == 0 else "failed",
                "exit_code": completed.returncode,
                "duration_ms": duration_ms,
                "command": redact(command),
                "stdout": redact(stdout),
                "stderr": redact(stderr),
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "approval_required": bool(hook.get("approval_required")),
            }
        except subprocess.TimeoutExpired:
            result = {
                "hook_id": hook["id"],
                "event": hook["event"],
                "status": "failed",
                "exit_code": None,
                "duration_ms": int((monotonic() - started) * 1000),
                "command": redact(command),
                "stdout": "",
                "stderr": "hook timed out",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "approval_required": bool(hook.get("approval_required")),
            }
        except OSError as exc:
            result = {
                "hook_id": hook["id"],
                "event": hook["event"],
                "status": "failed",
                "exit_code": None,
                "duration_ms": int((monotonic() - started) * 1000),
                "command": redact(command),
                "stdout": "",
                "stderr": str(redact(str(exc))),
                "stdout_truncated": False,
                "stderr_truncated": False,
                "approval_required": bool(hook.get("approval_required")),
            }
        self.audit_logger.append("hook.run", result, task_id=task_id, correlation_id=correlation_id)
        return result

    def _read_store(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "hooks": {}}
        with self.path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        hooks = raw.get("hooks", {}) if isinstance(raw, dict) else {}
        if not isinstance(hooks, dict):
            hooks = {}
        normalized_hooks: dict[str, dict[str, Any]] = {}
        for key, value in hooks.items():
            if not isinstance(value, dict):
                continue
            try:
                normalized_hooks[str(key)] = _public_hook(value)
            except ValueError:
                continue
        return {"version": 1, "hooks": normalized_hooks}

    def _write_store(self, store: dict[str, Any]) -> None:
        ensure_private_file(self.path)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump({"version": 1, "hooks": store.get("hooks", {})}, handle, indent=2, sort_keys=True)
            handle.write("\n")
        ensure_private_file(self.path)


def _public_hook(raw: dict[str, Any], *, redact_command: bool = False) -> dict[str, Any]:
    command = _normalize_command(raw.get("command") or ())
    return {
        "id": str(raw.get("id") or ""),
        "event": _normalize_event(str(raw.get("event") or "manual")),
        "command": redact(command) if redact_command else command,
        "enabled": bool(raw.get("enabled", False)),
        "approval_required": bool(raw.get("approval_required", True)),
        "timeout_seconds": _clamp_int(raw.get("timeout_seconds", DEFAULT_HOOK_TIMEOUT_SECONDS), minimum=1, maximum=MAX_HOOK_TIMEOUT_SECONDS),
        "max_output_bytes": _clamp_int(raw.get("max_output_bytes", DEFAULT_HOOK_OUTPUT_BYTES), minimum=256, maximum=MAX_HOOK_OUTPUT_BYTES),
        "created_at": str(raw.get("created_at") or ""),
        "updated_at": str(raw.get("updated_at") or ""),
    }


def _normalize_event(event: str) -> str:
    normalized = event.strip().lower().replace("_", ".")
    if normalized not in HOOK_EVENTS:
        raise ValueError(f"unsupported hook event: {event}")
    return normalized


def _normalize_command(command: list[str] | tuple[str, ...] | Any) -> list[str]:
    if not isinstance(command, (list, tuple)):
        raise ValueError("hook command must be an argv array")
    normalized = [str(part) for part in command if str(part)]
    if normalized and normalized[0] == "--":
        normalized = normalized[1:]
    if not normalized:
        raise ValueError("hook command cannot be empty")
    return normalized


def _validate_command_allowed(command: list[str], allowed_executables: tuple[str, ...]) -> None:
    executable = command[0]
    if Path(executable).name != executable:
        raise PermissionError("hook command must use an allowlisted executable name, not a path")
    if executable not in allowed_executables:
        raise PermissionError(f"hook executable {executable!r} is not allowlisted")


def _clamp_int(value: Any, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = minimum
    return max(minimum, min(parsed, maximum))


def _truncate_text(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    return encoded[:max_bytes].decode("utf-8", errors="replace"), True


def _hook_env(event: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for key in ("PATH", "HOME", "LANG", "LC_ALL", "TERM"):
        if key in os.environ:
            env[key] = os.environ[key]
    env["AEGIS_HOOK_EVENT"] = event
    return env


def _hook_audit_payload(hook: dict[str, Any]) -> dict[str, Any]:
    return {
        "hook_id": hook["id"],
        "event": hook["event"],
        "command": hook["command"],
        "enabled": bool(hook["enabled"]),
        "approval_required": bool(hook["approval_required"]),
        "timeout_seconds": int(hook["timeout_seconds"]),
        "max_output_bytes": int(hook["max_output_bytes"]),
    }
