"""Append-only structured audit logging with redaction and hash-chain checks."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any
from contextlib import contextmanager
import hashlib
import json

try:
    import fcntl
except ImportError:  # pragma: no cover - Aegis targets Linux/macOS, but keep import portable.
    fcntl = None

from aegis.config.defaults import SECRET_FIELD_NAMES
from aegis.security.context_firewall import redact_secret_values
from aegis.security.taint import now_utc
from aegis.storage.state import ensure_private_file


REDACTION = "[REDACTED]"


class AuditLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        ensure_private_file(self.path)
        if not self.path.exists():
            self.path.touch()
            ensure_private_file(self.path)

    def append(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        task_id: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        with self._append_lock():
            prev_hash = self._last_hash()
            entry = {
                "timestamp": now_utc(),
                "event_type": event_type,
                "task_id": task_id,
                "correlation_id": correlation_id or task_id,
                "payload": redact(payload or {}),
                "prev_hash": prev_hash,
            }
            entry["event_hash"] = self._hash_entry(entry)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
            ensure_private_file(self.path)
            return entry

    def tail(self, limit: int = 20) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-limit:] if line.strip()]

    def events(
        self,
        *,
        limit: int | None = None,
        task_id: str | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        matches: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if task_id and entry.get("task_id") != task_id:
                continue
            if event_type and entry.get("event_type") != event_type:
                continue
            matches.append(entry)
        if limit is None:
            return matches
        return matches[-limit:]

    def export_siem(
        self,
        *,
        limit: int = 1000,
        task_id: str | None = None,
        event_type: str | None = None,
    ) -> dict[str, Any]:
        events = [_siem_event(entry) for entry in self.events(limit=limit, task_id=task_id, event_type=event_type)]
        return {
            "format": "jsonl",
            "schema": "aegis.audit.siem.v1",
            "count": len(events),
            "filters": {"limit": limit, "task_id": task_id, "event_type": event_type},
            "chain_ok": self.verify_chain(),
            "events": events,
            "jsonl": "\n".join(json.dumps(event, sort_keys=True) for event in events) + ("\n" if events else ""),
        }

    def for_task(self, task_id: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        matches: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("task_id") == task_id:
                matches.append(entry)
        if limit is None:
            return matches
        return matches[-limit:]

    def verify_chain(self) -> bool:
        if not self.path.exists():
            return True
        previous = "0" * 64
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            event_hash = entry.pop("event_hash", None)
            if entry.get("prev_hash") != previous:
                return False
            calculated = self._hash_entry(entry)
            if calculated != event_hash:
                return False
            previous = event_hash
        return True

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last_hash = "0" * 64
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last_hash = json.loads(line)["event_hash"]
        return last_hash

    def _hash_entry(self, entry: dict[str, Any]) -> str:
        body = dict(entry)
        body.pop("event_hash", None)
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @contextmanager
    def _append_lock(self):
        lock_path = self.path.with_name(f"{self.path.name}.lock")
        ensure_private_file(lock_path)
        with lock_path.open("a", encoding="utf-8") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def redact(value: Any) -> Any:
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(secret in lowered for secret in SECRET_FIELD_NAMES):
                redacted[key] = REDACTION
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        return redact_secret_values(value)
    return value


def _siem_event(entry: dict[str, Any]) -> dict[str, Any]:
    event_type = str(entry.get("event_type", "audit.event"))
    return {
        "@timestamp": entry.get("timestamp"),
        "event": {
            "action": event_type,
            "kind": "event",
            "category": _event_category(event_type),
            "provider": "aegis-agent",
            "dataset": "aegis.audit",
            "hash": entry.get("event_hash"),
        },
        "aegis": {
            "task_id": entry.get("task_id"),
            "correlation_id": entry.get("correlation_id"),
            "prev_hash": entry.get("prev_hash"),
        },
        "message": event_type,
        "payload": redact(entry.get("payload", {})),
    }


def _event_category(event_type: str) -> str:
    prefix = event_type.split(".", 1)[0]
    return {
        "approval": "iam",
        "audit": "configuration",
        "connector": "network",
        "memory": "database",
        "model": "ml",
        "policy": "policy",
        "receipt": "process",
        "skill": "package",
        "task": "process",
        "tool": "process",
    }.get(prefix, "runtime")
