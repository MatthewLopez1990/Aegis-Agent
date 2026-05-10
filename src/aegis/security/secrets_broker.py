"""Brokered secret access. Secret values are never returned to model-facing code."""

from __future__ import annotations

from dataclasses import dataclass
import os
import json
from pathlib import Path
from uuid import uuid4

from aegis.security.taint import now_utc


@dataclass(frozen=True)
class SecretHandle:
    handle_id: str
    name: str
    requester: str
    scopes: tuple[str, ...]
    reason: str
    created_at: str
    present: bool
    redacted: str = "[REDACTED]"


class SecretsBroker:
    """Issues scoped handles while keeping raw secret values out of normal flows."""

    def __init__(self, store_path: str | Path | None = None) -> None:
        self.store_path = Path(store_path) if store_path else None
        self._memory_store: dict[str, str] = {}

    def request_handle(self, *, name: str, requester: str, reason: str, scopes: tuple[str, ...]) -> SecretHandle:
        return SecretHandle(
            handle_id=str(uuid4()),
            name=name,
            requester=requester,
            scopes=scopes,
            reason=reason,
            created_at=now_utc(),
            present=self.has_secret(name),
        )

    def resolve_for_authorized_tool(self, handle: SecretHandle, *, requester: str) -> str:
        if requester != handle.requester:
            raise PermissionError("secret handle requester mismatch")
        value = self._lookup_secret(handle.name)
        if value is None:
            raise KeyError(f"secret {handle.name!r} is not configured")
        return value

    def store_secret(self, *, name: str, value: str) -> None:
        if not value.strip():
            raise ValueError("secret value cannot be empty")
        if self.store_path is None:
            self._memory_store[name] = value
            return
        data = self._read_store()
        data["secrets"][name] = value
        self._write_store(data)

    def delete_secret(self, name: str) -> bool:
        if self.store_path is None:
            return self._memory_store.pop(name, None) is not None
        data = self._read_store()
        existed = name in data["secrets"]
        data["secrets"].pop(name, None)
        self._write_store(data)
        return existed

    def has_secret(self, name: str) -> bool:
        return self.secret_source(name) is not None

    def secret_source(self, name: str) -> str | None:
        if name in os.environ:
            return "environment"
        if self.store_path is None:
            return "memory" if name in self._memory_store else None
        return "local" if name in self._read_store()["secrets"] else None

    def _lookup_secret(self, name: str) -> str | None:
        if name in os.environ:
            return os.environ[name]
        if self.store_path is None:
            return self._memory_store.get(name)
        return self._read_store()["secrets"].get(name)

    def _read_store(self) -> dict[str, object]:
        if self.store_path is None or not self.store_path.exists():
            return {"version": 1, "secrets": {}}
        with self.store_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        secrets = raw.get("secrets", {}) if isinstance(raw, dict) else {}
        if not isinstance(secrets, dict):
            secrets = {}
        return {"version": 1, "secrets": {str(key): str(value) for key, value in secrets.items()}}

    def _write_store(self, data: dict[str, object]) -> None:
        if self.store_path is None:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "secrets": data.get("secrets", {})}
        with self.store_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, indent=2)
            handle.write("\n")
        os.chmod(self.store_path, 0o600)
