"""Local filesystem connector with scoped root and read-only defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec
from aegis.security.taint import RiskLevel, Sensitivity


class LocalFilesystemConnector:
    def __init__(self, root: str | Path, *, allow_write: bool = False) -> None:
        self.root = Path(root).expanduser().resolve()
        self.allow_write = allow_write
        self.spec = ConnectorSpec(
            name="filesystem",
            version="0.1.0",
            auth_type="local",
            required_scopes=("read",),
            optional_scopes=("write",),
            supported_operations=("read", "list", "dry_run_write", "write"),
            risk_by_operation={"read": RiskLevel.LOW, "list": RiskLevel.LOW, "dry_run_write": RiskLevel.MEDIUM, "write": RiskLevel.HIGH},
            rate_limits={},
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="read_only",
            approval_required=("write",),
        )

    def connect(self) -> bool:
        return self.root.exists()

    def health_check(self) -> dict[str, Any]:
        return {"name": self.spec.name, "root": str(self.root), "connected": self.connect(), "mode": "write" if self.allow_write else "read_only"}

    def list_scopes(self) -> tuple[str, ...]:
        return self.spec.required_scopes + self.spec.optional_scopes

    def request_scope(self, scope: str) -> bool:
        return scope == "read" or (scope == "write" and self.allow_write)

    def read(self, request: ConnectorRequest) -> ConnectorResult:
        operation = request.operation
        if operation == "list":
            path = self._resolve(request.params.get("path", "."))
            entries = sorted(child.name for child in path.iterdir()) if path.is_dir() else [path.name]
            return ConnectorResult(self.spec.name, "list", True, {"path": str(path), "entries": entries}, (str(path),))
        path = self._resolve(request.params.get("path", "."))
        if not path.is_file():
            return ConnectorResult(self.spec.name, "read", False, {}, error=f"{path} is not a file")
        limit = int(request.params.get("limit", 20000))
        content = path.read_text(encoding="utf-8", errors="replace")[:limit]
        return ConnectorResult(self.spec.name, "read", True, {"path": str(path), "content": content}, (str(path),))

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        if not self.allow_write or not request.approved:
            return ConnectorResult(self.spec.name, "write", False, {}, error="filesystem write requires explicit approval and write-enabled connector")
        path = self._resolve(request.params["path"])
        if path.exists() and request.params.get("overwrite") is not True:
            return ConnectorResult(self.spec.name, "write", False, {}, error="refusing to overwrite without overwrite=true")
        path.write_text(str(request.params.get("content", "")), encoding="utf-8")
        return ConnectorResult(self.spec.name, "write", True, {"path": str(path)}, (str(path),), rollback="restore from backup or version control")

    def dry_run(self, request: ConnectorRequest) -> ConnectorResult:
        path = self._resolve(request.params.get("path", "."))
        return ConnectorResult(
            self.spec.name,
            "dry_run_write",
            True,
            {"would_write": str(path), "bytes": len(str(request.params.get("content", "")).encode("utf-8"))},
            (str(path),),
            rollback="no action performed",
        )

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "rollback", False, {}, error="automatic filesystem rollback is not implemented")

    def audit(self) -> dict[str, Any]:
        return self.health_check()

    def disconnect(self) -> bool:
        return True

    def _resolve(self, user_path: str | Path) -> Path:
        path = (self.root / user_path).expanduser().resolve() if not Path(user_path).is_absolute() else Path(user_path).expanduser().resolve()
        if self.root not in (path, *path.parents):
            raise PermissionError(f"path {path} escapes connector root {self.root}")
        return path
