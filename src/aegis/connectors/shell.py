"""Shell connector with strict command allowlist and approval for execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import shlex
import subprocess

from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec
from aegis.security.taint import RiskLevel, Sensitivity


class ShellConnector:
    def __init__(self, cwd: str | Path, *, allowed_commands: tuple[str, ...]) -> None:
        self.cwd = Path(cwd).expanduser().resolve()
        self.allowed_commands = allowed_commands
        self.spec = ConnectorSpec(
            name="shell",
            version="0.1.0",
            auth_type="local",
            required_scopes=("execute",),
            optional_scopes=(),
            supported_operations=("dry_run", "execute"),
            risk_by_operation={"dry_run": RiskLevel.MEDIUM, "execute": RiskLevel.HIGH},
            rate_limits={},
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="dry_run",
            approval_required=("execute",),
        )

    def connect(self) -> bool:
        return self.cwd.exists()

    def health_check(self) -> dict[str, Any]:
        return {"name": self.spec.name, "cwd": str(self.cwd), "allowed_commands": list(self.allowed_commands), "connected": self.connect()}

    def list_scopes(self) -> tuple[str, ...]:
        return self.spec.required_scopes

    def request_scope(self, scope: str) -> bool:
        return scope == "execute"

    def read(self, request: ConnectorRequest) -> ConnectorResult:
        return self.dry_run(request)

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        return self.execute(request)

    def dry_run(self, request: ConnectorRequest) -> ConnectorResult:
        argv = self._parse_allowed(request.params.get("command", ""))
        return ConnectorResult(self.spec.name, "dry_run", True, {"argv": argv, "cwd": str(self.cwd), "would_execute": True})

    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        if not request.approved:
            return ConnectorResult(self.spec.name, "execute", False, {}, error="shell execution requires approval")
        argv = self._parse_allowed(request.params.get("command", ""))
        completed = subprocess.run(argv, cwd=self.cwd, text=True, capture_output=True, timeout=15, check=False)
        return ConnectorResult(
            self.spec.name,
            "execute",
            completed.returncode == 0,
            {"stdout": completed.stdout[:5000], "stderr": completed.stderr[:5000], "returncode": completed.returncode},
            rollback="manual review required for shell side effects",
            error=None if completed.returncode == 0 else "command failed",
        )

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "rollback", False, {}, error="shell rollback is command-specific")

    def audit(self) -> dict[str, Any]:
        return self.health_check()

    def disconnect(self) -> bool:
        return True

    def _parse_allowed(self, command: str) -> list[str]:
        argv = shlex.split(command)
        if not argv:
            raise ValueError("empty command")
        executable = Path(argv[0]).name
        if executable not in self.allowed_commands:
            raise PermissionError(f"command {executable!r} is not allowlisted")
        return argv
