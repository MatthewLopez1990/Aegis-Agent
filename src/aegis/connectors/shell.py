"""Shell connector with strict command allowlist and approval for execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import shlex
import subprocess

from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec, require_scope
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
        require_scope(request, "execute", connector=self.spec.name)
        argv = self._parse_allowed(request.params.get("command", ""))
        return ConnectorResult(self.spec.name, "dry_run", True, {"argv": argv, "cwd": str(self.cwd), "would_execute": True})

    def execute(self, request: ConnectorRequest) -> ConnectorResult:
        require_scope(request, "execute", connector=self.spec.name)
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
        command_name = argv[0]
        executable = Path(command_name).name
        path_qualified = command_name != executable
        path_allowlisted = path_qualified and command_name in self.allowed_commands
        basename_allowlisted = not path_qualified and executable in self.allowed_commands
        if not (path_allowlisted or basename_allowlisted):
            raise PermissionError(f"command {command_name!r} is not allowlisted")
        _validate_safe_arguments(executable, argv[1:])
        return argv


def _validate_safe_arguments(executable: str, args: list[str]) -> None:
    if executable == "pwd":
        if args:
            raise PermissionError("pwd does not accept arguments in the governed shell connector")
        return
    if executable == "ls":
        _validate_ls_args(args)
        return
    if executable == "find":
        _validate_find_args(args)
        return
    if executable in {"python", "python3"}:
        _validate_python_args(args)


def _validate_ls_args(args: list[str]) -> None:
    allowed_flags = {"-1", "-a", "-l", "-h", "-la", "-al", "-lh", "-hl", "-lah", "-lha", "-alh", "-ahl", "-hal", "-hla"}
    for arg in args:
        if arg.startswith("-"):
            if arg not in allowed_flags:
                raise PermissionError(f"ls flag {arg!r} is not allowed")
            continue
        _validate_relative_read_path(arg, command="ls")


def _validate_find_args(args: list[str]) -> None:
    denied = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fdelete"}
    for arg in args:
        if arg in denied:
            raise PermissionError(f"find argument {arg!r} is not allowed")
    for arg in args:
        if arg.startswith("-"):
            continue
        if arg in {";", "{}", "+"}:
            raise PermissionError(f"find argument {arg!r} is not allowed")
        _validate_relative_read_path(arg, command="find")


def _validate_python_args(args: list[str]) -> None:
    if not args:
        raise PermissionError("interactive python is not allowed in the governed shell connector")
    denied_flags = {"-c", "-m"}
    if any(arg in denied_flags for arg in args):
        raise PermissionError("python -c and -m are not allowed in the governed shell connector")
    if len(args) == 1 and args[0] in {"--version", "-V"}:
        return
    raise PermissionError("python execution requires a dedicated governed code tool or repair verification path")


def _validate_relative_read_path(value: str, *, command: str) -> None:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise PermissionError(f"{command} path {value!r} must stay within the workspace")
