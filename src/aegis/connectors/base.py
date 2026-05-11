"""Base interfaces for scoped connectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from aegis.security.taint import RiskLevel, Sensitivity


@dataclass(frozen=True)
class ConnectorSpec:
    name: str
    version: str
    auth_type: str
    required_scopes: tuple[str, ...]
    optional_scopes: tuple[str, ...]
    supported_operations: tuple[str, ...]
    risk_by_operation: dict[str, RiskLevel]
    rate_limits: dict[str, Any]
    data_sensitivity: Sensitivity
    default_mode: str
    approval_required: tuple[str, ...]
    operation_scopes: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class ConnectorRequest:
    operation: str
    params: dict[str, Any] = field(default_factory=dict)
    scopes: tuple[str, ...] = ()
    approved: bool = False
    dry_run: bool = False


@dataclass(frozen=True)
class ConnectorResult:
    connector: str
    operation: str
    ok: bool
    data: dict[str, Any]
    affected: tuple[str, ...] = ()
    rollback: str | None = None
    error: str | None = None


class Connector(Protocol):
    spec: ConnectorSpec

    def connect(self) -> bool: ...

    def health_check(self) -> dict[str, Any]: ...

    def list_scopes(self) -> tuple[str, ...]: ...

    def request_scope(self, scope: str) -> bool: ...

    def read(self, request: ConnectorRequest) -> ConnectorResult: ...

    def write(self, request: ConnectorRequest) -> ConnectorResult: ...

    def dry_run(self, request: ConnectorRequest) -> ConnectorResult: ...

    def rollback(self, request: ConnectorRequest) -> ConnectorResult: ...

    def audit(self) -> dict[str, Any]: ...

    def disconnect(self) -> bool: ...


def require_scope(request: ConnectorRequest, scope: str, *, connector: str) -> None:
    if scope not in request.scopes:
        raise PermissionError(f"connector {connector!r} operation {request.operation!r} requires {scope!r} scope")


def required_scopes_for_operation(spec: ConnectorSpec, operation: str) -> tuple[str, ...]:
    configured = spec.operation_scopes.get(operation)
    if configured is not None:
        return configured
    if operation == "execute":
        return ("execute",)
    if operation.startswith("dry_run"):
        return ("write",)
    if operation in {"write", "create", "update", "send", "send_message", "send_email", "post_message", "create_issue", "comment_on_pull_request"}:
        return ("write",)
    return ("read",)


def operation_kind(spec: ConnectorSpec, operation: str) -> str:
    scopes = required_scopes_for_operation(spec, operation)
    if operation.startswith("dry_run"):
        return "dry_run"
    if "execute" in scopes or "write" in scopes:
        return "write"
    return "read"
