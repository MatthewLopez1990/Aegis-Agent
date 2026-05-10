"""Reusable mock connector for credential-free service integrations."""

from __future__ import annotations

from typing import Any

from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec
from aegis.security.taint import RiskLevel, Sensitivity


class MockServiceConnector:
    def __init__(self, *, name: str, operations: tuple[str, ...], write_operations: tuple[str, ...], sample_data: dict[str, Any]) -> None:
        self.sample_data = sample_data
        self.write_operations = write_operations
        self.spec = ConnectorSpec(
            name=name,
            version="0.1.0",
            auth_type="mock",
            required_scopes=("read",),
            optional_scopes=("write",),
            supported_operations=operations + write_operations + ("dry_run",),
            risk_by_operation={**{op: RiskLevel.LOW for op in operations}, **{op: RiskLevel.HIGH for op in write_operations}},
            rate_limits={"per_minute": 60},
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="mock_read_only",
            approval_required=write_operations,
        )

    def connect(self) -> bool:
        return True

    def health_check(self) -> dict[str, Any]:
        return {"name": self.spec.name, "mode": self.spec.default_mode, "connected": True}

    def list_scopes(self) -> tuple[str, ...]:
        return self.spec.required_scopes + self.spec.optional_scopes

    def request_scope(self, scope: str) -> bool:
        return scope in self.list_scopes()

    def read(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, request.operation, True, {"mock": True, "data": self.sample_data})

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        if request.operation in self.write_operations and not request.approved:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="mock service write requires approval")
        return ConnectorResult(self.spec.name, request.operation, True, {"mock": True, "accepted": request.params}, rollback="mock rollback available")

    def dry_run(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "dry_run", True, {"would_call": request.operation, "params": request.params}, rollback="no action performed")

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "rollback", True, {"mock": True, "rolled_back": request.params})

    def audit(self) -> dict[str, Any]:
        return self.health_check()

    def disconnect(self) -> bool:
        return True
