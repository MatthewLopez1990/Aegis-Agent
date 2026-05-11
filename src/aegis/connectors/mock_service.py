"""Reusable mock connector for credential-free service integrations."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from aegis.audit.logger import redact
from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec, require_scope
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
            operation_scopes={
                **{operation: ("read",) for operation in operations},
                **{operation: ("write",) for operation in write_operations},
                "dry_run": ("write",),
            },
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
        require_scope(request, "read", connector=self.spec.name)
        if request.operation not in self.spec.supported_operations or request.operation in self.write_operations:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"unsupported mock service read operation: {request.operation}")
        return ConnectorResult(self.spec.name, request.operation, True, {"mock": True, "data": self.sample_data})

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        require_scope(request, "write", connector=self.spec.name)
        if request.operation not in self.write_operations:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"unsupported mock service write operation: {request.operation}")
        if request.operation in self.write_operations and not request.approved:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="mock service write requires approval")
        return ConnectorResult(self.spec.name, request.operation, True, {"mock": True, "accepted": _summarize_params(request.params)}, rollback="mock rollback available")

    def dry_run(self, request: ConnectorRequest) -> ConnectorResult:
        if request.operation != "dry_run" and request.operation not in self.spec.supported_operations:
            return ConnectorResult(self.spec.name, "dry_run", False, {}, error=f"unsupported mock service operation: {request.operation}")
        required_scope = "write" if request.operation in self.write_operations or request.operation == "dry_run" else "read"
        require_scope(request, required_scope, connector=self.spec.name)
        return ConnectorResult(self.spec.name, "dry_run", True, {"would_call": request.operation, "params": _summarize_params(request.params), "action_performed": False}, rollback="no action performed")

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "rollback", True, {"mock": True, "rolled_back": _summarize_params(request.params)})

    def audit(self) -> dict[str, Any]:
        return self.health_check()

    def disconnect(self) -> bool:
        return True


def _summarize_params(params: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(params, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return {
        "receipt_schema": "redacted_param_summary_v1",
        "param_sha256": hashlib.sha256(encoded).hexdigest(),
        "param_bytes": len(encoded),
        "param_keys": sorted(str(key) for key in params.keys()),
        "raw_secret_values_included": False,
        "raw_response_body_included": False,
        "redacted_preview": _preview(redact(params)),
    }


def _preview(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _preview(item) for key, item in value.items()}
    if isinstance(value, list):
        return {"type": "list", "items": len(value), "preview": [_preview(item) for item in value[:10]]}
    if isinstance(value, tuple):
        return {"type": "tuple", "items": len(value), "preview": [_preview(item) for item in value[:10]]}
    if isinstance(value, str):
        return {"type": "string", "chars": len(value), "redacted": value == "[REDACTED]" or "[REDACTED_VALUE]" in value}
    return value
