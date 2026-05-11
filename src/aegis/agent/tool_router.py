"""Audited routing from plan steps to scoped connectors."""

from __future__ import annotations

from aegis.audit.logger import AuditLogger
from aegis.connectors.base import ConnectorRequest, ConnectorResult, operation_kind, required_scopes_for_operation
from aegis.connectors.registry import ConnectorRegistry
from aegis.agent.planner import PlanStep


class ToolRouter:
    def __init__(self, connectors: ConnectorRegistry, audit_logger: AuditLogger) -> None:
        self.connectors = connectors
        self.audit_logger = audit_logger

    def route(self, step: PlanStep, *, approved: bool = False, task_id: str | None = None) -> ConnectorResult:
        if not step.connector:
            result = ConnectorResult("none", step.operation, True, {"recorded": True})
            self.audit_logger.append("tool.recorded", {"step": step.to_dict(), "result": result.data}, task_id=task_id)
            return result

        connector = self.connectors.get(step.connector)
        missing_scopes = [scope for scope in required_scopes_for_operation(connector.spec, step.operation) if scope not in step.scopes]
        if missing_scopes:
            result = ConnectorResult(
                step.connector,
                step.operation,
                False,
                {},
                error=f"missing required connector scope(s): {', '.join(missing_scopes)}",
            )
            self.audit_logger.append(
                "connector.scope_denied",
                {"connector": step.connector, "operation": step.operation, "missing_scopes": missing_scopes},
                task_id=task_id,
            )
            return result
        request = ConnectorRequest(operation=step.operation, params=step.params, scopes=step.scopes, approved=approved)

        kind = operation_kind(connector.spec, step.operation)
        if kind == "read":
            result = connector.read(request)
        elif kind == "dry_run":
            result = connector.dry_run(request)
        else:
            if step.operation in connector.spec.approval_required and not approved:
                result = connector.dry_run(request)
            else:
                result = connector.write(request)

        self.audit_logger.append(
            "connector.called",
            {
                "connector": result.connector,
                "operation": result.operation,
                "ok": result.ok,
                "affected": list(result.affected),
                "data": safe_connector_payload(result.data),
                "error": result.error,
            },
            task_id=task_id,
        )
        return result

def safe_connector_payload(data: dict[str, object]) -> dict[str, object]:
    """Keep receipts and audit logs from storing raw untrusted blobs."""
    safe: dict[str, object] = {}
    for key, value in data.items():
        if key == "content" and isinstance(value, str):
            safe["content_length"] = len(value)
            safe["content_omitted"] = "raw connector content omitted; use tainted context summary"
        elif isinstance(value, str) and len(value) > 1000:
            safe[f"{key}_length"] = len(value)
            safe[f"{key}_omitted"] = "large value omitted from receipt"
        else:
            safe[key] = value
    return safe
