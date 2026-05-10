"""Audited policy gate wrapper."""

from __future__ import annotations

from aegis.audit.logger import AuditLogger
from aegis.security.policy_engine import PolicyDecision, PolicyEngine, PolicyRequest


class PolicyGate:
    def __init__(self, engine: PolicyEngine, audit_logger: AuditLogger) -> None:
        self.engine = engine
        self.audit_logger = audit_logger

    def evaluate(self, request: PolicyRequest, *, task_id: str | None = None) -> PolicyDecision:
        decision = self.engine.evaluate(request)
        self.audit_logger.append(
            "policy.decision",
            {
                "decision": decision.decision.value,
                "reasons": list(decision.reasons),
                "requirements": list(decision.requirements),
                "risk_level": decision.risk_level.value,
                "request": {
                    "task_type": request.task_type,
                    "connector": request.connector,
                    "operation": request.operation,
                    "requested_scopes": list(request.requested_scopes),
                    "data_sensitivity": request.data_sensitivity.value,
                    "approval_state": request.approval_state,
                },
            },
            task_id=task_id,
        )
        return decision
