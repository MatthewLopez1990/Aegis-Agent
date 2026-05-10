"""Configurable policy decisions for tasks, skills, and connectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aegis.security.taint import RiskLevel, Sensitivity


class PolicyDecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_DRY_RUN_FIRST = "require_dry_run_first"
    REQUIRE_ADDITIONAL_EVIDENCE = "require_additional_evidence"
    REQUIRE_SAFER_ALTERNATIVE = "require_safer_alternative"
    REQUIRE_ADMIN_APPROVAL = "require_admin_approval"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class PolicyRequest:
    user_role: str
    workspace: str
    task_type: str
    risk_level: RiskLevel
    connector: str | None = None
    operation: str | None = None
    requested_scopes: tuple[str, ...] = ()
    data_sensitivity: Sensitivity = Sensitivity.INTERNAL
    approval_state: str | None = None
    skill_manifest: dict[str, Any] | None = None
    environment: str = "local"
    target_domain: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    decision: PolicyDecisionType
    reasons: tuple[str, ...]
    risk_level: RiskLevel
    requirements: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision == PolicyDecisionType.ALLOW


class PolicyEngine:
    """Secure defaults: read-only by default, explicit approval for risky actions."""

    DESTRUCTIVE_OPERATIONS = {"delete", "overwrite", "write_destructive", "drop", "truncate"}
    MESSAGE_SEND_OPERATIONS = {"send", "send_message", "send_email", "post_message"}
    SECRET_OPERATIONS = {"read_secret", "expose_secret", "export_secret"}
    WRITE_OPERATIONS = {"write", "create", "update", "send", "send_message", "send_email", "execute"}

    def __init__(self, *, network_allowlist: tuple[str, ...] = ()) -> None:
        self.network_allowlist = network_allowlist

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        reasons: list[str] = []
        operation = request.operation or "read"
        scopes = set(request.requested_scopes)

        if operation in self.SECRET_OPERATIONS:
            return PolicyDecision(
                PolicyDecisionType.DENY,
                ("raw secret exposure is never allowed",),
                RiskLevel.CRITICAL,
                ("use secrets broker scoped handle",),
            )

        if request.skill_manifest and not request.skill_manifest.get("validated", False):
            return PolicyDecision(
                PolicyDecisionType.DENY,
                ("skill manifest has not passed validation",),
                RiskLevel.HIGH,
                ("validate skill manifest before execution",),
            )

        if request.connector == "http" and request.target_domain:
            allowed = any(request.target_domain == domain or request.target_domain.endswith(f".{domain}") for domain in self.network_allowlist)
            if not allowed:
                return PolicyDecision(
                    PolicyDecisionType.REQUIRE_APPROVAL,
                    (f"network egress to {request.target_domain} is not in the allowlist",),
                    max_risk(request.risk_level, RiskLevel.HIGH),
                    ("approve egress or use an allowed domain",),
                )

        if operation in self.DESTRUCTIVE_OPERATIONS:
            if request.approval_state == "approved":
                return PolicyDecision(PolicyDecisionType.ALLOW, ("destructive action approved",), RiskLevel.HIGH)
            return PolicyDecision(
                PolicyDecisionType.REQUIRE_APPROVAL,
                ("destructive action requires human approval",),
                RiskLevel.HIGH,
                ("collect approval before execution", "prefer rollback-capable operation"),
            )

        if operation in self.MESSAGE_SEND_OPERATIONS:
            if request.approval_state == "approved":
                return PolicyDecision(PolicyDecisionType.ALLOW, ("message send approved",), RiskLevel.HIGH)
            return PolicyDecision(
                PolicyDecisionType.REQUIRE_APPROVAL,
                ("sending messages or email requires human approval",),
                RiskLevel.HIGH,
                ("draft first", "collect approval before send"),
            )

        if operation in self.WRITE_OPERATIONS and "write" not in scopes and operation != "execute":
            return PolicyDecision(
                PolicyDecisionType.DENY,
                ("connector write requested without write scope",),
                RiskLevel.HIGH,
                ("request scoped write permission",),
            )

        if operation == "execute":
            if "execute" not in scopes:
                return PolicyDecision(
                    PolicyDecisionType.DENY,
                    ("execution requested without execute scope",),
                    RiskLevel.HIGH,
                    ("request scoped execute permission",),
                )
            if request.approval_state == "approved":
                return PolicyDecision(PolicyDecisionType.ALLOW, ("execution approved",), RiskLevel.HIGH)
            return PolicyDecision(
                PolicyDecisionType.REQUIRE_APPROVAL,
                ("shell or code execution requires human approval",),
                RiskLevel.HIGH,
                ("dry-run command", "collect approval before execution"),
            )

        if request.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} and request.approval_state != "approved":
            return PolicyDecision(
                PolicyDecisionType.REQUIRE_APPROVAL,
                ("high-risk action requires approval",),
                request.risk_level,
                ("collect approval",),
            )

        if request.data_sensitivity == Sensitivity.SECRET:
            return PolicyDecision(
                PolicyDecisionType.DENY,
                ("secret data cannot be provided to the model or normal tools",),
                RiskLevel.CRITICAL,
                ("use secrets broker",),
            )

        reasons.append("read-only or low-risk action allowed by default policy")
        return PolicyDecision(PolicyDecisionType.ALLOW, tuple(reasons), request.risk_level)


_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def max_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if _RISK_ORDER[left] >= _RISK_ORDER[right] else right
