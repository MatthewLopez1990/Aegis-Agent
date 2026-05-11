"""Configurable policy decisions for tasks, skills, and connectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aegis.security.policy_profile import PolicyProfile
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
    WRITE_OPERATIONS = {"write", "create", "update", "send", "send_message", "send_email", "execute", "draft_email"}

    def __init__(self, *, network_allowlist: tuple[str, ...] = (), profile: PolicyProfile | None = None) -> None:
        self.profile = profile or PolicyProfile.secure_default(network_allowlist=network_allowlist)
        self.network_allowlist = self.profile.network_allowlist

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        reasons: list[str] = []
        operation = request.operation or "read"
        scopes = set(request.requested_scopes)

        if operation in self.SECRET_OPERATIONS:
            return self._configured_decision(
                self.profile.raw_secret_exposure,
                ("raw secret exposure is never allowed",),
                RiskLevel.CRITICAL,
                ("use secrets broker scoped handle",),
            )

        if request.data_sensitivity == Sensitivity.SECRET:
            return self._configured_decision(
                self.profile.secret_data,
                ("secret data cannot be provided to the model or normal tools",),
                RiskLevel.CRITICAL,
                ("use secrets broker",),
            )

        if request.skill_manifest and not request.skill_manifest.get("validated", False):
            return self._configured_decision(
                self.profile.skill_without_valid_manifest,
                ("skill manifest has not passed validation",),
                RiskLevel.HIGH,
                ("validate skill manifest before execution",),
            )

        if request.target_domain:
            allowed = any(request.target_domain == domain or request.target_domain.endswith(f".{domain}") for domain in self.network_allowlist)
            if not allowed:
                return self._configured_decision(
                    self.profile.unapproved_network_egress,
                    (f"network egress to {request.target_domain} is not in the allowlist",),
                    max_risk(request.risk_level, RiskLevel.HIGH),
                    ("approve egress or use an allowed domain",),
                )

        if operation in self.DESTRUCTIVE_OPERATIONS:
            if self._action_allows_after_approval(self.profile.destructive_action, request.approval_state):
                return PolicyDecision(PolicyDecisionType.ALLOW, ("destructive action approved",), RiskLevel.HIGH)
            return self._configured_decision(
                self.profile.destructive_action,
                ("destructive action requires human approval",),
                RiskLevel.HIGH,
                ("collect approval before execution", "prefer rollback-capable operation"),
            )

        if operation in self.MESSAGE_SEND_OPERATIONS:
            if self._action_allows_after_approval(self.profile.message_send, request.approval_state):
                return PolicyDecision(PolicyDecisionType.ALLOW, ("message send approved",), RiskLevel.HIGH)
            return self._configured_decision(
                self.profile.message_send,
                ("sending messages or email requires human approval",),
                RiskLevel.HIGH,
                ("draft first", "collect approval before send"),
            )

        if _is_write_operation(operation) and "write" not in scopes and operation != "execute":
            return self._configured_decision(
                self.profile.connector_write_without_scope,
                ("connector write requested without write scope",),
                RiskLevel.HIGH,
                ("request scoped write permission",),
            )

        if request.connector and (operation in {"read", "list"} or operation.startswith("read_") or operation.startswith("search_") or operation.startswith("draft_")):
            if "read" not in scopes:
                return self._configured_decision(
                    self.profile.connector_write_without_scope,
                    ("connector read requested without read scope",),
                    RiskLevel.HIGH,
                    ("request scoped read permission",),
                )

        if operation == "execute":
            if "execute" not in scopes:
                return self._configured_decision(
                    self.profile.unknown_shell_command,
                    ("execution requested without execute scope",),
                    RiskLevel.HIGH,
                    ("request scoped execute permission",),
                )
            if self._action_allows_after_approval(self.profile.shell_execution, request.approval_state):
                return PolicyDecision(PolicyDecisionType.ALLOW, ("execution approved",), RiskLevel.HIGH)
            return self._configured_decision(
                self.profile.shell_execution,
                ("shell or code execution requires human approval",),
                RiskLevel.HIGH,
                ("dry-run command", "collect approval before execution"),
            )

        if request.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            if self._action_allows_after_approval(self.profile.high_risk_action, request.approval_state):
                return PolicyDecision(PolicyDecisionType.ALLOW, ("high-risk action approved",), request.risk_level)
            return self._configured_decision(
                self.profile.high_risk_action,
                ("high-risk action requires approval",),
                request.risk_level,
                ("collect approval",),
            )

        reasons.append("read-only or low-risk action allowed by default policy")
        return PolicyDecision(PolicyDecisionType.ALLOW, tuple(reasons), request.risk_level)

    def _action_allows_after_approval(self, action: str, approval_state: str | None) -> bool:
        if action == PolicyDecisionType.ALLOW.value:
            return True
        if action == PolicyDecisionType.REQUIRE_APPROVAL.value:
            return approval_state in {"approved", "admin_approved"}
        if action == PolicyDecisionType.REQUIRE_ADMIN_APPROVAL.value:
            return approval_state == "admin_approved"
        return False

    def _configured_decision(
        self,
        action: str,
        reasons: tuple[str, ...],
        risk_level: RiskLevel,
        requirements: tuple[str, ...],
    ) -> PolicyDecision:
        return PolicyDecision(PolicyDecisionType(action), reasons, risk_level, requirements)


def _is_write_operation(operation: str) -> bool:
    if operation in PolicyEngine.WRITE_OPERATIONS:
        return True
    return operation.startswith(("create_", "update_", "close_", "delete_"))


_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def max_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if _RISK_ORDER[left] >= _RISK_ORDER[right] else right
