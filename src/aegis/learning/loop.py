"""Governed self-improvement proposals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from aegis.security.taint import now_utc


@dataclass(frozen=True)
class ImprovementProposal:
    id: str
    kind: str
    summary: str
    evidence: tuple[str, ...]
    approval_required: bool = True
    default_state: str = "disabled_until_review"
    status: str = "proposed"
    created_at: str = ""

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "approval_required": self.approval_required,
            "default_state": self.default_state,
            "status": self.status,
            "created_at": self.created_at or now_utc(),
        }


@dataclass(frozen=True)
class FailureClassification:
    failure_class: str
    severity: str
    confidence: float
    signals: tuple[str, ...]
    review_gate: str
    retryable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_class": self.failure_class,
            "severity": self.severity,
            "confidence": self.confidence,
            "signals": list(self.signals),
            "review_gate": self.review_gate,
            "retryable": self.retryable,
        }


class LearningLoop:
    def propose_from_failure(self, *, task_id: str, failure_summary: str) -> ImprovementProposal:
        return ImprovementProposal(
            id=str(uuid4()),
            kind="skill_or_memory_update",
            summary=f"Review failed task {task_id}: {failure_summary}",
            evidence=(task_id,),
            created_at=now_utc(),
        )

    def classify_failure(self, failure_summary: str) -> dict[str, Any]:
        return _classify_failure(failure_summary).to_dict()

    def repair_plan_from_failure(self, *, failure_summary: str, step: dict[str, Any] | None = None) -> dict[str, Any]:
        connector = str((step or {}).get("connector") or "runtime")
        operation = str((step or {}).get("operation") or "unknown")
        classification = _classify_failure(failure_summary)
        return {
            "failure_class": classification.failure_class,
            "classification": classification.to_dict(),
            "severity": classification.severity,
            "confidence": classification.confidence,
            "signals": list(classification.signals),
            "review_gate": classification.review_gate,
            "target_subsystem": connector,
            "operation": operation,
            "proposed_action": _proposed_action(classification.failure_class, connector, operation),
            "required_validation": _required_validation(classification),
            "candidate_expectations": _candidate_expectations(classification),
            "review_policy": {
                "approval_required": True,
                "default_state": "disabled_until_review",
                "gate": classification.review_gate,
                "workspace_mutation_allowed_before_approval": False,
            },
        }

    def periodic_nudge(self, *, stale_count: int, low_confidence_count: int) -> dict[str, Any]:
        return {
            "should_review": stale_count > 0 or low_confidence_count > 0,
            "stale_count": stale_count,
            "low_confidence_count": low_confidence_count,
            "default_action": "ask_user_before_memory_or_skill_changes",
        }

    def score_repair_candidate(self, candidate: dict[str, Any], *, proposal: dict[str, Any] | None = None) -> dict[str, Any]:
        return _score_repair_candidate(candidate, proposal=proposal)

    def feedback_loop_summary(self, proposals: list[dict[str, Any]]) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        by_failure_class: dict[str, int] = {}
        by_review_gate: dict[str, int] = {}
        candidate_readiness: dict[str, int] = {}
        candidate_scores: list[int] = []
        open_review_count = 0
        blocked_candidate_count = 0
        ready_candidate_count = 0

        for proposal in proposals:
            status = str(proposal.get("status") or "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            if status in {"proposed", "reviewing"}:
                open_review_count += 1

            metadata = proposal.get("metadata", {}) if isinstance(proposal.get("metadata"), dict) else {}
            plan = metadata.get("repair_plan", {}) if isinstance(metadata.get("repair_plan"), dict) else {}
            classification = plan.get("classification", {}) if isinstance(plan.get("classification"), dict) else {}
            failure_class = str(plan.get("failure_class") or classification.get("failure_class") or _failure_class(str(proposal.get("summary") or "")))
            review_gate = str(plan.get("review_gate") or classification.get("review_gate") or _review_gate(failure_class))
            by_failure_class[failure_class] = by_failure_class.get(failure_class, 0) + 1
            by_review_gate[review_gate] = by_review_gate.get(review_gate, 0) + 1

            for candidate in metadata.get("repair_candidates", []) if isinstance(metadata.get("repair_candidates"), list) else []:
                if not isinstance(candidate, dict):
                    continue
                score = _score_repair_candidate(candidate, proposal=proposal)
                readiness = str(score["readiness"])
                candidate_readiness[readiness] = candidate_readiness.get(readiness, 0) + 1
                candidate_scores.append(int(score["score"]))
                if readiness in {"blocked", "rejected"}:
                    blocked_candidate_count += 1
                if readiness in {"ready_for_review", "ready_to_apply", "ready_to_implement", "ready_to_verify", "verified"}:
                    ready_candidate_count += 1

        average_candidate_score = round(sum(candidate_scores) / len(candidate_scores), 2) if candidate_scores else 0.0
        return {
            "generated_at": now_utc(),
            "proposal_count": len(proposals),
            "by_status": dict(sorted(by_status.items())),
            "failure_classes": dict(sorted(by_failure_class.items())),
            "review_gates": dict(sorted(by_review_gate.items())),
            "candidate_readiness": dict(sorted(candidate_readiness.items())),
            "candidate_count": len(candidate_scores),
            "average_candidate_score": average_candidate_score,
            "ready_candidate_count": ready_candidate_count,
            "blocked_candidate_count": blocked_candidate_count,
            "open_review_count": open_review_count,
            "next_actions": _feedback_next_actions(by_status, candidate_readiness, blocked_candidate_count),
        }


def _failure_class(summary: str) -> str:
    return _classify_failure(summary).failure_class


def _classify_failure(summary: str) -> FailureClassification:
    lowered = summary.lower()
    matched_class = "runtime_failure"
    matched_signals: list[str] = []
    for failure_class, phrases in _FAILURE_CLASS_RULES:
        signals = [_signal_label(phrase) for phrase in phrases if phrase in lowered]
        if signals:
            matched_class = failure_class
            matched_signals = _dedupe(signals)
            break
    if not matched_signals:
        matched_signals = ["unclassified_failure"]
    severity = _severity(matched_class, matched_signals)
    confidence = _confidence(matched_class, matched_signals)
    retryable = any(signal in _RETRYABLE_SIGNALS for signal in matched_signals)
    return FailureClassification(
        failure_class=matched_class,
        severity=severity,
        confidence=confidence,
        signals=tuple(matched_signals),
        review_gate=_review_gate(matched_class),
        retryable=retryable,
    )


def _proposed_action(failure_class: str, connector: str, operation: str) -> str:
    if failure_class == "context_safety":
        return f"Quarantine untrusted {connector} {operation} evidence, preserve receipts, and require security review before repair."
    if failure_class == "policy_or_permission":
        return f"Review whether {connector} {operation} needs a safer scoped capability, clearer denial, or documentation."
    if failure_class == "tool_execution":
        return f"Add focused coverage for {connector} {operation} and repair the failing execution path."
    if failure_class == "model_invocation":
        return "Verify provider routing, authentication, fallback behavior, and receipt capture."
    if failure_class == "data_contract":
        return f"Tighten parsing and validation around {connector} {operation}, then add malformed-input coverage."
    if failure_class == "persistence_state":
        return "Inspect local state transitions, migrations, and rollback behavior before changing durable records."
    if failure_class == "configuration":
        return "Validate local configuration defaults and produce a clear operator-facing remediation."
    return "Investigate the runtime failure, add a regression test, and record verification evidence."


def _required_validation(classification: FailureClassification) -> list[str]:
    validation = [
        "capture changed files or generated candidate id",
        "run a focused regression or verification command",
        "record the verification result before marking implemented",
        "treat diagnostic context as untrusted evidence",
    ]
    if classification.failure_class == "context_safety":
        validation.extend(
            [
                "verify secrets and quarantined content are not persisted in repair artifacts",
                "obtain security review before any policy or prompt-handling change",
            ]
        )
    elif classification.failure_class == "policy_or_permission":
        validation.append("confirm the repair does not broaden access without explicit approval")
    elif classification.failure_class == "model_invocation":
        validation.append("verify provider fallback and auth errors are captured without logging raw secrets")
    elif classification.failure_class == "data_contract":
        validation.append("include malformed or missing-field input in regression coverage")
    elif classification.failure_class == "persistence_state":
        validation.append("verify local state remains recoverable after retry or rollback")
    elif classification.retryable:
        validation.append("cover retry and timeout behavior with bounded local verification")
    return validation


def _candidate_expectations(classification: FailureClassification) -> dict[str, Any]:
    required_artifacts = ["summary", "patch_plan", "changed_files_or_patch", "verification_command"]
    if classification.failure_class in {"context_safety", "policy_or_permission"}:
        required_artifacts.append("reviewer_rationale")
    if classification.failure_class == "persistence_state":
        required_artifacts.append("rollback_or_migration_notes")
    return {
        "minimum_score_for_review": 60,
        "minimum_score_for_application": 80,
        "required_artifacts": required_artifacts,
        "must_preserve_local_first": True,
        "must_remain_dependency_free": True,
    }


def _score_repair_candidate(candidate: dict[str, Any], *, proposal: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ValueError("repair candidate must be a JSON object")

    score = 0
    blockers: list[dict[str, str]] = []
    review_gates: list[dict[str, str]] = []
    signals: list[str] = []
    status = str(candidate.get("status") or "unknown")
    review_status = str(candidate.get("review_status") or "pending")
    patch = candidate.get("patch") if isinstance(candidate.get("patch"), dict) else {}
    sandbox = candidate.get("sandbox") if isinstance(candidate.get("sandbox"), dict) else {}
    has_patch = bool(str(patch.get("unified_diff") or "").strip())
    changed_files = _string_list(candidate.get("changed_files"))
    has_scope = bool(changed_files or has_patch)
    summary = str(candidate.get("summary") or "").strip()
    patch_plan = str(candidate.get("patch_plan") or "").strip()

    if summary:
        score += 15
        signals.append("has_summary")
    else:
        blockers.append({"type": "missing_summary", "detail": "candidate needs a concise repair summary"})
    if patch_plan:
        score += 20
        signals.append("has_patch_plan")
    else:
        blockers.append({"type": "missing_patch_plan", "detail": "candidate needs an implementation or patch plan"})
    if has_scope:
        score += 20
        signals.append("has_changed_scope")
    else:
        blockers.append({"type": "missing_changed_scope", "detail": "candidate needs changed files or an applicable patch"})

    if has_patch:
        preflight = patch.get("preflight") if isinstance(patch.get("preflight"), dict) else {}
        if _check_ok(preflight):
            score += 20
            signals.append("patch_preflight_passed")
        else:
            blockers.append({"type": "patch_preflight_missing_or_failed", "detail": "applicable patch candidates require passing preflight"})
    elif patch_plan:
        score += 10
        signals.append("plan_only_candidate")

    if sandbox:
        if sandbox.get("workspace_mutated") is False:
            score += 5
            signals.append("sandbox_preserved_workspace")
        if sandbox.get("verified") is True:
            score += 10
            signals.append("sandbox_verified")
        else:
            blockers.append({"type": "sandbox_unverified", "detail": "generated or synthesized candidates require sandbox verification"})

    if isinstance(candidate.get("prompt"), dict):
        score += 5
        signals.append("prompt_lineage_recorded")

    if review_status == "approved":
        score += 15
        signals.append("review_approved")
    elif review_status == "rejected":
        blockers.append({"type": "candidate_rejected", "detail": "rejected candidates cannot be applied"})
    else:
        review_gates.append({"type": "candidate_review_required", "detail": "candidate needs approve/reject disposition"})

    if status == "verified":
        score += 10
        signals.append("verified")
    elif status == "applied_pending_verification":
        score += 5
        review_gates.append({"type": "verification_required", "detail": "applied candidate needs passing verification"})

    score = max(0, min(100, score))
    readiness = _candidate_readiness(
        blockers=blockers,
        review_gates=review_gates,
        review_status=review_status,
        status=status,
        has_patch=has_patch,
        patch_ok=(not has_patch or "patch_preflight_passed" in signals),
    )
    return {
        "candidate_id": candidate.get("id"),
        "proposal_id": (proposal or {}).get("id"),
        "score": score,
        "readiness": readiness,
        "status": status,
        "review_status": review_status,
        "signals": signals,
        "blockers": blockers,
        "review_gates": review_gates,
        "next_actions": _candidate_next_actions(readiness, blockers, review_gates),
    }


def _candidate_readiness(
    *,
    blockers: list[dict[str, str]],
    review_gates: list[dict[str, str]],
    review_status: str,
    status: str,
    has_patch: bool,
    patch_ok: bool,
) -> str:
    if any(blocker["type"] == "candidate_rejected" for blocker in blockers):
        return "rejected"
    if blockers:
        return "blocked"
    if status == "verified":
        return "verified"
    if status == "applied_pending_verification":
        return "ready_to_verify"
    if review_status != "approved":
        return "ready_for_review"
    if has_patch and patch_ok:
        return "ready_to_apply"
    return "ready_to_implement"


def _candidate_next_actions(readiness: str, blockers: list[dict[str, str]], review_gates: list[dict[str, str]]) -> list[str]:
    if blockers:
        return [_action_for_blocker(blocker["type"]) for blocker in blockers]
    if readiness == "ready_for_review":
        return ["Approve or reject the candidate before any workspace mutation."]
    if readiness == "ready_to_apply":
        return ["Apply the reviewed patch, then run and record focused verification."]
    if readiness == "ready_to_implement":
        return ["Implement the reviewed plan with changed-file evidence and verification."]
    if readiness == "ready_to_verify":
        return ["Run verification and record the repair attempt before marking implemented."]
    if readiness == "verified":
        return ["No candidate action required; keep the verification receipt linked to the proposal."]
    if review_gates:
        return [gate["detail"] for gate in review_gates]
    return ["Record a repair candidate with enough evidence for review."]


def _action_for_blocker(blocker_type: str) -> str:
    actions = {
        "missing_summary": "Add a concise repair summary.",
        "missing_patch_plan": "Add an implementation or patch plan.",
        "missing_changed_scope": "Declare changed files or provide an applicable patch.",
        "patch_preflight_missing_or_failed": "Run patch preflight and repair the diff before review.",
        "sandbox_unverified": "Regenerate or verify the isolated repair sandbox.",
        "candidate_rejected": "Create a new candidate; rejected candidates cannot proceed.",
    }
    return actions.get(blocker_type, "Resolve candidate evidence blockers before review.")


def _feedback_next_actions(by_status: dict[str, int], candidate_readiness: dict[str, int], blocked_candidate_count: int) -> list[str]:
    actions: list[str] = []
    if by_status.get("proposed", 0):
        actions.append("Move proposed improvements into review or reject them with rationale.")
    if candidate_readiness.get("ready_for_review", 0):
        actions.append("Review ready repair candidates before allowing workspace mutation.")
    if candidate_readiness.get("ready_to_apply", 0) or candidate_readiness.get("ready_to_implement", 0):
        actions.append("Apply approved candidates with changed-file evidence and focused verification.")
    if candidate_readiness.get("ready_to_verify", 0):
        actions.append("Record verification for applied repair candidates.")
    if blocked_candidate_count:
        actions.append("Resolve blocked candidates by adding missing evidence or replacing rejected plans.")
    if not actions:
        actions.append("No open self-improvement feedback loop actions were found.")
    return actions


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _check_ok(value: dict[str, Any]) -> bool:
    return value.get("ok") is True or value.get("status") in {"check_passed", "passed", "verified"}


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _signal_label(phrase: str) -> str:
    return phrase.replace(" ", "_").replace("-", "_").strip("_")


def _severity(failure_class: str, signals: list[str]) -> str:
    if failure_class == "context_safety" or any(signal in _HIGH_SEVERITY_SIGNALS for signal in signals):
        return "high"
    if failure_class in {"policy_or_permission", "persistence_state", "model_invocation"}:
        return "medium"
    if failure_class == "runtime_failure" and signals == ["unclassified_failure"]:
        return "low"
    return "medium"


def _confidence(failure_class: str, signals: list[str]) -> float:
    if failure_class == "runtime_failure" and signals == ["unclassified_failure"]:
        return 0.35
    if len(signals) >= 2:
        return 0.9
    return 0.75


def _review_gate(failure_class: str) -> str:
    return {
        "context_safety": "security_review_required",
        "policy_or_permission": "policy_review_required",
        "tool_execution": "maintainer_review_required",
        "model_invocation": "provider_review_required",
        "data_contract": "contract_review_required",
        "persistence_state": "state_review_required",
        "configuration": "operator_review_required",
    }.get(failure_class, "maintainer_review_required")


_FAILURE_CLASS_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "context_safety",
        (
            "prompt injection",
            "ignore previous instructions",
            "quarantine",
            "taint",
            "untrusted",
            "exfiltration",
            "leak secret",
            "raw secret",
            "credential",
            "api key",
        ),
    ),
    (
        "policy_or_permission",
        (
            "not allowlisted",
            "allowlist",
            "permission",
            "denied",
            "forbidden",
            "unauthorized",
            "policy",
            "approval",
            "sandbox",
            "escapes workspace",
            "requires approved",
        ),
    ),
    (
        "model_invocation",
        (
            "model",
            "provider",
            "rate limit",
            "context length",
            "token limit",
            "authentication",
            "api error",
        ),
    ),
    (
        "data_contract",
        (
            "json",
            "schema",
            "parse",
            "validation",
            "missing field",
            "typeerror",
            "valueerror",
            "decode",
        ),
    ),
    (
        "persistence_state",
        (
            "sqlite",
            "database",
            "migration",
            "state",
            "checkpoint",
            "corrupt",
            "rollback",
        ),
    ),
    (
        "configuration",
        (
            "config",
            "environment",
            "env var",
            "not configured",
            "missing setting",
        ),
    ),
    (
        "tool_execution",
        (
            "connector",
            "tool",
            "subprocess",
            "command",
            "returncode",
            "exit code",
            "timeout",
            "network",
        ),
    ),
)

_HIGH_SEVERITY_SIGNALS = {"exfiltration", "leak_secret", "raw_secret", "credential", "api_key", "escapes_workspace"}
_RETRYABLE_SIGNALS = {"timeout", "network", "rate_limit", "api_error"}
