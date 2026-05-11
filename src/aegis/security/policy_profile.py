"""Policy profile loading for local admin-controlled security posture."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import json
import re
import tomllib

from aegis.research.harness import ResearchHarness
from aegis.security.taint import now_utc


VALID_POLICY_ACTIONS = {
    "allow",
    "deny",
    "require_approval",
    "require_admin_approval",
    "require_dry_run_first",
    "require_additional_evidence",
    "require_safer_alternative",
    "quarantine",
}

_ACTION_FIELDS = {
    "raw_secret_exposure",
    "destructive_action",
    "message_send",
    "shell_execution",
    "unknown_shell_command",
    "unapproved_network_egress",
    "skill_without_valid_manifest",
    "connector_write_without_scope",
    "high_risk_action",
    "high_risk_memory_without_confirmation",
    "secret_data",
}
_IMMUTABLE_DENY_FIELDS = {"raw_secret_exposure", "secret_data"}
_DEFAULT_FIELDS = _ACTION_FIELDS | {"read_only"}
_POLICY_BUNDLES: dict[str, dict[str, Any]] = {
    "strict-local": {
        "description": "Maximum local safety: risky writes, messages, network egress, shell, and high-risk actions require admin approval.",
        "profile": {
            "defaults": {
                "read_only": True,
                "destructive_action": "require_admin_approval",
                "message_send": "require_admin_approval",
                "shell_execution": "require_admin_approval",
                "unapproved_network_egress": "require_admin_approval",
                "high_risk_action": "require_admin_approval",
            },
            "network": {"allowlist": ["localhost", "127.0.0.1"]},
            "shell": {"allowlist": ["pwd", "ls", "find", "python3"]},
        },
    },
    "approval-first": {
        "description": "Default Aegis posture: low-risk reads allowed, writes and risky actions require approval.",
        "profile": {
            "defaults": {
                "read_only": True,
                "destructive_action": "require_approval",
                "message_send": "require_approval",
                "shell_execution": "require_approval",
                "unapproved_network_egress": "require_approval",
                "high_risk_action": "require_approval",
            },
        },
    },
    "developer-local": {
        "description": "Local development posture with loopback egress and common read-only shell commands allowlisted; secret controls remain immutable deny.",
        "profile": {
            "defaults": {
                "read_only": True,
                "destructive_action": "require_approval",
                "message_send": "require_approval",
                "shell_execution": "require_approval",
                "unapproved_network_egress": "require_approval",
            },
            "network": {"allowlist": ["localhost", "127.0.0.1", "example.com"]},
            "shell": {"allowlist": ["pwd", "ls", "find", "python3"]},
        },
    },
}


@dataclass(frozen=True)
class PolicyProfile:
    read_only: bool = True
    raw_secret_exposure: str = "deny"
    destructive_action: str = "require_approval"
    message_send: str = "require_approval"
    shell_execution: str = "require_approval"
    unknown_shell_command: str = "deny"
    unapproved_network_egress: str = "require_approval"
    skill_without_valid_manifest: str = "deny"
    connector_write_without_scope: str = "deny"
    high_risk_action: str = "require_approval"
    high_risk_memory_without_confirmation: str = "deny"
    secret_data: str = "deny"
    network_allowlist: tuple[str, ...] = ()
    shell_allowlist: tuple[str, ...] = ()

    @classmethod
    def secure_default(
        cls,
        *,
        read_only: bool = True,
        network_allowlist: tuple[str, ...] = (),
        shell_allowlist: tuple[str, ...] = (),
    ) -> "PolicyProfile":
        return cls(read_only=read_only, network_allowlist=network_allowlist, shell_allowlist=shell_allowlist)


def load_policy_profile(path: str | Path, *, base: PolicyProfile | None = None) -> PolicyProfile:
    with Path(path).open("rb") as handle:
        raw = tomllib.load(handle)
    return parse_policy_profile(raw, base=base)


def import_policy_bundle(source: str | Path, *, base: PolicyProfile | None = None) -> dict[str, Any]:
    source_path = Path(source).expanduser()
    with source_path.open("rb") as handle:
        raw = tomllib.load(handle)
    profile = parse_policy_profile(raw, base=base)
    return {
        "ok": True,
        "source": str(source_path),
        "profile": policy_profile_to_dict(profile),
        "toml": _bundle_toml(raw),
    }


def import_policy_bundle_text(toml_text: str, *, source: str = "inline", base: PolicyProfile | None = None) -> dict[str, Any]:
    raw = tomllib.loads(toml_text)
    profile = parse_policy_profile(raw, base=base)
    return {
        "ok": True,
        "source": source,
        "profile": policy_profile_to_dict(profile),
        "toml": _bundle_toml(raw),
    }


def apply_policy_bundle(
    source: str | Path,
    *,
    data_dir: str | Path,
    approved: bool = False,
    name: str | None = None,
    base: PolicyProfile | None = None,
) -> dict[str, Any]:
    if not approved:
        return {"ok": False, "status": "approval_required", "reason": "policy bundle apply requires explicit approval"}
    if str(source) in _POLICY_BUNDLES:
        imported = export_policy_bundle(str(source))
        bundle_name = str(source)
    else:
        imported = import_policy_bundle(source, base=base)
        bundle_name = name or Path(source).stem
    data_path = Path(data_dir).expanduser().resolve()
    policy_dir = data_path / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy_dir.chmod(0o700)
    filename = f"{_safe_bundle_name(bundle_name)}.toml"
    policy_path = policy_dir / filename
    policy_path.write_text(str(imported["toml"]), encoding="utf-8")
    policy_path.chmod(0o600)
    config_path = data_path / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    relative_policy_path = f"policies/{filename}"
    previous_policy_path = _get_config_policy_path(config_path)
    _set_config_policy_path(config_path, relative_policy_path)
    _write_policy_rollback(data_path, previous_policy_path=previous_policy_path, applied_policy_path=relative_policy_path)
    return {
        "ok": True,
        "status": "applied",
        "name": bundle_name,
        "policy_path": str(policy_path),
        "config_path": str(config_path),
        "config_policy_path": relative_policy_path,
        "previous_policy_path": previous_policy_path,
        "profile": imported["profile"],
        "restart_required": True,
    }


def diff_policy_bundle(source: str | Path, *, current: PolicyProfile, base: PolicyProfile | None = None) -> dict[str, Any]:
    if str(source) in _POLICY_BUNDLES:
        candidate = export_policy_bundle(str(source))
        name = str(source)
    else:
        candidate = import_policy_bundle(source, base=base)
        name = Path(source).stem
    return _policy_profile_diff(name=name, current=policy_profile_to_dict(current), candidate=candidate["profile"])


def diff_policy_bundle_text(toml_text: str, *, current: PolicyProfile, name: str = "inline", base: PolicyProfile | None = None) -> dict[str, Any]:
    candidate = import_policy_bundle_text(toml_text, source=name, base=base)
    return _policy_profile_diff(name=name, current=policy_profile_to_dict(current), candidate=candidate["profile"])


def rollback_policy_bundle(*, data_dir: str | Path, approved: bool = False) -> dict[str, Any]:
    if not approved:
        return {"ok": False, "status": "approval_required", "reason": "policy rollback requires explicit approval"}
    data_path = Path(data_dir).expanduser().resolve()
    rollback_path = data_path / "policies" / ".rollback.json"
    if not rollback_path.exists():
        return {"ok": False, "status": "no_rollback", "reason": "no policy rollback receipt is available"}
    receipt = json.loads(rollback_path.read_text(encoding="utf-8"))
    config_path = data_path / "config.toml"
    current_policy_path = _get_config_policy_path(config_path)
    applied_policy_path = receipt.get("applied_policy_path")
    if applied_policy_path and current_policy_path and current_policy_path != applied_policy_path:
        return {
            "ok": False,
            "status": "stale_rollback",
            "reason": "current policy path no longer matches rollback receipt",
            "current_policy_path": current_policy_path,
            "applied_policy_path": applied_policy_path,
        }
    previous_policy_path = receipt.get("previous_policy_path")
    _set_config_policy_path(config_path, str(previous_policy_path) if previous_policy_path else None)
    rollback_path.unlink()
    return {
        "ok": True,
        "status": "rolled_back",
        "previous_policy_path": previous_policy_path,
        "removed_policy_path": applied_policy_path,
        "config_path": str(config_path),
        "restart_required": True,
    }


def schedule_policy_bundle(
    source: str | Path,
    *,
    data_dir: str | Path,
    activate_at: str,
    environment: str = "local",
    approved: bool = False,
    name: str | None = None,
    base: PolicyProfile | None = None,
) -> dict[str, Any]:
    if not approved:
        return {"ok": False, "status": "approval_required", "reason": "policy rollout scheduling requires explicit approval"}
    candidate = _load_policy_candidate(source, base=base, name=name)
    data_path = Path(data_dir).expanduser().resolve()
    rollout_dir = data_path / "policies" / "rollouts"
    rollout_dir.mkdir(parents=True, exist_ok=True)
    rollout_dir.chmod(0o700)
    environment_name = _safe_bundle_name(environment)
    bundle_name = _safe_bundle_name(str(candidate["name"]))
    rollout_id = f"{environment_name}-{bundle_name}-{_safe_bundle_name(now_utc())}"
    rollout_path = rollout_dir / f"{rollout_id}.json"
    receipt = {
        "id": rollout_id,
        "status": "scheduled",
        "environment": environment_name,
        "name": candidate["name"],
        "source": str(source),
        "activate_at": activate_at,
        "created_at": now_utc(),
        "profile": candidate["profile"],
        "toml": candidate["toml"],
        "connects_to_target": False,
        "writes_active_config": False,
        "restart_required_at_activation": True,
    }
    rollout_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rollout_path.chmod(0o600)
    return {
        "ok": True,
        "status": "scheduled",
        "id": rollout_id,
        "environment": environment_name,
        "activate_at": activate_at,
        "rollout_path": str(rollout_path),
        "profile": candidate["profile"],
        "restart_required": False,
    }


def list_policy_rollouts(*, data_dir: str | Path) -> dict[str, Any]:
    rollout_dir = Path(data_dir).expanduser().resolve() / "policies" / "rollouts"
    rollouts = []
    if rollout_dir.exists():
        for path in sorted(rollout_dir.glob("*.json")):
            try:
                rollouts.append(json.loads(path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                rollouts.append({"id": path.stem, "status": "invalid_receipt", "path": str(path)})
    return {"ok": True, "rollouts": rollouts}


def list_policy_promotions(*, data_dir: str | Path, limit: int = 20) -> dict[str, Any]:
    receipt_path = Path(data_dir).expanduser().resolve() / "policies" / "promotions.jsonl"
    promotions = []
    if receipt_path.exists():
        for line in receipt_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError:
                promotions.append({"status": "invalid_receipt", "reason": "invalid promotion receipt JSON"})
                continue
            if isinstance(decoded, dict):
                promotions.append(decoded)
    return {"ok": True, "promotions": promotions[-max(0, int(limit)) :], "receipt_path": str(receipt_path)}


def activate_due_policy_rollouts(
    *,
    data_dir: str | Path,
    now: str | datetime | None = None,
    environment: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    data_path = Path(data_dir).expanduser().resolve()
    rollout_dir = data_path / "policies" / "rollouts"
    current = _parse_policy_datetime(now or now_utc())
    environment_name = _safe_bundle_name(environment) if environment else None
    activated: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    if not rollout_dir.exists():
        return {"ok": True, "activated": 0, "results": [], "skipped": [], "restart_required": False}
    for path in sorted(rollout_dir.glob("*.json")):
        if len(activated) >= max(0, int(limit)):
            break
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            skipped.append({"id": path.stem, "status": "invalid_receipt", "reason": "invalid rollout receipt JSON"})
            continue
        rollout_id = str(receipt.get("id", path.stem))
        if receipt.get("status") != "scheduled":
            skipped.append({"id": rollout_id, "status": receipt.get("status", "unknown"), "reason": "not scheduled"})
            continue
        if environment_name and receipt.get("environment") != environment_name:
            skipped.append({"id": rollout_id, "status": receipt.get("status", "unknown"), "reason": "different environment"})
            continue
        activate_at = _parse_policy_datetime(str(receipt.get("activate_at", "")))
        if activate_at > current:
            skipped.append({"id": rollout_id, "status": "scheduled", "reason": "not due", "activate_at": receipt.get("activate_at")})
            continue
        toml_text = str(receipt.get("toml", ""))
        if not toml_text.strip():
            skipped.append({"id": rollout_id, "status": "invalid_receipt", "reason": "missing policy TOML"})
            continue
        apply_result = apply_policy_bundle_text(
            toml_text,
            data_dir=data_path,
            approved=True,
            name=f"{receipt.get('environment', 'local')}-{receipt.get('name', rollout_id)}",
        )
        updated = {
            **receipt,
            "status": "activated",
            "activated_at": now_utc(),
            "writes_active_config": True,
            "activation": {
                "policy_path": apply_result["policy_path"],
                "config_policy_path": apply_result["config_policy_path"],
                "previous_policy_path": apply_result["previous_policy_path"],
            },
        }
        path.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(0o600)
        activated.append(
            {
                "id": rollout_id,
                "environment": updated.get("environment"),
                "name": updated.get("name"),
                "status": "activated",
                "policy_path": apply_result["policy_path"],
                "config_policy_path": apply_result["config_policy_path"],
                "restart_required": True,
            }
        )
    return {
        "ok": True,
        "activated": len(activated),
        "results": activated,
        "skipped": skipped,
        "restart_required": bool(activated),
    }


def promote_policy_bundle(
    source: str | Path,
    *,
    data_dir: str | Path,
    from_environment: str,
    to_environment: str,
    approved: bool = False,
    name: str | None = None,
    base: PolicyProfile | None = None,
    require_clean_evaluation: bool = False,
    baseline_report_id: str | None = None,
    candidate_report_id: str | None = None,
    evaluation_scenario: str | None = None,
    require_live_parity: bool = False,
    live_gap_backlog: list[dict[str, Any]] | None = None,
    deferred_live_gap_areas: list[str] | None = None,
    live_gap_deferral_reason: str | None = None,
) -> dict[str, Any]:
    if not approved:
        return {"ok": False, "status": "approval_required", "reason": "policy environment promotion requires explicit approval"}
    evaluation_delta = None
    if require_clean_evaluation:
        evaluation_delta = ResearchHarness(data_dir=data_dir).evaluation_regression_delta(
            baseline_report_id=baseline_report_id,
            candidate_report_id=candidate_report_id,
            scenario=evaluation_scenario,
        )
        if evaluation_delta.get("regression"):
            return {
                "ok": False,
                "status": "blocked_by_evaluation_regression",
                "reason": "policy promotion requires a clean evaluation delta",
                "evaluation_delta": evaluation_delta,
            }
        if evaluation_delta.get("status") == "insufficient_history":
            return {
                "ok": False,
                "status": "blocked_by_missing_evaluation_history",
                "reason": "policy promotion requires at least two evaluation reports",
                "evaluation_delta": evaluation_delta,
            }
    live_parity_gate = live_gap_backlog or []
    open_live_gaps, deferred_live_gaps = _partition_live_gap_backlog(live_parity_gate, deferred_live_gap_areas or [])
    if require_live_parity and deferred_live_gaps and not str(live_gap_deferral_reason or "").strip():
        return {
            "ok": False,
            "status": "blocked_by_live_parity_deferral_missing_reason",
            "reason": "live parity deferrals require an explicit reason",
            "deferred_live_gaps": deferred_live_gaps,
        }
    if require_live_parity and open_live_gaps:
        return {
            "ok": False,
            "status": "blocked_by_live_parity_gap",
            "reason": "policy promotion requires closing or explicitly deferring live parity gaps",
            "live_gap_backlog": open_live_gaps,
            "deferred_live_gaps": deferred_live_gaps,
            "live_gap_deferral_reason": str(live_gap_deferral_reason or "").strip() or None,
        }
    candidate = _load_policy_candidate(source, base=base, name=name)
    data_path = Path(data_dir).expanduser().resolve()
    from_name = _safe_bundle_name(from_environment)
    to_name = _safe_bundle_name(to_environment)
    bundle_name = _safe_bundle_name(str(candidate["name"]))
    environment_dir = data_path / "policies" / "environments" / to_name
    environment_dir.mkdir(parents=True, exist_ok=True)
    environment_dir.chmod(0o700)
    policy_path = environment_dir / f"{bundle_name}.toml"
    policy_path.write_text(str(candidate["toml"]), encoding="utf-8")
    policy_path.chmod(0o600)
    receipt_path = data_path / "policies" / "promotions.jsonl"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt = {
        "status": "promoted",
        "name": candidate["name"],
        "source": str(source),
        "from_environment": from_name,
        "to_environment": to_name,
        "policy_path": str(policy_path),
        "created_at": now_utc(),
        "connects_to_target": False,
        "writes_active_config": False,
        "evaluation_gate": evaluation_delta,
        "live_parity_gate": live_parity_gate if require_live_parity else None,
        "deferred_live_gaps": deferred_live_gaps if require_live_parity else [],
        "live_gap_deferral_reason": str(live_gap_deferral_reason or "").strip() or None,
    }
    with receipt_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(receipt, sort_keys=True) + "\n")
    receipt_path.chmod(0o600)
    return {
        "ok": True,
        "status": "promoted",
        "name": candidate["name"],
        "from_environment": from_name,
        "to_environment": to_name,
        "policy_path": str(policy_path),
        "receipt_path": str(receipt_path),
        "profile": candidate["profile"],
        "evaluation_gate": evaluation_delta,
        "live_parity_gate": live_parity_gate if require_live_parity else None,
        "deferred_live_gaps": deferred_live_gaps if require_live_parity else [],
        "live_gap_deferral_reason": str(live_gap_deferral_reason or "").strip() or None,
        "restart_required": False,
    }


def parse_policy_profile(raw: dict[str, Any], *, base: PolicyProfile | None = None) -> PolicyProfile:
    profile = base or PolicyProfile.secure_default()
    defaults = _section(raw, "defaults")
    network = _section(raw, "network")
    shell = _section(raw, "shell")

    unknown_defaults = set(defaults) - _DEFAULT_FIELDS
    if unknown_defaults:
        raise ValueError(f"unknown policy defaults: {', '.join(sorted(unknown_defaults))}")

    updates: dict[str, Any] = {}
    if "read_only" in defaults:
        updates["read_only"] = bool(defaults["read_only"])
    for field_name in _ACTION_FIELDS:
        if field_name in defaults:
            action = _policy_action(defaults[field_name], field_name=field_name)
            updates[field_name] = action

    if "allowlist" in network:
        updates["network_allowlist"] = _string_tuple(network["allowlist"], section="network.allowlist")
    if "allowlist" in shell:
        updates["shell_allowlist"] = _string_tuple(shell["allowlist"], section="shell.allowlist")

    return replace(profile, **updates)


def policy_profile_to_dict(profile: PolicyProfile) -> dict[str, Any]:
    data = asdict(profile)
    data["network_allowlist"] = list(profile.network_allowlist)
    data["shell_allowlist"] = list(profile.shell_allowlist)
    return data


def list_policy_bundles() -> list[dict[str, Any]]:
    bundles = []
    for name, bundle in sorted(_POLICY_BUNDLES.items()):
        profile = parse_policy_profile(bundle["profile"])
        bundles.append({"name": name, "description": bundle["description"], "profile": policy_profile_to_dict(profile)})
    return bundles


def export_policy_bundle(name: str) -> dict[str, Any]:
    if name not in _POLICY_BUNDLES:
        raise KeyError(name)
    bundle = _POLICY_BUNDLES[name]
    profile = parse_policy_profile(bundle["profile"])
    return {
        "name": name,
        "description": bundle["description"],
        "profile": policy_profile_to_dict(profile),
        "toml": _bundle_toml(bundle["profile"]),
    }


def _load_policy_candidate(source: str | Path, *, base: PolicyProfile | None = None, name: str | None = None) -> dict[str, Any]:
    if str(source) in _POLICY_BUNDLES:
        candidate = export_policy_bundle(str(source))
        return {**candidate, "name": name or candidate["name"]}
    candidate = import_policy_bundle(source, base=base)
    return {**candidate, "name": name or Path(source).stem}


def apply_policy_bundle_text(
    toml_text: str,
    *,
    data_dir: str | Path,
    approved: bool = False,
    name: str = "imported-policy",
    base: PolicyProfile | None = None,
) -> dict[str, Any]:
    if not approved:
        return {"ok": False, "status": "approval_required", "reason": "policy bundle apply requires explicit approval"}
    imported = import_policy_bundle_text(toml_text, source=name, base=base)
    data_path = Path(data_dir).expanduser().resolve()
    policy_dir = data_path / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy_dir.chmod(0o700)
    filename = f"{_safe_bundle_name(name)}.toml"
    policy_path = policy_dir / filename
    policy_path.write_text(str(imported["toml"]), encoding="utf-8")
    policy_path.chmod(0o600)
    config_path = data_path / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    relative_policy_path = f"policies/{filename}"
    previous_policy_path = _get_config_policy_path(config_path)
    _set_config_policy_path(config_path, relative_policy_path)
    _write_policy_rollback(data_path, previous_policy_path=previous_policy_path, applied_policy_path=relative_policy_path)
    return {
        "ok": True,
        "status": "applied",
        "name": name,
        "policy_path": str(policy_path),
        "config_path": str(config_path),
        "config_policy_path": relative_policy_path,
        "previous_policy_path": previous_policy_path,
        "profile": imported["profile"],
        "restart_required": True,
    }


def _section(raw: dict[str, Any], name: str) -> dict[str, Any]:
    section = raw.get(name, {})
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise ValueError(f"policy section {name!r} must be a table")
    return section


def _policy_action(value: Any, *, field_name: str) -> str:
    action = str(value)
    if action not in VALID_POLICY_ACTIONS:
        raise ValueError(f"unsupported policy action for {field_name}: {action}")
    if field_name in _IMMUTABLE_DENY_FIELDS and action != "deny":
        raise ValueError(f"{field_name} must remain deny")
    return action


def _string_tuple(value: Any, *, section: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{section} must be a list")
    return tuple(str(item) for item in value)


def _safe_bundle_name(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip()).strip(".-")
    return safe or "imported-policy"


def _parse_policy_datetime(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _policy_profile_diff(*, name: str, current: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    changes = []
    for key in sorted(set(current) | set(candidate)):
        before = current.get(key)
        after = candidate.get(key)
        if before != after:
            changes.append({"field": key, "before": before, "after": after})
    return {"ok": True, "name": name, "changes": changes, "changed": bool(changes), "candidate": candidate}


def _partition_live_gap_backlog(live_gap_backlog: list[dict[str, Any]], deferred_areas: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    deferred = {str(area) for area in deferred_areas if str(area).strip()}
    open_gaps = []
    deferred_gaps = []
    for item in live_gap_backlog:
        if str(item.get("area", "")) in deferred:
            deferred_gaps.append(item)
        else:
            open_gaps.append(item)
    return open_gaps, deferred_gaps


def _get_config_policy_path(config_path: Path) -> str | None:
    if not config_path.exists():
        return None
    raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    policy = raw.get("policy", {})
    if not isinstance(policy, dict) or not policy.get("path"):
        return None
    return str(policy["path"])


def _write_policy_rollback(data_path: Path, *, previous_policy_path: str | None, applied_policy_path: str) -> None:
    policy_dir = data_path / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = policy_dir / ".rollback.json"
    receipt_path.write_text(
        json.dumps({"previous_policy_path": previous_policy_path, "applied_policy_path": applied_policy_path}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)


def _set_config_policy_path(config_path: Path, policy_path: str | None) -> None:
    lines = config_path.read_text(encoding="utf-8").splitlines() if config_path.exists() else []
    output: list[str] = []
    in_policy = False
    saw_policy = False
    wrote_path = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_policy and not wrote_path:
                if policy_path is not None:
                    output.append(f'path = "{policy_path}"')
                wrote_path = True
            in_policy = stripped == "[policy]"
            saw_policy = saw_policy or in_policy
            output.append(line)
            continue
        if in_policy and stripped.startswith("path"):
            if policy_path is not None:
                output.append(f'path = "{policy_path}"')
            wrote_path = True
            continue
        output.append(line)
    if not saw_policy and policy_path is not None:
        if output and output[-1] != "":
            output.append("")
        output.extend(["[policy]", f'path = "{policy_path}"'])
    elif in_policy and not wrote_path and policy_path is not None:
        output.append(f'path = "{policy_path}"')
    config_path.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    config_path.chmod(0o600)


def _bundle_toml(raw: dict[str, Any]) -> str:
    lines: list[str] = []
    for section_name in ("defaults", "network", "shell"):
        section = raw.get(section_name)
        if not isinstance(section, dict) or not section:
            continue
        lines.append(f"[{section_name}]")
        for key, value in section.items():
            if isinstance(value, bool):
                rendered = "true" if value else "false"
            elif isinstance(value, list):
                rendered = "[" + ", ".join(f'"{str(item)}"' for item in value) + "]"
            else:
                rendered = f'"{str(value)}"'
            lines.append(f"{key} = {rendered}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
