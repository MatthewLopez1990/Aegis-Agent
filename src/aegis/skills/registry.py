"""Skill registry backed by the local store."""

from __future__ import annotations

import json
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import RiskLevel
from aegis.skills.manifest import SkillManifest
from aegis.skills.signing import DEFAULT_SKILL_SIGNING_KEY, verify_manifest_signature
from aegis.skills.static_scan import scan_skill_manifest
from aegis.security.secrets_broker import SecretsBroker


class SkillRegistry:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger, secrets_broker: SecretsBroker | None = None) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.secrets_broker = secrets_broker or SecretsBroker()

    def register(
        self,
        manifest: SkillManifest,
        *,
        enable: bool = False,
        require_signature: bool = False,
        signature_key_name: str = DEFAULT_SKILL_SIGNING_KEY,
    ) -> SkillManifest:
        signature = verify_manifest_signature(manifest.to_dict(), self.secrets_broker, required=require_signature, key_name=signature_key_name)
        if not signature["ok"]:
            self.audit_logger.append("skill.signature_failed", {"skill_id": manifest.id, "reason": signature["reason"], "required": require_signature})
            raise PermissionError(f"skill signature verification failed: {signature['reason']}")
        validated = manifest.validate()
        static_scan = scan_skill_manifest(validated)
        if not static_scan["ok"]:
            self.audit_logger.append("skill.static_scan_failed", {"skill_id": validated.id, "scan": static_scan})
            raise PermissionError("skill static scan failed")
        if validated.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            enable = False
        self.store.insert_skill(validated.id, validated.to_dict(), enabled=enable)
        self.audit_logger.append(
            "skill.registered",
            {
                "skill_id": validated.id,
                "enabled": enable,
                "risk_level": validated.risk_level.value,
                "signature": signature,
                "static_scan": static_scan,
            },
        )
        return validated

    def get(self, skill_id: str) -> tuple[SkillManifest, bool]:
        row = self.store.get_skill(skill_id)
        if not row:
            raise KeyError(skill_id)
        return SkillManifest.from_dict(json.loads(row["manifest_json"])), bool(row["enabled"])

    def list(self) -> list[dict[str, Any]]:
        rows = self.store.list_skills()
        return [
            {
                "id": row["id"],
                "enabled": bool(row["enabled"]),
                "manifest": json.loads(row["manifest_json"]),
            }
            for row in rows
        ]

    def list_public(self) -> list[dict[str, Any]]:
        rows = self.store.list_skills()
        return [_public_skill_summary(row) for row in rows]

    def disable(self, skill_id: str) -> None:
        self.get(skill_id)
        self.store.set_skill_enabled(skill_id, False)
        self.audit_logger.append("skill.disabled", {"skill_id": skill_id})

    def remove(self, skill_id: str) -> dict[str, Any]:
        manifest, enabled = self.get(skill_id)
        self.store.delete_skill(skill_id)
        self.audit_logger.append("skill.removed", {"skill_id": skill_id, "was_enabled": enabled, "risk_level": manifest.risk_level.value})
        return {"skill_id": skill_id, "was_enabled": enabled, "risk_level": manifest.risk_level.value}

    def enable(self, skill_id: str, *, approved: bool = False, admin_approved: bool = False) -> None:
        manifest, _ = self.get(skill_id)
        if manifest.risk_level == RiskLevel.HIGH and not approved:
            raise PermissionError("high-risk skills require an approved enable request")
        if manifest.risk_level == RiskLevel.CRITICAL and not (approved and admin_approved):
            raise PermissionError("critical-risk skills require an approved admin enable request")
        self.store.set_skill_enabled(skill_id, True)
        self.audit_logger.append("skill.enabled", {"skill_id": skill_id, "approved": approved, "admin_approved": admin_approved, "risk_level": manifest.risk_level.value})


def _public_skill_summary(row: dict[str, Any]) -> dict[str, Any]:
    manifest = json.loads(row["manifest_json"])
    permissions = manifest.get("permissions", {})
    network = manifest.get("network", {})
    filesystem = manifest.get("filesystem", {})
    secrets = manifest.get("secrets", [])
    commands = manifest.get("commands", [])
    return {
        "id": str(row["id"]),
        "name": str(manifest.get("name", "")),
        "description": str(manifest.get("description", "")),
        "version": str(manifest.get("version", "")),
        "enabled": bool(row["enabled"]),
        "risk_level": str(manifest.get("risk_level", "")),
        "approval_required": bool(manifest.get("approval_required", False)),
        "sandbox_profile": str(manifest.get("sandbox_profile", "")),
        "validated": bool(manifest.get("validated", False)),
        "connectors": [str(connector) for connector in manifest.get("connectors", [])],
        "permissions_summary": _permissions_summary(permissions),
        "has_secrets": bool(secrets) if isinstance(secrets, list) else False,
        "has_network": bool(network) if isinstance(network, dict) else False,
        "has_commands": bool(commands) if isinstance(commands, list) else False,
        "has_filesystem_access": bool(filesystem) if isinstance(filesystem, dict) else False,
        "created_at": str(manifest.get("created_at", row.get("created_at", ""))),
        "updated_at": str(manifest.get("updated_at", row.get("updated_at", ""))),
    }


def _permissions_summary(permissions: Any) -> list[str]:
    if not isinstance(permissions, dict):
        return []
    summary: list[str] = []
    for domain, value in sorted(permissions.items()):
        if isinstance(value, dict):
            enabled = [str(name) for name, allowed in sorted(value.items()) if bool(allowed)]
            summary.extend(f"{domain}:{name}" for name in enabled)
        elif isinstance(value, list):
            summary.extend(f"{domain}:{name}" for name in sorted(str(item) for item in value))
        elif bool(value):
            summary.append(str(domain))
    return summary
