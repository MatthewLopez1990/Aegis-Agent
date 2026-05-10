"""Skill registry backed by the local store."""

from __future__ import annotations

import json
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import RiskLevel
from aegis.skills.manifest import SkillManifest


class SkillRegistry:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def register(self, manifest: SkillManifest, *, enable: bool = False) -> SkillManifest:
        validated = manifest.validate()
        if validated.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            enable = False
        self.store.insert_skill(validated.id, validated.to_dict(), enabled=enable)
        self.audit_logger.append("skill.registered", {"skill_id": validated.id, "enabled": enable, "risk_level": validated.risk_level.value})
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

    def disable(self, skill_id: str) -> None:
        self.store.set_skill_enabled(skill_id, False)
        self.audit_logger.append("skill.disabled", {"skill_id": skill_id})

    def enable(self, skill_id: str) -> None:
        manifest, _ = self.get(skill_id)
        if manifest.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            raise PermissionError("high-risk skills cannot be enabled without an approval workflow")
        self.store.set_skill_enabled(skill_id, True)
        self.audit_logger.append("skill.enabled", {"skill_id": skill_id})
