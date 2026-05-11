"""Skill manifest validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.security.taint import RiskLevel, now_utc
from aegis.skills.sandbox import get_sandbox_profile


REQUIRED_MANIFEST_FIELDS = {
    "id",
    "name",
    "description",
    "version",
    "author",
    "source",
    "permissions",
    "input_schema",
    "output_schema",
    "risk_level",
    "approval_required",
    "sandbox_profile",
    "tests",
    "evals",
    "rollback",
}


@dataclass(frozen=True)
class SkillManifest:
    id: str
    name: str
    description: str
    version: str
    author: str
    source: str
    permissions: dict[str, Any]
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    risk_level: RiskLevel
    approval_required: bool
    sandbox_profile: str
    tests: list[dict[str, Any]]
    evals: list[dict[str, Any]]
    rollback: str
    created_at: str = field(default_factory=now_utc)
    updated_at: str = field(default_factory=now_utc)
    connectors: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    network: dict[str, Any] = field(default_factory=dict)
    filesystem: dict[str, Any] = field(default_factory=dict)
    commands: list[str] = field(default_factory=list)
    changelog: list[str] = field(default_factory=list)
    signature: dict[str, Any] | None = None
    validated: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SkillManifest":
        missing = REQUIRED_MANIFEST_FIELDS - raw.keys()
        if missing:
            raise ValueError(f"skill manifest missing fields: {sorted(missing)}")
        return cls(
            id=str(raw["id"]),
            name=str(raw["name"]),
            description=str(raw["description"]),
            version=str(raw["version"]),
            author=str(raw["author"]),
            source=str(raw["source"]),
            permissions=dict(raw["permissions"]),
            input_schema=dict(raw["input_schema"]),
            output_schema=dict(raw["output_schema"]),
            risk_level=RiskLevel(str(raw["risk_level"])),
            approval_required=bool(raw["approval_required"]),
            sandbox_profile=str(raw["sandbox_profile"]),
            tests=list(raw["tests"]),
            evals=list(raw["evals"]),
            rollback=str(raw["rollback"]),
            created_at=str(raw.get("created_at", now_utc())),
            updated_at=str(raw.get("updated_at", now_utc())),
            connectors=list(raw.get("connectors", [])),
            secrets=list(raw.get("secrets", [])),
            network=dict(raw.get("network", {})),
            filesystem=dict(raw.get("filesystem", {})),
            commands=list(raw.get("commands", [])),
            changelog=list(raw.get("changelog", [])),
            signature=dict(raw["signature"]) if isinstance(raw.get("signature"), dict) else None,
            validated=bool(raw.get("validated", False)),
        )

    def validate(self) -> "SkillManifest":
        get_sandbox_profile(self.sandbox_profile)
        if self.secrets and self.risk_level not in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            raise ValueError("skills requesting secrets must be high risk")
        if self.commands and self.risk_level != RiskLevel.HIGH:
            raise ValueError("skills requesting shell commands must be high risk")
        if self.permissions.get("filesystem", {}).get("write") and self.risk_level != RiskLevel.HIGH:
            raise ValueError("filesystem write skills must be high risk")
        if self.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} and not self.approval_required:
            raise ValueError("high-risk skills must require approval")
        return SkillManifest(**{**self.to_dict(), "validated": True, "risk_level": self.risk_level})

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "source": self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "permissions": self.permissions,
            "connectors": self.connectors,
            "secrets": self.secrets,
            "network": self.network,
            "filesystem": self.filesystem,
            "commands": self.commands,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "risk_level": self.risk_level.value,
            "approval_required": self.approval_required,
            "sandbox_profile": self.sandbox_profile,
            "tests": self.tests,
            "evals": self.evals,
            "rollback": self.rollback,
            "changelog": self.changelog,
            "signature": self.signature,
            "validated": self.validated,
        }
