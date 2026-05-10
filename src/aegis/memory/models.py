"""Memory record types with provenance and safety metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

from aegis.security.taint import Sensitivity, now_utc


class MemoryType(str, Enum):
    PROFILE = "profile_memory"
    PREFERENCE = "preference_memory"
    PROJECT = "project_memory"
    WORKFLOW = "workflow_memory"
    PROCEDURAL = "procedural_memory"
    EPISODIC = "episodic_memory"
    CONNECTOR = "connector_memory"
    POLICY = "policy_memory"
    SKILL = "skill_memory"


@dataclass(frozen=True)
class MemoryRecord:
    type: MemoryType
    content: str
    summary: str
    source: str
    provenance: dict[str, Any]
    confidence: float
    sensitivity: Sensitivity
    owner: str
    scope: str
    tags: tuple[str, ...] = ()
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=now_utc)
    updated_at: str = field(default_factory=now_utc)
    last_confirmed_at: str | None = None
    expires_at: str | None = None
    redaction_status: str = "not_redacted"
    deleted: bool = False

    def to_row(self) -> dict[str, Any]:
        search_text = " ".join([self.id, self.content, self.summary, " ".join(self.tags), self.source, self.owner, self.scope]).lower()
        return {
            "id": self.id,
            "type": self.type.value,
            "content": self.content,
            "summary": self.summary,
            "source": self.source,
            "provenance": self.provenance,
            "confidence": self.confidence,
            "sensitivity": self.sensitivity.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_confirmed_at": self.last_confirmed_at,
            "expires_at": self.expires_at,
            "owner": self.owner,
            "scope": self.scope,
            "tags": list(self.tags),
            "search_text": search_text,
            "redaction_status": self.redaction_status,
            "deleted": self.deleted,
        }
