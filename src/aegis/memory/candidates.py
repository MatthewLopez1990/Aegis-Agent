"""Validated memory candidate acceptance helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.memory.models import MemoryType
from aegis.security.taint import Sensitivity, now_utc


class MemoryCandidateError(ValueError):
    pass


@dataclass(frozen=True)
class MemoryCandidate:
    id: str
    type: MemoryType
    content: str
    source: str
    provenance: dict[str, Any]
    confidence: float
    sensitivity: Sensitivity
    owner: str
    scope: str
    tags: tuple[str, ...]
    import_action: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "MemoryCandidate":
        if payload.get("blocked"):
            raise MemoryCandidateError("blocked memory candidates cannot be committed")
        import_action = str(payload.get("import_action", ""))
        if import_action not in {"review_required", "session_review_required"}:
            raise MemoryCandidateError("memory candidate must require review before commit")
        content = str(payload.get("content", "")).strip()
        if not content or content == "[BLOCKED_SECRET_LIKE_CONTENT]":
            raise MemoryCandidateError("memory candidate content is empty or blocked")
        provenance = payload.get("provenance", {})
        if not isinstance(provenance, dict):
            raise MemoryCandidateError("memory candidate provenance must be an object")
        tags = payload.get("tags", [])
        if not isinstance(tags, list):
            raise MemoryCandidateError("memory candidate tags must be a list")
        return cls(
            id=str(payload.get("id", "")),
            type=MemoryType(str(payload.get("type"))),
            content=content,
            source=str(payload.get("source", "")),
            provenance=dict(provenance),
            confidence=max(0.0, min(float(payload.get("confidence", 0.5)), 1.0)),
            sensitivity=Sensitivity(str(payload.get("sensitivity", Sensitivity.INTERNAL.value))),
            owner=str(payload.get("owner", "local-user")),
            scope=str(payload.get("scope", "workspace")),
            tags=tuple(str(tag) for tag in tags),
            import_action=import_action,
        )


def candidate_to_create_kwargs(candidate: MemoryCandidate, *, confirmed: bool, reviewer: str = "local-user") -> dict[str, Any]:
    return {
        "memory_type": candidate.type,
        "content": candidate.content,
        "source": candidate.source,
        "provenance": {
            **candidate.provenance,
            "dry_run": False,
            "committed_from_preview": True,
            "candidate_id": candidate.id,
            "reviewer": reviewer,
            "accepted_at": now_utc(),
        },
        "confidence": candidate.confidence,
        "sensitivity": candidate.sensitivity,
        "owner": candidate.owner,
        "scope": candidate.scope,
        "tags": candidate.tags,
        "confirmed": confirmed,
    }
