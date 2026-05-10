"""Governed memory CRUD, retrieval, conflict checks, and safety gates."""

from __future__ import annotations

import json
import re
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.memory.models import MemoryRecord, MemoryType
from aegis.memory.store import LocalStore
from aegis.security.taint import Sensitivity, now_utc


SECRET_LIKE = re.compile(
    r"(api[_ -]?key|secret|password|refresh[_ -]?token|ssh[-_ ]?private|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.I,
)


class MemorySafetyError(ValueError):
    pass


class MemoryManager:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def create_memory(
        self,
        *,
        memory_type: MemoryType,
        content: str,
        source: str,
        provenance: dict[str, Any],
        confidence: float,
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
        owner: str = "local-user",
        scope: str = "workspace",
        tags: tuple[str, ...] = (),
        confirmed: bool = False,
    ) -> MemoryRecord:
        if SECRET_LIKE.search(content):
            raise MemorySafetyError("refusing to store secret-like content as normal memory")
        if sensitivity in {Sensitivity.CONFIDENTIAL, Sensitivity.SECRET} and not confirmed:
            raise MemorySafetyError("sensitive memory requires explicit confirmation")
        if confidence < 0.5 and not confirmed:
            raise MemorySafetyError("uncertain memory requires confirmation before storage")
        summary = summarize(content)
        record = MemoryRecord(
            type=memory_type,
            content=content,
            summary=summary,
            source=source,
            provenance=provenance,
            confidence=max(0.0, min(confidence, 1.0)),
            sensitivity=sensitivity,
            owner=owner,
            scope=scope,
            tags=tags,
            last_confirmed_at=now_utc() if confirmed else None,
        )
        self.store.insert_memory(record.to_row())
        self.audit_logger.append(
            "memory.created",
            {
                "memory_id": record.id,
                "type": record.type.value,
                "source": record.source,
                "confidence": record.confidence,
                "sensitivity": record.sensitivity.value,
                "provenance": provenance,
            },
        )
        return record

    def retrieve_relevant(self, query: str, *, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.store.search_memories(query, limit=limit)
        self.audit_logger.append("memory.retrieved", {"query": query, "count": len(rows)})
        return [decode_memory_row(row) for row in rows]

    def update_memory(self, memory_id: str, *, content: str | None = None, confidence: float | None = None, confirmed: bool = False) -> dict[str, Any]:
        changes: dict[str, Any] = {}
        if content is not None:
            if SECRET_LIKE.search(content):
                raise MemorySafetyError("refusing to store secret-like content as normal memory")
            changes["content"] = content
            changes["summary"] = summarize(content)
            changes["search_text"] = content.lower()
        if confidence is not None:
            changes["confidence"] = max(0.0, min(confidence, 1.0))
        if confirmed:
            changes["last_confirmed_at"] = now_utc()
        updated = decode_memory_row(self.store.update_memory(memory_id, changes))
        self.audit_logger.append("memory.updated", {"memory_id": memory_id, "changes": sorted(changes)})
        return updated

    def delete_memory(self, memory_id: str) -> None:
        self.store.update_memory(memory_id, {"deleted": 1})
        self.audit_logger.append("memory.deleted", {"memory_id": memory_id})

    def expire_memory(self, memory_id: str) -> dict[str, Any]:
        expired = decode_memory_row(self.store.update_memory(memory_id, {"expires_at": now_utc(), "deleted": 1}))
        self.audit_logger.append("memory.expired", {"memory_id": memory_id})
        return expired

    def merge_duplicate(self, primary_id: str, duplicate_id: str) -> dict[str, Any]:
        primary = self.store.get_memory(primary_id)
        duplicate = self.store.get_memory(duplicate_id)
        if not primary or not duplicate:
            raise KeyError("primary or duplicate memory not found")
        primary_decoded = decode_memory_row(primary)
        duplicate_decoded = decode_memory_row(duplicate)
        merged_tags = sorted(set(primary_decoded["tags"]) | set(duplicate_decoded["tags"]))
        merged_content = primary_decoded["content"]
        if duplicate_decoded["content"] not in merged_content:
            merged_content = f"{merged_content}\n\nMerged duplicate note: {duplicate_decoded['content']}"
        updated = self.store.update_memory(
            primary_id,
            {
                "content": merged_content,
                "summary": summarize(merged_content),
                "tags_json": json.dumps(merged_tags),
                "search_text": " ".join([merged_content, " ".join(merged_tags)]).lower(),
                "confidence": max(primary_decoded["confidence"], duplicate_decoded["confidence"]),
            },
        )
        self.store.update_memory(duplicate_id, {"deleted": 1})
        self.audit_logger.append("memory.merged", {"primary_id": primary_id, "duplicate_id": duplicate_id})
        return decode_memory_row(updated)

    def export_memory(self, query: str = "") -> list[dict[str, Any]]:
        rows = self.store.search_memories(query or "%", limit=1000)
        self.audit_logger.append("memory.exported", {"query": query, "count": len(rows)})
        return [decode_memory_row(row) for row in rows]

    def explain_usage(self, memory_id: str, query: str) -> str:
        row = self.store.get_memory(memory_id)
        if not row:
            raise KeyError(memory_id)
        decoded = decode_memory_row(row)
        tags = ", ".join(decoded["tags"]) or "no tags"
        return (
            f"Memory {memory_id} was considered for query {query!r} because its "
            f"summary/source/tags matched retrieval text. Source={decoded['source']}; "
            f"confidence={decoded['confidence']}; tags={tags}."
        )

    def detect_conflicts(self, candidate_content: str, *, scope: str = "workspace") -> list[dict[str, Any]]:
        rows = self.store.search_memories(scope, limit=100)
        conflicts: list[dict[str, Any]] = []
        candidate_terms = set(candidate_content.lower().split())
        for row in rows:
            if row["scope"] != scope:
                continue
            existing_terms = set(str(row["content"]).lower().split())
            overlap = len(candidate_terms & existing_terms)
            if overlap >= 3 and candidate_content.strip().lower() != str(row["content"]).strip().lower():
                conflicts.append(decode_memory_row(row))
        return conflicts


def summarize(content: str, limit: int = 180) -> str:
    normalized = re.sub(r"\s+", " ", content).strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def decode_memory_row(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["provenance"] = json.loads(decoded.pop("provenance_json", "{}"))
    decoded["tags"] = json.loads(decoded.pop("tags_json", "[]"))
    decoded["deleted"] = bool(decoded["deleted"])
    return decoded
