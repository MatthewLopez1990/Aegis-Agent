"""Conversation sessions with persistent history and context compaction hooks."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import TrustClass, now_utc


class SessionManager:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def create_session(
        self,
        *,
        title: str,
        channel: str = "terminal",
        model: str | None = None,
        personality: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        row = {
            "id": str(uuid4()),
            "title": title,
            "channel": channel,
            "status": "active",
            "model": model,
            "personality": personality,
            "created_at": now_utc(),
            "updated_at": now_utc(),
            "metadata": metadata or {},
        }
        self.store.insert_session(row)
        self.audit_logger.append("session.created", row)
        return row

    def add_message(
        self,
        session_id: str,
        *,
        role: str,
        content: str,
        trust_class: TrustClass = TrustClass.USER_DIRECTIVE,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        row = {
            "id": str(uuid4()),
            "session_id": session_id,
            "role": role,
            "content": content,
            "trust_class": trust_class.value,
            "created_at": now_utc(),
            "metadata": metadata or {},
        }
        self.store.insert_message(row)
        self.audit_logger.append("session.message_added", {"session_id": session_id, "role": role, "trust_class": trust_class.value})
        return row

    def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        return [_decode_session(row) for row in self.store.list_sessions(limit=limit)]

    def history(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        return [_decode_message(row) for row in self.store.list_messages(session_id, limit=limit)]

    def compact_history(self, session_id: str, *, keep_last: int = 20) -> dict[str, Any]:
        messages = self.history(session_id, limit=1000)
        older = messages[:-keep_last] if len(messages) > keep_last else []
        summary = " ".join(message["content"] for message in older)
        if len(summary) > 1000:
            summary = summary[:997] + "..."
        result = {"session_id": session_id, "compacted_messages": len(older), "summary": summary}
        self.audit_logger.append("session.compacted", result)
        return result


def _decode_session(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["metadata"] = json.loads(decoded.pop("metadata_json", "{}"))
    return decoded


def _decode_message(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["metadata"] = json.loads(decoded.pop("metadata_json", "{}"))
    return decoded
