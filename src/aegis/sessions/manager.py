"""Conversation sessions with persistent history and context compaction hooks."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import TrustClass, now_utc

TRUSTED_DIRECTIVE_CHANNELS = {"terminal", "web", "api"}
SESSION_MESSAGE_ROLES = {"user", "assistant"}


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
        trust_class: TrustClass | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if role not in SESSION_MESSAGE_ROLES:
            raise ValueError("session message role must be user or assistant")
        resolved_trust = trust_class or self._default_trust_class(session_id, role=role)
        row = {
            "id": str(uuid4()),
            "session_id": session_id,
            "role": role,
            "content": content,
            "trust_class": resolved_trust.value,
            "created_at": now_utc(),
            "metadata": metadata or {},
        }
        self.store.insert_message(row)
        self.audit_logger.append("session.message_added", {"session_id": session_id, "role": role, "trust_class": resolved_trust.value})
        return row

    def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        return [self._with_session_activity(_decode_session(row)) for row in self.store.list_sessions(limit=limit)]

    def get_session(self, session_id: str) -> dict[str, Any]:
        row = self.store.get_session(session_id)
        if not row:
            raise KeyError(session_id)
        return self._with_session_activity(_decode_session(row))

    def update_session(
        self,
        session_id: str,
        *,
        title: str | None = None,
        model: str | None = None,
        personality: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        changes: dict[str, Any] = {}
        if title is not None:
            changes["title"] = title
        if model is not None:
            changes["model"] = model
        if personality is not None:
            changes["personality"] = personality
        if status is not None:
            if status not in {"active", "archived", "paused"}:
                raise ValueError("session status must be active, archived, or paused")
            changes["status"] = status
        if not changes:
            return self.get_session(session_id)
        updated = _decode_session(self.store.update_session(session_id, changes))
        self.audit_logger.append("session.updated", {"session_id": session_id, "changes": sorted(changes)})
        return updated

    def history(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        return [self._decode_message(row) for row in self.store.list_messages(session_id, limit=limit)]

    def compact_history(self, session_id: str, *, keep_last: int = 20) -> dict[str, Any]:
        if keep_last < 0:
            raise ValueError("keep_last must be non-negative")
        messages = self.history(session_id, limit=1000)
        if keep_last == 0:
            older = messages
        else:
            older = messages[:-keep_last] if len(messages) > keep_last else []
        summary = " ".join(message["content"] for message in older)
        if len(summary) > 1000:
            summary = summary[:997] + "..."
        summary_message_id = None
        if older and summary:
            summary_message = self.add_message(
                session_id,
                role="assistant",
                content=f"Session summary of {len(older)} older messages: {summary}",
                metadata={"kind": "session_compaction", "keep_last": keep_last, "compacted_messages": len(older)},
            )
            summary_message_id = summary_message["id"]
        result = {"session_id": session_id, "compacted_messages": len(older), "summary": summary, "summary_message_id": summary_message_id, "keep_last": keep_last}
        self.audit_logger.append("session.compacted", result)
        return result

    def _default_trust_class(self, session_id: str, *, role: str) -> TrustClass:
        if role == "assistant":
            return TrustClass.DEVELOPER_TRUSTED
        session = self.store.get_session(session_id)
        channel = str(session.get("channel", "")) if session else ""
        if channel in TRUSTED_DIRECTIVE_CHANNELS:
            return TrustClass.USER_DIRECTIVE
        return TrustClass.UNKNOWN_UNTRUSTED

    def _with_session_activity(self, session: dict[str, Any]) -> dict[str, Any]:
        session_id = str(session["id"])
        messages = self.store.list_messages(session_id, limit=1000)
        tasks = self.store.list_tasks(limit=1000, session_id=session_id)
        latest_task = tasks[0] if tasks else None
        return {
            **session,
            "message_count": len(messages),
            "task_count": len(tasks),
            "waiting_task_count": sum(1 for task in tasks if task.get("status") == "waiting_approval"),
            "latest_task": _session_task_summary(latest_task) if latest_task else None,
        }

    def _decode_message(self, row: dict[str, Any]) -> dict[str, Any]:
        decoded = dict(row)
        decoded["metadata"] = json.loads(decoded.pop("metadata_json", "{}"))
        state = self._message_state(decoded["metadata"])
        decoded.update(state)
        decoded["action_hints"] = self._message_action_hints(decoded["metadata"], state=state)
        return decoded

    def _message_state(self, metadata: dict[str, Any]) -> dict[str, str]:
        state: dict[str, str] = {}
        task_id = metadata.get("task_id")
        if isinstance(task_id, str) and task_id:
            task_row = self.store.get_task(task_id)
            if task_row and task_row.get("status"):
                state["current_task_status"] = str(task_row["status"])
        approval_id = metadata.get("checkpoint_approval_id")
        if isinstance(approval_id, str) and approval_id:
            approval = self.store.get_approval(approval_id)
            if approval and approval.get("status"):
                state["current_approval_status"] = str(approval["status"])
        return state

    def _message_action_hints(self, metadata: dict[str, Any], *, state: dict[str, str]) -> list[dict[str, str]]:
        hints: list[dict[str, str]] = []
        task_id = metadata.get("task_id")
        task_status = state.get("current_task_status") or str(metadata.get("status") or "")
        if isinstance(task_id, str) and task_id:
            short_task_id = task_id[:8]
            hints.extend(
                [
                    {"label": "Status", "command": f"status {short_task_id}", "action": "task_status", "task_id": task_id},
                    {"label": "Events", "command": f"events {short_task_id}", "action": "task_events", "task_id": task_id},
                    {"label": "Timeline", "command": f"timeline {short_task_id}", "action": "task_timeline", "task_id": task_id},
                ]
            )
            if task_status in {"waiting_approval", "paused"}:
                hints.append({"label": "Resume", "command": f"resume {short_task_id}", "action": "task_resume", "task_id": task_id})
        approval_id = metadata.get("checkpoint_approval_id")
        if isinstance(approval_id, str) and approval_id:
            short_approval_id = approval_id[:8]
            hints.append({"label": "Approval", "command": f"approval {short_approval_id}", "action": "approval_review", "approval_id": approval_id})
            if state.get("current_approval_status") == "pending":
                hints.extend(
                    [
                        {"label": "Approve", "command": f"approve {short_approval_id}", "action": "approval_approve", "approval_id": approval_id},
                        {"label": "Deny", "command": f"deny {short_approval_id}", "action": "approval_deny", "approval_id": approval_id},
                    ]
                )
        return hints


def _decode_session(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["metadata"] = json.loads(decoded.pop("metadata_json", "{}"))
    return decoded


def _session_task_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "status": row["status"],
        "risk_level": row["risk_level"],
        "updated_at": row["updated_at"],
    }
