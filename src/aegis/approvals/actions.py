"""Portable approval action hints for CLI, TUI, API, and chat adapters."""

from __future__ import annotations

import re
from typing import Any


_APPROVAL_INTENT_PHRASES: dict[str, str] = {
    "approve": "approval_approve",
    "yes approve": "approval_approve",
    "yes approve that plan": "approval_approve",
    "yes proceed": "approval_approve",
    "proceed": "approval_approve",
    "continue": "approval_approve",
    "deny": "approval_deny",
    "no": "approval_deny",
    "no do not do that": "approval_deny",
    "no don't do that": "approval_deny",
    "do not do that": "approval_deny",
    "don't do that": "approval_deny",
    "stop": "approval_deny",
    "cancel": "approval_deny",
    "revert": "approval_reject_or_revert_intent",
    "let's revert": "approval_reject_or_revert_intent",
    "lets revert": "approval_reject_or_revert_intent",
    "cancel that plan": "approval_reject_or_revert_intent",
    "reject and revert": "approval_reject_or_revert_intent",
    "show approval": "approval_review",
    "show risk": "approval_review",
    "show payload": "approval_review",
}


def approval_intent_from_text(text: Any) -> dict[str, Any] | None:
    """Parse short operator chat replies into non-executing approval intents."""

    phrase = _normalize_approval_phrase(text)
    if not phrase:
        return None
    action = _APPROVAL_INTENT_PHRASES.get(phrase)
    if action is None:
        return None
    return {
        "kind": "approval_intent",
        "action": action,
        "matched_phrase": phrase,
        "requires_explicit_approval_id": True,
        "auto_execute": False,
        "safety": "intent_only_no_state_change",
        "next_step": "Match this intent to a current approval action_hints entry before executing.",
    }


def approval_action_hints(approval: dict[str, Any], *, task_id: Any = None, session_id: Any = None, admin_required: bool = False) -> list[dict[str, Any]]:
    approval_id = str(approval.get("id") or "")
    status = str(approval.get("status") or "")
    task_id_text = str(task_id or approval.get("task_id") or "")
    session_id_text = str(session_id or "")
    admin_flag = " --admin" if admin_required else ""
    hints: list[dict[str, Any]] = []
    if approval_id:
        hints.append(
            {
                "label": "Review Approval",
                "command": f"approval {approval_id}",
                "action": "approval_review",
                "approval_id": approval_id,
                "utterances": ["show approval", "show risk", "show payload"],
            }
        )
    if approval_id and status == "pending":
        hints.extend(
            [
                {
                    "label": "Approve",
                    "command": f"approve {approval_id}{admin_flag}",
                    "action": "approval_approve",
                    "approval_id": approval_id,
                    "admin_required": admin_required,
                    "utterances": ["approve", "yes approve that plan", "yes proceed"],
                },
                {
                    "label": "Deny",
                    "command": f"deny {approval_id}{admin_flag}",
                    "action": "approval_deny",
                    "approval_id": approval_id,
                    "admin_required": admin_required,
                    "utterances": ["deny", "no do not do that", "stop"],
                },
                {
                    "label": "Reject And Revert Intent",
                    "command": f"deny {approval_id}{admin_flag}",
                    "action": "approval_reject_or_revert_intent",
                    "approval_id": approval_id,
                    "admin_required": admin_required,
                    "utterances": ["revert", "let's revert", "cancel that plan"],
                    "note": "For pending approvals this denies the proposed action before it runs.",
                },
            ]
        )
    if task_id_text and status == "approved":
        hints.append(
            {
                "label": "Resume",
                "command": f"task resume {task_id_text}",
                "action": "task_resume",
                "task_id": task_id_text,
                "utterances": ["proceed", "continue", "resume task"],
            }
        )
    if session_id_text:
        hints.extend(
            [
                {
                    "label": "Show Session",
                    "command": f"session show {session_id_text}",
                    "action": "session_show",
                    "session_id": session_id_text,
                    "utterances": ["show session", "open the session"],
                },
                {
                    "label": "Session History",
                    "command": f"session history {session_id_text}",
                    "action": "session_history",
                    "session_id": session_id_text,
                    "utterances": ["show history", "what happened before"],
                },
            ]
        )
    return hints


def _normalize_approval_phrase(text: Any) -> str:
    value = str(text or "").strip().lower()
    value = value.strip(" \t\r\n.!?")
    value = value.replace("\u2019", "'")
    value = re.sub(r"\s+", " ", value)
    return value
