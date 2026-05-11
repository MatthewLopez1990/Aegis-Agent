"""Portable approval action hints for CLI, TUI, API, and chat adapters."""

from __future__ import annotations

from typing import Any


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
