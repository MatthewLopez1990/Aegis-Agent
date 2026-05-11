"""Evidence bundles for completed and blocked tasks."""

from __future__ import annotations

import json
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.memory.manager import decode_memory_row
from aegis.memory.store import LocalStore


class EvidenceBundleBuilder:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def build(self, task_id: str) -> dict[str, Any]:
        task = self.store.get_task(task_id)
        if not task:
            raise KeyError(task_id)
        audit_tail = self.audit_logger.for_task(task_id)
        session = _session_snapshot(self.store, task)
        repair_evidence = _repair_evidence(self.store, task_id)
        return {
            "task": {
                "id": task["id"],
                "status": task["status"],
                "interpretation": task["interpretation"],
                "session_id": task.get("session_id"),
                "session": session,
                "action_hints": _task_action_hints(task["id"], task.get("session_id"), status=task["status"]),
                "plan": json.loads(task["plan_json"]),
                "checkpoint": json.loads(task["checkpoint_json"]),
                "receipt": json.loads(task["receipt_json"]) if task["receipt_json"] else None,
            },
            "audit_tail": audit_tail,
            "improvement_proposals": repair_evidence["improvement_proposals"],
            "repair_candidates": repair_evidence["repair_candidates"],
            "repair_attempts": repair_evidence["repair_attempts"],
            "verification_receipts": repair_evidence["verification_receipts"],
            "learned_memories": repair_evidence["learned_memories"],
            "missing_evidence": repair_evidence["missing_evidence"],
        }

    def timeline(self, task_id: str) -> dict[str, Any]:
        bundle = self.build(task_id)
        task = bundle["task"]
        items: list[dict[str, Any]] = []
        for index, step in enumerate(task["plan"], start=1):
            items.append(
                {
                    "kind": "plan_step",
                    "title": step.get("description", f"Step {index}"),
                    "status": "planned",
                    "sequence": index,
                    "connector": step.get("connector") or "none",
                    "operation": step.get("operation"),
                    "risk_level": step.get("risk_level"),
                    "details": step,
                }
            )
        receipt = task.get("receipt")
        if isinstance(receipt, dict):
            items.append(
                {
                    "kind": "receipt",
                    "title": receipt.get("plan_step", "Receipt"),
                    "status": receipt.get("result", "unknown"),
                    "timestamp": receipt.get("timestamp"),
                    "connector": receipt.get("tool_or_connector"),
                    "operation": receipt.get("approval_status"),
                    "risk_level": receipt.get("risk_classification"),
                    "details": {
                        "affected": receipt.get("files_or_records_affected", []),
                        "error": receipt.get("error_details"),
                        "rollback": receipt.get("rollback"),
                    },
                }
            )
        for entry in bundle["audit_tail"]:
            items.append(
                {
                    "kind": "audit",
                    "title": entry.get("event_type", "audit event"),
                    "status": "recorded",
                    "timestamp": entry.get("timestamp"),
                    "details": entry.get("payload", {}),
                    "hash": entry.get("event_hash"),
                }
            )
        for proposal in bundle.get("improvement_proposals", []):
            items.append(
                {
                    "kind": "repair_proposal",
                    "title": proposal.get("summary", "Repair proposal"),
                    "status": proposal.get("status", "unknown"),
                    "timestamp": proposal.get("created_at"),
                    "operation": proposal.get("kind"),
                    "details": proposal,
                }
            )
        for candidate in bundle.get("repair_candidates", []):
            items.append(
                {
                    "kind": "repair_candidate",
                    "title": candidate.get("summary", "Repair candidate"),
                    "status": candidate.get("status", "unknown"),
                    "timestamp": candidate.get("created_at"),
                    "operation": "repair_candidate",
                    "details": candidate,
                }
            )
        for attempt in bundle.get("repair_attempts", []):
            items.append(
                {
                    "kind": "repair_attempt",
                    "title": attempt.get("outcome", "Repair attempt"),
                    "status": attempt.get("status", "unknown"),
                    "timestamp": attempt.get("created_at"),
                    "operation": "repair_attempt",
                    "details": attempt,
                }
            )
        for receipt in bundle.get("verification_receipts", []):
            items.append(
                {
                    "kind": "verification",
                    "title": receipt.get("verification_receipt", "Verification receipt"),
                    "status": receipt.get("test_result", "unknown"),
                    "timestamp": receipt.get("created_at"),
                    "operation": "verification",
                    "details": receipt,
                }
            )
        for memory in bundle.get("learned_memories", []):
            items.append(
                {
                    "kind": "memory",
                    "title": memory.get("summary") or memory.get("id", "Learned memory"),
                    "status": "recorded",
                    "timestamp": memory.get("created_at"),
                    "operation": "procedural_memory",
                    "details": memory,
                }
            )
        return {
            "task_id": task_id,
            "status": task["status"],
            "session_id": task.get("session_id"),
            "session": task.get("session"),
            "action_hints": task.get("action_hints", []),
            "items": sorted(items, key=_timeline_sort_key),
        }

    def run_events(self, task_id: str) -> dict[str, Any]:
        timeline = self.timeline(task_id)
        events: list[dict[str, Any]] = []
        for index, item in enumerate(timeline["items"], start=1):
            details = item.get("details", {}) if isinstance(item.get("details"), dict) else {}
            kind = str(item.get("kind") or "event")
            title = str(item.get("title") or kind)
            event_type = str(details.get("event_type") or title)
            if kind == "audit":
                event_type = title
            events.append(
                {
                    "sequence": index,
                    "kind": _run_event_kind(kind, event_type),
                    "title": title,
                    "status": str(item.get("status") or "recorded"),
                    "timestamp": item.get("timestamp"),
                    "tool": item.get("connector") or details.get("connector") or details.get("tool") or details.get("tool_or_connector") or "runtime",
                    "operation": item.get("operation") or details.get("operation") or details.get("approval_status") or "",
                    "summary": _run_event_summary(kind, event_type, details),
                    "details": details,
                    "hash": item.get("hash"),
                }
            )
        step_groups = _run_event_step_groups(timeline["items"], events)
        provider_substeps = _run_event_provider_substeps(events)
        progress = _run_event_progress(timeline["status"], events, step_groups, provider_substeps)
        return {
            "task_id": task_id,
            "status": timeline["status"],
            "session_id": timeline.get("session_id"),
            "session": timeline.get("session"),
            "action_hints": timeline.get("action_hints", []),
            "progress": progress,
            "provider_substeps": provider_substeps,
            "step_groups": step_groups,
            "events": events,
        }


def _timeline_sort_key(item: dict[str, Any]) -> tuple[str, int]:
    timestamp = str(item.get("timestamp") or "")
    sequence = int(item.get("sequence") or 0)
    return (timestamp, sequence)


def _task_action_hints(task_id: Any, session_id: Any, *, status: Any) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    task_id_text = str(task_id) if task_id else ""
    if session_id:
        session_id_text = str(session_id)
        hints.extend(
            [
                {"label": "Show Session", "command": f"session show {session_id_text}", "action": "session_show", "session_id": session_id_text},
                {"label": "Session History", "command": f"session history {session_id_text}", "action": "session_history", "session_id": session_id_text},
            ]
        )
    if task_id_text and status in {"waiting_approval", "paused"}:
        hints.append({"label": "Resume", "command": f"task resume {task_id_text}", "action": "task_resume", "task_id": task_id_text})
    return hints


def _run_event_kind(kind: str, event_type: str) -> str:
    if kind == "plan_step":
        return "plan"
    if kind == "receipt":
        return "receipt"
    if event_type.startswith("approval."):
        return "approval"
    if event_type in {"connector.called", "tool.executed"}:
        return "tool"
    if event_type.startswith("model."):
        return "model"
    if event_type.startswith("task."):
        return "task"
    if kind in {"repair_proposal", "repair_candidate", "repair_attempt"} or event_type.startswith("improvement."):
        return "repair"
    if kind == "verification":
        return "verification"
    if kind == "memory" or event_type.startswith("memory."):
        return "memory"
    return "audit"


def _run_event_summary(kind: str, event_type: str, details: dict[str, Any]) -> str:
    if kind == "plan_step":
        connector = details.get("connector") or "runtime"
        operation = details.get("operation") or "record"
        return f"Planned {operation} on {connector}."
    if kind == "receipt":
        error = details.get("error")
        return f"Receipt recorded{f': {error}' if error else '.'}"
    if event_type == "connector.called":
        connector = details.get("connector") or "connector"
        operation = details.get("operation") or "operation"
        ok = "succeeded" if details.get("ok") else "failed"
        return f"{connector} {operation} {ok}."
    if event_type == "tool.executed":
        return f"Tool {details.get('tool', 'unknown')} executed."
    if event_type.startswith("approval."):
        return f"Approval event: {event_type.removeprefix('approval.')}."
    if event_type.startswith("model."):
        return f"Model event: {event_type.removeprefix('model.')}."
    if event_type == "task.resume_requested":
        context = _session_event_label(details, "resolved") or details.get("resolved_context_ref") or "no session"
        return f"Resume requested in {context}."
    if event_type == "task.resume_result":
        status = details.get("status") or "unknown"
        context = _session_event_label(details, "resolved") or details.get("resolved_context_ref") or "no session"
        approval = details.get("approval_status")
        suffix = f" after {approval} approval" if approval else ""
        return f"Resume {status} in {context}{suffix}."
    if event_type == "task.resume_rejected":
        requested = _session_event_label(details, "requested") or details.get("requested_context_ref") or "unknown context"
        task_context = _session_event_label(details, "task") or details.get("task_context_ref") or "task context"
        return f"Resume rejected: {requested} does not match {task_context}."
    if event_type.startswith("task."):
        return f"Task event: {event_type.removeprefix('task.')}."
    if kind == "repair_proposal":
        return f"Repair proposal is {details.get('status', 'unknown')}."
    if kind == "repair_candidate":
        return f"Repair candidate is {details.get('status', 'unknown')}."
    if kind == "repair_attempt":
        return f"Repair attempt recorded with status {details.get('status', 'unknown')}."
    if kind == "verification":
        return f"Repair verification result: {details.get('test_result', 'unknown')}."
    if kind == "memory":
        return "Procedural repair memory recorded."
    return event_type


def _run_event_step_groups(timeline_items: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    by_step_id: dict[str, dict[str, Any]] = {}
    by_title: dict[str, dict[str, Any]] = {}
    by_index: dict[int, dict[str, Any]] = {}
    for item in timeline_items:
        if item.get("kind") != "plan_step":
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        step_id = str(details.get("id") or item.get("sequence") or len(groups) + 1)
        group = {
            "sequence": len(groups) + 1,
            "step_id": step_id,
            "title": item.get("title") or f"Step {len(groups) + 1}",
            "connector": item.get("connector") or details.get("connector") or "runtime",
            "operation": item.get("operation") or details.get("operation") or "",
            "risk_level": item.get("risk_level") or details.get("risk_level"),
            "status": "planned",
            "event_count": 0,
            "events": [],
        }
        groups.append(group)
        by_step_id[step_id] = group
        by_title[str(group["title"])] = group
        by_index[int(item.get("sequence") or len(groups))] = group
    ungrouped: list[dict[str, Any]] = []
    for event in events:
        group = _match_step_group(event, by_step_id=by_step_id, by_title=by_title, by_index=by_index)
        if group is None:
            ungrouped.append(event)
            continue
        group["events"].append(event)
        group["event_count"] = int(group["event_count"]) + 1
    for group in groups:
        group["status"] = _group_status(group["events"])
        group["latest_event"] = group["events"][-1]["title"] if group["events"] else None
    if ungrouped:
        groups.append(
            {
                "sequence": len(groups) + 1,
                "step_id": "runtime",
                "title": "Runtime events",
                "connector": "runtime",
                "operation": "audit",
                "risk_level": None,
                "status": _group_status(ungrouped),
                "event_count": len(ungrouped),
                "latest_event": ungrouped[-1]["title"],
                "events": ungrouped,
            }
        )
    return groups


def _run_event_provider_substeps(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    substeps: list[dict[str, Any]] = []
    for event in events:
        kind = str(event.get("kind") or "")
        if kind not in {"tool", "model"}:
            continue
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        result = details.get("result") if isinstance(details.get("result"), dict) else {}
        identifier = details.get("identifier") or details.get("tool") or event.get("tool") or "runtime"
        provider = details.get("provider") or result.get("provider") or result.get("source") or event.get("tool") or kind
        result_status = result.get("status") or result.get("ok")
        status = str(result_status if result_status is not None else event.get("status") or "recorded")
        substeps.append(
            {
                "sequence": event.get("sequence"),
                "kind": kind,
                "provider": _safe_run_value(provider),
                "identifier": _safe_run_value(identifier),
                "operation": _safe_run_value(event.get("operation") or details.get("operation") or ""),
                "status": _safe_run_value(status),
                "summary": _safe_run_value(event.get("summary") or ""),
            }
        )
    return substeps


def _run_event_progress(
    status: str,
    events: list[dict[str, Any]],
    step_groups: list[dict[str, Any]],
    provider_substeps: list[dict[str, Any]],
) -> dict[str, Any]:
    total_steps = len([group for group in step_groups if group.get("step_id") != "runtime"])
    completed_steps = len([group for group in step_groups if group.get("step_id") != "runtime" and group.get("status") == "completed"])
    waiting_steps = len([group for group in step_groups if group.get("step_id") != "runtime" and group.get("status") == "waiting"])
    failed_steps = len([group for group in step_groups if group.get("step_id") != "runtime" and group.get("status") == "failed"])
    events_by_kind: dict[str, int] = {}
    events_by_status: dict[str, int] = {}
    substeps_by_kind: dict[str, int] = {}
    substeps_by_status: dict[str, int] = {}
    for event in events:
        kind = str(event.get("kind") or "event")
        event_status = str(event.get("status") or "unknown")
        events_by_kind[kind] = events_by_kind.get(kind, 0) + 1
        events_by_status[event_status] = events_by_status.get(event_status, 0) + 1
    for substep in provider_substeps:
        substep_kind = str(substep.get("kind") or "substep")
        substep_status = str(substep.get("status") or "unknown")
        substeps_by_kind[substep_kind] = substeps_by_kind.get(substep_kind, 0) + 1
        substeps_by_status[substep_status] = substeps_by_status.get(substep_status, 0) + 1
    return {
        "status": status,
        "total_steps": total_steps,
        "completed_steps": completed_steps,
        "waiting_steps": waiting_steps,
        "failed_steps": failed_steps,
        "step_completion_ratio": round(completed_steps / total_steps, 3) if total_steps else 0.0,
        "total_events": len(events),
        "events_by_kind": dict(sorted(events_by_kind.items())),
        "events_by_status": dict(sorted(events_by_status.items())),
        "provider_substeps": len(provider_substeps),
        "provider_substeps_by_kind": dict(sorted(substeps_by_kind.items())),
        "provider_substeps_by_status": dict(sorted(substeps_by_status.items())),
        "latest_sequence": max((int(event.get("sequence", 0) or 0) for event in events), default=0),
    }


def _session_event_label(details: dict[str, Any], prefix: str) -> str | None:
    context_ref = details.get(f"{prefix}_context_ref") or details.get(f"{prefix}_session_short_id")
    title = details.get(f"{prefix}_context_title")
    channel = details.get(f"{prefix}_context_channel")
    if not title and not channel:
        return None
    bits = [str(context_ref)] if context_ref else []
    if title:
        bits.append(str(title))
    if channel:
        bits.append(str(channel))
    return " / ".join(bits)


def _safe_run_value(value: Any) -> str:
    text = str(value if value is not None else "")
    text = " ".join(text.split())
    return text[:160]


def _match_step_group(
    event: dict[str, Any],
    *,
    by_step_id: dict[str, dict[str, Any]],
    by_title: dict[str, dict[str, Any]],
    by_index: dict[int, dict[str, Any]],
) -> dict[str, Any] | None:
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    step = details.get("step") if isinstance(details.get("step"), dict) else {}
    step_id = details.get("step_id") or step.get("id")
    if step_id is not None and str(step_id) in by_step_id:
        return by_step_id[str(step_id)]
    title = str(event.get("title") or "")
    if title in by_title:
        return by_title[title]
    checkpoint = details.get("checkpoint") if isinstance(details.get("checkpoint"), dict) else {}
    next_step_index = checkpoint.get("next_step_index")
    if next_step_index is not None:
        try:
            return by_index.get(int(next_step_index) + 1)
        except (TypeError, ValueError):
            return None
    return None


def _group_status(events: list[dict[str, Any]]) -> str:
    if not events:
        return "planned"
    statuses = {str(event.get("status") or "").lower() for event in events}
    titles = {str(event.get("title") or "").lower() for event in events}
    if statuses & {"failed", "blocked"}:
        return "failed"
    if any("waiting" in status or "approval" in title for status in statuses for title in titles):
        return "waiting"
    if statuses & {"completed", "recorded"}:
        return "completed"
    return str(events[-1].get("status") or "recorded")


def _session_snapshot(store: LocalStore, task: dict[str, Any]) -> dict[str, Any] | None:
    session_id = task.get("session_id")
    if not session_id:
        return None
    row = store.get_session(str(session_id))
    if not row:
        return {"id": session_id, "missing": True}
    decoded = dict(row)
    decoded["metadata"] = json.loads(decoded.pop("metadata_json", "{}"))
    decoded["message_count"] = len(store.list_messages(str(session_id), limit=1000))
    decoded["task_count"] = len(store.list_tasks(limit=1000, session_id=str(session_id)))
    return decoded


def _repair_evidence(store: LocalStore, task_id: str) -> dict[str, Any]:
    proposals = [_decode_improvement_proposal(row) for row in store.list_improvement_proposals(task_id=task_id, limit=1000)]
    repair_candidates: list[dict[str, Any]] = []
    repair_attempts: list[dict[str, Any]] = []
    verification_receipts: list[dict[str, Any]] = []
    learned_memories: list[dict[str, Any]] = []
    missing_evidence: list[dict[str, Any]] = []

    for proposal in proposals:
        metadata = proposal.get("metadata", {})
        candidates = list(metadata.get("repair_candidates", []))
        attempts = list(metadata.get("repair_attempts", []))
        if proposal.get("status") == "approved" and not attempts:
            missing_evidence.append({"proposal_id": proposal["id"], "kind": "repair_attempt", "reason": "approved proposal has no repair attempt"})
        for index, candidate in enumerate(candidates, start=1):
            repair_candidates.append(
                {
                    **candidate,
                    "proposal_id": proposal["id"],
                    "task_id": task_id,
                    "candidate_index": index,
                }
            )
        learned_memory_id = metadata.get("learned_memory_id")
        if learned_memory_id:
            memory = store.get_memory(str(learned_memory_id))
            if memory:
                learned_memories.append(decode_memory_row(memory))
            else:
                missing_evidence.append({"proposal_id": proposal["id"], "kind": "learned_memory", "reason": "learned memory id is missing", "memory_id": learned_memory_id})
        for index, attempt in enumerate(attempts, start=1):
            normalized_attempt = {
                **attempt,
                "proposal_id": proposal["id"],
                "task_id": task_id,
                "attempt_index": index,
            }
            repair_attempts.append(normalized_attempt)
            verification = attempt.get("verification") if isinstance(attempt.get("verification"), dict) else {}
            receipt_id = verification.get("verification_receipt")
            if receipt_id:
                verification_receipts.append(
                    {
                        "proposal_id": proposal["id"],
                        "task_id": task_id,
                        "attempt_index": index,
                        "created_at": attempt.get("created_at"),
                        **verification,
                    }
                )
            if attempt.get("status") == "implemented" and not learned_memory_id:
                missing_evidence.append({"proposal_id": proposal["id"], "kind": "learned_memory", "reason": "implemented repair has no learned memory"})

    return {
        "improvement_proposals": proposals,
        "repair_candidates": repair_candidates,
        "repair_attempts": repair_attempts,
        "verification_receipts": verification_receipts,
        "learned_memories": learned_memories,
        "missing_evidence": missing_evidence,
    }


def _decode_improvement_proposal(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    evidence_json = decoded.pop("evidence_json", None)
    metadata_json = decoded.pop("metadata_json", None)
    if evidence_json is not None:
        decoded["evidence"] = json.loads(evidence_json)
    if metadata_json is not None:
        decoded["metadata"] = json.loads(metadata_json)
    decoded["approval_required"] = bool(decoded.get("approval_required", True))
    return decoded
