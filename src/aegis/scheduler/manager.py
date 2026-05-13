"""Cron-like scheduled automation with approval-aware execution."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import now_utc


class ScheduleManager:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def create_schedule(
        self,
        *,
        name: str,
        natural_language: str,
        cron: str,
        task_request: str,
        channel: str = "terminal",
        metadata: dict[str, Any] | None = None,
        context_from: list[str] | tuple[str, ...] = (),
        delivery_targets: list[str] | tuple[str, ...] = (),
    ) -> dict[str, Any]:
        normalized_metadata = _schedule_metadata(
            metadata or {},
            context_from=context_from,
            delivery_targets=delivery_targets,
        )
        row = {
            "id": str(uuid4()),
            "name": name,
            "natural_language": natural_language,
            "cron": cron,
            "task_request": task_request,
            "channel": channel,
            "status": "paused_pending_approval",
            "next_run_at": estimate_next_run(cron),
            "last_run_at": None,
            "created_at": now_utc(),
            "updated_at": now_utc(),
            "metadata": normalized_metadata,
        }
        self.store.insert_schedule(row)
        self.audit_logger.append("schedule.created", row)
        return row

    def create_memory_review_digest_schedule(
        self,
        *,
        name: str,
        cron: str,
        channel: str = "terminal",
        limit: int = 10,
        scope: str = "workspace",
    ) -> dict[str, Any]:
        return self.create_schedule(
            name=name,
            natural_language=f"Deliver a governed memory review digest for {scope}",
            cron=cron,
            task_request="Deliver memory review digest",
            channel=channel,
            metadata={"kind": "memory_review_digest", "limit": max(1, int(limit)), "scope": scope},
        )

    def create_memory_review_escalation_schedule(
        self,
        *,
        name: str,
        cron: str,
        channel: str = "terminal",
        max_age_days: int = 7,
        limit: int = 10,
        scope: str = "workspace",
        route: str = "operator",
    ) -> dict[str, Any]:
        return self.create_schedule(
            name=name,
            natural_language=f"Escalate overdue governed memory review items for {scope}",
            cron=cron,
            task_request="Escalate overdue memory review items",
            channel=channel,
            metadata={
                "kind": "memory_review_escalation",
                "max_age_days": max(1, int(max_age_days)),
                "limit": max(1, int(limit)),
                "scope": scope,
                "route": route,
            },
        )

    def create_evaluation_run_schedule(
        self,
        *,
        name: str,
        cron: str,
        scenario: str,
        steps: list[str] | tuple[str, ...],
        channel: str = "terminal",
        reviewer: str = "scheduler",
    ) -> dict[str, Any]:
        normalized_steps = [str(step) for step in steps if str(step).strip()]
        if not normalized_steps:
            normalized_steps = ["run governed evaluation"]
        return self.create_schedule(
            name=name,
            natural_language=f"Run local governed evaluation for {scenario}",
            cron=cron,
            task_request=f"Run evaluation scenario: {scenario}",
            channel=channel,
            metadata={
                "kind": "evaluation_run",
                "scenario": str(scenario),
                "steps": normalized_steps,
                "reviewer": str(reviewer),
            },
        )

    def create_evaluation_suite_schedule(
        self,
        *,
        name: str,
        cron: str,
        suite: str = "security",
        scenario_ids: list[str] | tuple[str, ...] = (),
        channel: str = "terminal",
        reviewer: str = "scheduler",
    ) -> dict[str, Any]:
        normalized_scenario_ids = [str(scenario_id) for scenario_id in scenario_ids if str(scenario_id).strip()]
        return self.create_schedule(
            name=name,
            natural_language=f"Run local governed evaluation suite {suite}",
            cron=cron,
            task_request=f"Run evaluation suite: {suite}",
            channel=channel,
            metadata={
                "kind": "evaluation_suite",
                "suite": str(suite),
                "scenario_ids": normalized_scenario_ids,
                "reviewer": str(reviewer),
            },
        )

    def create_no_agent_hook_schedule(
        self,
        *,
        name: str,
        cron: str,
        hook_id: str,
        channel: str = "terminal",
        context_from: list[str] | tuple[str, ...] = (),
        delivery_targets: list[str] | tuple[str, ...] = (),
    ) -> dict[str, Any]:
        return self.create_schedule(
            name=name,
            natural_language=f"Run governed no-agent hook {hook_id}",
            cron=cron,
            task_request=f"Run no-agent hook {hook_id}",
            channel=channel,
            metadata={
                "kind": "no_agent_hook",
                "hook_id": str(hook_id),
                "action": "argv_hook",
                "raw_command_included": False,
            },
            context_from=context_from,
            delivery_targets=delivery_targets,
        )

    def list_schedules(self) -> list[dict[str, Any]]:
        return [_decode(row) for row in self.store.list_schedules()]

    def get(self, schedule_id: str) -> dict[str, Any]:
        for row in self.list_schedules():
            if row["id"] == schedule_id:
                return row
        raise KeyError(schedule_id)

    def activate(self, schedule_id: str) -> dict[str, Any]:
        current = self.get(schedule_id)
        if not current.get("metadata", {}).get("approved"):
            self.audit_logger.append("schedule.activation_blocked", {"schedule_id": schedule_id, "reason": "approval required"})
            raise PermissionError("schedule must be approved before activation")
        self.store.update_schedule(schedule_id, {"status": "active"})
        row = self.get(schedule_id)
        self.audit_logger.append("schedule.activated", {"schedule_id": schedule_id})
        return row

    def approve(self, schedule_id: str, *, approved_by: str = "local-user") -> dict[str, Any]:
        row = self.get(schedule_id)
        metadata = dict(row.get("metadata", {}))
        metadata.update({"approved": True, "approved_by": approved_by, "approved_at": now_utc()})
        self.store.update_schedule(schedule_id, {"status": "paused_approved", "metadata_json": json.dumps(metadata)})
        updated = self.get(schedule_id)
        self.audit_logger.append("schedule.approved", {"schedule_id": schedule_id, "approved_by": approved_by})
        return updated

    def pause(self, schedule_id: str) -> dict[str, Any]:
        self.store.update_schedule(schedule_id, {"status": "paused"})
        row = self.get(schedule_id)
        self.audit_logger.append("schedule.paused", {"schedule_id": schedule_id})
        return row

    def mark_ran(self, schedule_id: str, *, task_id: str | None = None, metadata_updates: dict[str, Any] | None = None) -> dict[str, Any]:
        row = self.get(schedule_id)
        metadata = dict(row.get("metadata", {}))
        if task_id:
            metadata["last_task_id"] = task_id
        if metadata_updates:
            metadata.update(metadata_updates)
        self.store.update_schedule(
            schedule_id,
            {
                "status": "active",
                "last_run_at": now_utc(),
                "next_run_at": estimate_next_run(row["cron"]),
                "metadata_json": json.dumps(metadata),
            },
        )
        updated = self.get(schedule_id)
        self.audit_logger.append("schedule.ran", {"schedule_id": schedule_id, "task_id": task_id})
        return updated

    def mark_failed(self, schedule_id: str, *, error: str) -> dict[str, Any]:
        row = self.get(schedule_id)
        metadata = dict(row.get("metadata", {}))
        failures = list(metadata.get("failures", []))
        failures.append({"error": error, "created_at": now_utc()})
        metadata["failures"] = failures[-5:]
        self.store.update_schedule(schedule_id, {"status": "active", "metadata_json": json.dumps(metadata)})
        updated = self.get(schedule_id)
        self.audit_logger.append("schedule.failed", {"schedule_id": schedule_id, "error": error})
        return updated

    def claim_due(self, schedule_id: str, *, expected_next_run_at: str) -> bool:
        claimed = self.store.claim_due_schedule(schedule_id, expected_next_run_at=expected_next_run_at)
        self.audit_logger.append("schedule.claimed" if claimed else "schedule.claim_skipped", {"schedule_id": schedule_id})
        return claimed

    def due(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        current = now or datetime.now(UTC)
        due_rows = []
        for row in self.list_schedules():
            if row["status"] != "active" or not row.get("next_run_at"):
                continue
            if not row.get("metadata", {}).get("approved"):
                continue
            if datetime.fromisoformat(row["next_run_at"]) <= current:
                due_rows.append(row)
        return due_rows


def estimate_next_run(cron: str) -> str:
    # Conservative implementation: supports common hourly/daily shorthand and otherwise schedules one hour out.
    current = datetime.now(UTC)
    if cron in {"@hourly", "0 * * * *"}:
        next_run = current.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    elif cron in {"@daily", "0 0 * * *"}:
        next_run = current.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    else:
        next_run = current + timedelta(hours=1)
    return next_run.isoformat()


def _decode(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["metadata"] = json.loads(decoded.pop("metadata_json", "{}"))
    return decoded


def _schedule_metadata(
    metadata: dict[str, Any],
    *,
    context_from: list[str] | tuple[str, ...],
    delivery_targets: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    normalized = dict(metadata)
    context_sources = _string_list(context_from or normalized.get("context_from", ()), max_items=12, max_chars=240)
    if context_sources:
        normalized["context_from"] = context_sources
    else:
        normalized.pop("context_from", None)
    targets = _string_list(delivery_targets or normalized.get("delivery_targets", ()), max_items=8, max_chars=80)
    if targets:
        normalized["delivery_targets"] = targets
    else:
        normalized.pop("delivery_targets", None)
    return normalized


def _string_list(value: Any, *, max_items: int, max_chars: int) -> list[str]:
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, (list, tuple)):
        candidates = [str(item) for item in value]
    else:
        candidates = []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        cleaned = " ".join(str(item).replace("\r", " ").replace("\n", " ").split()).strip()
        if not cleaned:
            continue
        cleaned = cleaned[:max_chars]
        if cleaned in seen:
            continue
        seen.add(cleaned)
        normalized.append(cleaned)
        if len(normalized) >= max_items:
            break
    return normalized
