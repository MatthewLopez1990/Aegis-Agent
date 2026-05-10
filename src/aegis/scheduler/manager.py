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
    ) -> dict[str, Any]:
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
            "metadata": metadata or {},
        }
        self.store.insert_schedule(row)
        self.audit_logger.append("schedule.created", row)
        return row

    def list_schedules(self) -> list[dict[str, Any]]:
        return [_decode(row) for row in self.store.list_schedules()]

    def mark_ran(self, schedule_id: str) -> None:
        self.store.update_schedule(schedule_id, {"last_run_at": now_utc(), "next_run_at": estimate_next_run("* * * * *")})
        self.audit_logger.append("schedule.ran", {"schedule_id": schedule_id})

    def due(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        current = now or datetime.now(UTC)
        due_rows = []
        for row in self.list_schedules():
            if row["status"] != "active" or not row.get("next_run_at"):
                continue
            if datetime.fromisoformat(row["next_run_at"]) <= current:
                due_rows.append(row)
        return due_rows


def estimate_next_run(cron: str) -> str:
    # Conservative MVP: supports common hourly/daily shorthand and otherwise schedules one hour out.
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
