"""Evidence bundles for completed and blocked tasks."""

from __future__ import annotations

import json
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore


class EvidenceBundleBuilder:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def build(self, task_id: str) -> dict[str, Any]:
        task = self.store.get_task(task_id)
        if not task:
            raise KeyError(task_id)
        return {
            "task": {
                "id": task["id"],
                "status": task["status"],
                "interpretation": task["interpretation"],
                "plan": json.loads(task["plan_json"]),
                "checkpoint": json.loads(task["checkpoint_json"]),
                "receipt": json.loads(task["receipt_json"]) if task["receipt_json"] else None,
            },
            "audit_tail": [entry for entry in self.audit_logger.tail(50) if entry.get("task_id") == task_id],
        }
