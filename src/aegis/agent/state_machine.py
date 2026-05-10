"""Durable task state machine."""

from __future__ import annotations

from enum import Enum


class TaskStatus(str, Enum):
    PENDING = "pending"
    PLANNED = "planned"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


ALLOWED_TRANSITIONS = {
    TaskStatus.PENDING: {TaskStatus.PLANNED, TaskStatus.BLOCKED, TaskStatus.FAILED},
    TaskStatus.PLANNED: {TaskStatus.RUNNING, TaskStatus.WAITING_APPROVAL, TaskStatus.BLOCKED, TaskStatus.FAILED},
    TaskStatus.WAITING_APPROVAL: {TaskStatus.RUNNING, TaskStatus.BLOCKED, TaskStatus.FAILED},
    TaskStatus.RUNNING: {TaskStatus.COMPLETED, TaskStatus.WAITING_APPROVAL, TaskStatus.BLOCKED, TaskStatus.FAILED},
    TaskStatus.COMPLETED: set(),
    TaskStatus.FAILED: set(),
    TaskStatus.BLOCKED: set(),
}


class TaskStateMachine:
    def transition(self, current: TaskStatus | str, next_status: TaskStatus | str) -> TaskStatus:
        current_status = TaskStatus(current)
        requested = TaskStatus(next_status)
        if requested not in ALLOWED_TRANSITIONS[current_status]:
            raise ValueError(f"invalid task transition {current_status.value} -> {requested.value}")
        return requested
