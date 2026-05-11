"""Durable Kanban board for multi-step and multi-agent work coordination."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import RiskLevel, now_utc


DEFAULT_LANES = ("backlog", "ready", "in_progress", "review", "blocked", "done")


class KanbanManager:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def create_board(self, name: str, *, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        row = {"id": str(uuid4()), "name": name, "created_at": now_utc(), "updated_at": now_utc(), "metadata": {"lanes": list(DEFAULT_LANES), **(metadata or {})}}
        self.store.insert_kanban_board(row)
        self.audit_logger.append("kanban.board_created", row)
        return row

    def add_card(
        self,
        board_id: str,
        *,
        title: str,
        description: str,
        lane: str = "backlog",
        owner: str | None = None,
        risk_level: RiskLevel = RiskLevel.LOW,
        task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._require_board(board_id)
        if lane not in DEFAULT_LANES:
            raise ValueError(f"unknown lane {lane!r}")
        row = {
            "id": str(uuid4()),
            "board_id": board_id,
            "title": title,
            "description": description,
            "lane": lane,
            "owner": owner,
            "risk_level": risk_level.value,
            "task_id": task_id,
            "created_at": now_utc(),
            "updated_at": now_utc(),
            "metadata": metadata or {},
        }
        self.store.insert_kanban_card(row)
        self.audit_logger.append("kanban.card_created", row, task_id=task_id)
        return row

    def move_card(self, card_id: str, lane: str) -> None:
        if lane not in DEFAULT_LANES:
            raise ValueError(f"unknown lane {lane!r}")
        self._require_card(card_id)
        self.store.move_kanban_card(card_id, lane)
        self.audit_logger.append("kanban.card_moved", {"card_id": card_id, "lane": lane})

    def list_boards(self) -> list[dict[str, Any]]:
        return [_decode(row) for row in self.store.list_kanban_boards()]

    def list_cards(self, board_id: str) -> list[dict[str, Any]]:
        self._require_board(board_id)
        return [_decode(row) for row in self.store.list_kanban_cards(board_id)]

    def _require_board(self, board_id: str) -> dict[str, Any]:
        row = self.store.get_kanban_board(board_id)
        if row is None:
            raise KeyError(board_id)
        return _decode(row)

    def _require_card(self, card_id: str) -> dict[str, Any]:
        row = self.store.get_kanban_card(card_id)
        if row is None:
            raise KeyError(card_id)
        return _decode(row)


def _decode(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["metadata"] = json.loads(decoded.pop("metadata_json", "{}"))
    return decoded
