"""Durable Kanban board for multi-step and multi-agent work coordination."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import RiskLevel, now_utc


DEFAULT_LANES = ("backlog", "ready", "in_progress", "review", "blocked", "done")
SUBAGENT_DELEGATION_BOARD_PURPOSE = "subagent_delegations"
SUBAGENT_DELEGATION_BOARD_NAME = "Subagent Delegations"


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

    def subagent_delegation_board(self, *, create: bool = False) -> dict[str, Any] | None:
        for board in self.list_boards():
            if board.get("metadata", {}).get("purpose") == SUBAGENT_DELEGATION_BOARD_PURPOSE:
                return board
        if not create:
            return None
        return self.create_board(
            SUBAGENT_DELEGATION_BOARD_NAME,
            metadata={
                "purpose": SUBAGENT_DELEGATION_BOARD_PURPOSE,
                "isolation": "card_per_delegate",
                "execution_mode": "durable_card_queue",
                "autonomous_runtime": False,
            },
        )

    def add_subagent_delegation(self, *, role: str, task: str, task_id: str | None = None) -> dict[str, Any]:
        role = role.strip()
        task = task.strip()
        if not role or not task:
            raise ValueError("subagent delegation requires non-empty role and task")
        board = self.subagent_delegation_board(create=True)
        assert board is not None
        return self.add_card(
            board["id"],
            title=f"{role}: {task[:80]}",
            description=task,
            lane="ready",
            owner=role,
            risk_level=RiskLevel.HIGH,
            task_id=task_id,
            metadata={
                "delegation_type": "subagent",
                "role": role,
                "source_tool": "subagent_delegate",
                "isolation": "durable_card",
                "instructions_tainted": True,
                "parent_task_id": task_id,
                "approval_gate": "tool_catalog_required",
                "handoff_receipt": "kanban.card_created",
                "raw_instruction_forwarded_to_model": False,
            },
        )

    def subagent_status(self, *, limit: int = 20) -> dict[str, Any]:
        board = self.subagent_delegation_board(create=False)
        lanes = {lane: 0 for lane in DEFAULT_LANES}
        cards: list[dict[str, Any]] = []
        if board is not None:
            cards = self.list_cards(board["id"])
            for card in cards:
                lane = str(card.get("lane", ""))
                if lane in lanes:
                    lanes[lane] += 1
        open_cards = [card for card in cards if card.get("lane") != "done"]
        active_roles = sorted({str(card.get("owner")) for card in open_cards if card.get("owner")})
        safe_cards = [_subagent_card_summary(card) for card in sorted(cards, key=lambda row: str(row.get("updated_at", "")), reverse=True)[: max(0, limit)]]
        return {
            "status": "delegation_queue_ready" if board is not None else "no_delegations",
            "execution_mode": "durable_card_queue",
            "autonomous_runtime": False,
            "parallel_runtime": "operator_orchestrated_cards",
            "board": _subagent_board_summary(board) if board is not None else None,
            "lanes": lanes,
            "total_cards": len(cards),
            "open_cards": len(open_cards),
            "ready_cards": lanes["ready"],
            "in_progress_cards": lanes["in_progress"],
            "review_cards": lanes["review"],
            "blocked_cards": lanes["blocked"],
            "done_cards": lanes["done"],
            "active_roles": active_roles,
            "cards": safe_cards,
            "implemented_controls": [
                "approval_required_delegation",
                "durable_work_cards",
                "tainted_instruction_metadata",
                "audit_receipts",
                "operator_lane_control",
            ],
            "remaining_depth_work": [
                "isolated_parallel_runtime",
                "agent_profile_lifecycle",
                "handoff_receipts",
                "recursive_budget_limits",
            ],
            "raw_instruction_included": False,
        }

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


def _preview(value: str, *, limit: int = 160) -> str:
    normalized = " ".join(str(value).split())
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[: limit - 3]}..."


def _subagent_board_summary(board: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": board["id"],
        "name": board["name"],
        "updated_at": board["updated_at"],
        "metadata": {
            "purpose": board.get("metadata", {}).get("purpose"),
            "isolation": board.get("metadata", {}).get("isolation"),
            "execution_mode": board.get("metadata", {}).get("execution_mode"),
            "autonomous_runtime": bool(board.get("metadata", {}).get("autonomous_runtime", False)),
        },
    }


def _subagent_card_summary(card: dict[str, Any]) -> dict[str, Any]:
    metadata = card.get("metadata", {})
    return {
        "id": card["id"],
        "title": card["title"],
        "lane": card["lane"],
        "owner": card.get("owner"),
        "risk_level": card.get("risk_level"),
        "task_id": card.get("task_id"),
        "parent_task_id": metadata.get("parent_task_id"),
        "created_at": card.get("created_at"),
        "updated_at": card.get("updated_at"),
        "description_preview": _preview(str(card.get("description", ""))),
        "delegation_type": metadata.get("delegation_type"),
        "instructions_tainted": bool(metadata.get("instructions_tainted", True)),
        "approval_gate": metadata.get("approval_gate", "tool_catalog_required"),
        "raw_instruction_forwarded_to_model": bool(metadata.get("raw_instruction_forwarded_to_model", False)),
    }
