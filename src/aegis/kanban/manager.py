"""Durable Kanban board for multi-step and multi-agent work coordination."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import RiskLevel, now_utc


DEFAULT_LANES = ("backlog", "ready", "in_progress", "review", "blocked", "done")
SUBAGENT_DELEGATION_BOARD_PURPOSE = "subagent_delegations"
SUBAGENT_DELEGATION_BOARD_NAME = "Subagent Delegations"
SUBAGENT_DEFAULT_PROFILE_ID = "operator-default"


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

    def move_subagent_delegation(self, card_id: str, lane: str, *, actor: str = "operator", reason: str = "") -> dict[str, Any]:
        if lane not in DEFAULT_LANES:
            raise ValueError(f"unknown lane {lane!r}")
        card = self._require_card(card_id)
        board = self.subagent_delegation_board(create=False)
        metadata = card.get("metadata", {})
        if board is None or card.get("board_id") != board.get("id") or metadata.get("delegation_type") != "subagent":
            raise ValueError("card is not a subagent delegation")
        from_lane = str(card.get("lane", ""))
        timestamp = now_utc()
        reason_text = reason.strip()
        receipt = {
            "receipt_schema": "aegis.subagent.handoff.v1",
            "event_type": "subagent.handoff_recorded",
            "card_id": card_id,
            "board_id": board["id"],
            "from_lane": from_lane,
            "to_lane": lane,
            "actor": _safe_actor(actor),
            "reason_included": bool(reason_text),
            "reason_sha256": hashlib.sha256(reason_text.encode("utf-8")).hexdigest() if reason_text else None,
            "reason_character_count": len(reason_text),
            "raw_reason_included": False,
            "raw_instruction_included": False,
            "raw_instruction_forwarded_to_model": False,
            "autonomous_runtime": False,
            "created_at": timestamp,
        }
        receipt_count = _handoff_receipt_count(metadata, default=1 if metadata.get("handoff_receipt") else 0) + 1
        self.store.move_kanban_card(card_id, lane)
        self.store.update_kanban_card_metadata(
            card_id,
            {
                "handoff_receipt": "subagent.handoff_recorded",
                "handoff_receipts_recorded": receipt_count,
                "last_handoff_receipt": receipt,
            },
        )
        audit_entry = self.audit_logger.append(
            "subagent.handoff_recorded",
            {**receipt, "role": metadata.get("role"), "receipt_count": receipt_count},
            task_id=str(card.get("task_id")) if card.get("task_id") else None,
        )
        updated_card = self._require_card(card_id)
        return {
            "ok": True,
            "card_id": card_id,
            "lane": lane,
            "receipt": receipt,
            "receipt_count": receipt_count,
            "audit_event_hash": audit_entry["event_hash"],
            "card": _subagent_card_summary(updated_card),
        }

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
                "profile_lifecycle": "durable_board_metadata",
                "subagent_profiles": {SUBAGENT_DEFAULT_PROFILE_ID: _default_subagent_profile(now_utc())},
            },
        )

    def list_subagent_profiles(self) -> list[dict[str, Any]]:
        board = self.subagent_delegation_board(create=False)
        if board is None:
            return []
        return [_profile_summary(profile) for profile in _profiles_from_board(board).values()]

    def create_subagent_profile(
        self,
        name: str,
        *,
        role: str | None = None,
        tool_allowlist: list[str] | tuple[str, ...] | None = None,
        max_parallel_cards: int = 1,
        recursive_depth_limit: int = 0,
        max_tool_calls: int = 0,
        max_runtime_seconds: int = 0,
        network_policy: str = "disabled",
        workspace_scope: str = "current_workspace",
        actor: str = "operator",
    ) -> dict[str, Any]:
        profile = _build_subagent_profile(
            name,
            role=role,
            tool_allowlist=tuple(tool_allowlist or ()),
            max_parallel_cards=max_parallel_cards,
            recursive_depth_limit=recursive_depth_limit,
            max_tool_calls=max_tool_calls,
            max_runtime_seconds=max_runtime_seconds,
            network_policy=network_policy,
            workspace_scope=workspace_scope,
        )
        board = self.subagent_delegation_board(create=True)
        assert board is not None
        profiles = _profiles_from_board(board)
        created = profile["id"] not in profiles
        if not created:
            profile["created_at"] = profiles[profile["id"]].get("created_at", profile["created_at"])
        profiles[profile["id"]] = profile
        self.store.update_kanban_board_metadata(
            board["id"],
            {
                "profile_lifecycle": "durable_board_metadata",
                "subagent_profiles": profiles,
            },
        )
        event_type = "subagent.profile_created" if created else "subagent.profile_updated"
        self.audit_logger.append(event_type, {"profile": _profile_summary(profile), "actor": _safe_actor(actor), "raw_secret_values_included": False})
        return {"ok": True, "created": created, "profile": _profile_summary(profile), "profiles": [_profile_summary(row) for row in profiles.values()]}

    def disable_subagent_profile(self, profile_id: str, *, actor: str = "operator") -> dict[str, Any]:
        board = self.subagent_delegation_board(create=False)
        if board is None:
            raise KeyError(profile_id)
        profiles = _profiles_from_board(board)
        normalized_id = _profile_id(profile_id)
        if normalized_id not in profiles:
            raise KeyError(profile_id)
        profile = dict(profiles[normalized_id])
        profile["enabled"] = False
        profile["status"] = "disabled"
        profile["updated_at"] = now_utc()
        profile["disabled_by"] = _safe_actor(actor)
        profiles[normalized_id] = profile
        self.store.update_kanban_board_metadata(board["id"], {"subagent_profiles": profiles})
        self.audit_logger.append(
            "subagent.profile_disabled",
            {"profile_id": normalized_id, "actor": _safe_actor(actor), "raw_secret_values_included": False},
        )
        return {"ok": True, "profile": _profile_summary(profile), "profiles": [_profile_summary(row) for row in profiles.values()]}

    def add_subagent_delegation(self, *, role: str, task: str, task_id: str | None = None) -> dict[str, Any]:
        role = role.strip()
        task = task.strip()
        if not role or not task:
            raise ValueError("subagent delegation requires non-empty role and task")
        board = self.subagent_delegation_board(create=True)
        assert board is not None
        profiles = _profiles_from_board(board)
        profile = _select_profile_for_role(profiles, role)
        existing_cards = self.list_cards(board["id"])
        open_profile_cards = _open_profile_card_count(existing_cards, str(profile["id"]))
        max_parallel_cards = _profile_int(profile, "max_parallel_cards", 1)
        if open_profile_cards >= max_parallel_cards:
            self.audit_logger.append(
                "subagent.budget_denied",
                {
                    "profile_id": profile["id"],
                    "open_profile_cards": open_profile_cards,
                    "max_parallel_cards": max_parallel_cards,
                    "raw_instruction_included": False,
                    "autonomous_runtime": False,
                },
                task_id=task_id,
            )
            raise ValueError(f"subagent profile {profile['id']!r} has no available parallel card budget")
        budget_snapshot = _profile_budget_snapshot(profile, open_profile_cards=open_profile_cards)
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
                "profile_id": profile["id"],
                "profile_status": "matched" if _profile_id(role) == profile["id"] and profile.get("enabled", True) else "default_profile",
                "profile_snapshot": _profile_summary(profile),
                "budget_snapshot": budget_snapshot,
                "budget_enforced": True,
                "source_tool": "subagent_delegate",
                "isolation": "durable_card",
                "instructions_tainted": True,
                "parent_task_id": task_id,
                "approval_gate": "tool_catalog_required",
                "handoff_receipt": "kanban.card_created",
                "handoff_receipts_recorded": 1,
                "last_handoff_receipt": {
                    "receipt_schema": "aegis.subagent.handoff.v1",
                    "event_type": "kanban.card_created",
                    "from_lane": None,
                    "to_lane": "ready",
                    "raw_reason_included": False,
                    "raw_instruction_included": False,
                    "raw_instruction_forwarded_to_model": False,
                    "autonomous_runtime": False,
                },
                "raw_instruction_forwarded_to_model": False,
            },
        )

    def subagent_status(self, *, limit: int = 20) -> dict[str, Any]:
        board = self.subagent_delegation_board(create=False)
        lanes = {lane: 0 for lane in DEFAULT_LANES}
        cards: list[dict[str, Any]] = []
        profiles: list[dict[str, Any]] = []
        if board is not None:
            profiles = [_profile_summary(profile) for profile in _profiles_from_board(board).values()]
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
            "profiles": profiles,
            "profile_count": len(profiles),
            "enabled_profile_count": len([profile for profile in profiles if profile.get("enabled")]),
            "cards": safe_cards,
            "implemented_controls": [
                "approval_required_delegation",
                "durable_work_cards",
                "tainted_instruction_metadata",
                "audit_receipts",
                "operator_lane_control",
                "handoff_receipts",
                "agent_profile_lifecycle",
                "recursive_budget_limits",
            ],
            "remaining_depth_work": [
                "isolated_parallel_runtime",
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


def _safe_actor(value: str, *, limit: int = 80) -> str:
    normalized = " ".join(str(value or "operator").split())
    if not normalized:
        return "operator"
    return normalized[:limit]


def _safe_label(value: str, *, limit: int = 120) -> str:
    return " ".join(str(value or "").split())[:limit]


def _handoff_receipt_count(metadata: dict[str, Any], *, default: int = 0) -> int:
    try:
        return int(metadata.get("handoff_receipts_recorded", default))
    except (TypeError, ValueError):
        return default


def _profile_id(name: str) -> str:
    normalized = "".join(char.lower() if char.isalnum() else "-" for char in str(name).strip())
    normalized = "-".join(part for part in normalized.split("-") if part)
    if not normalized:
        raise ValueError("subagent profile name is required")
    return normalized[:64]


def _safe_tool_allowlist(values: tuple[str, ...]) -> list[str]:
    tools: list[str] = []
    for value in values:
        tool = _safe_label(value, limit=80)
        if not tool:
            continue
        tools.append(tool)
    return sorted(set(tools))[:50]


def _default_subagent_profile(timestamp: str) -> dict[str, Any]:
    return {
        "profile_schema": "aegis.subagent.profile.v1",
        "id": SUBAGENT_DEFAULT_PROFILE_ID,
        "name": "Operator Default",
        "role": "Operator",
        "enabled": True,
        "status": "enabled",
        "tool_allowlist": [],
        "max_parallel_cards": 1,
        "recursive_depth_limit": 0,
        "max_tool_calls": 0,
        "max_runtime_seconds": 0,
        "network_policy": "disabled",
        "workspace_scope": "current_workspace",
        "autonomous_runtime": False,
        "raw_instruction_forwarded_to_model": False,
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def _build_subagent_profile(
    name: str,
    *,
    role: str | None,
    tool_allowlist: tuple[str, ...],
    max_parallel_cards: int,
    recursive_depth_limit: int,
    max_tool_calls: int = 0,
    max_runtime_seconds: int = 0,
    network_policy: str,
    workspace_scope: str,
) -> dict[str, Any]:
    timestamp = now_utc()
    if recursive_depth_limit != 0:
        raise ValueError("subagent recursive depth must remain 0 until autonomous isolation is enabled")
    if max_parallel_cards < 1 or max_parallel_cards > 20:
        raise ValueError("subagent max_parallel_cards must be between 1 and 20")
    if max_tool_calls < 0 or max_tool_calls > 1000:
        raise ValueError("subagent max_tool_calls must be between 0 and 1000")
    if max_runtime_seconds < 0 or max_runtime_seconds > 86400:
        raise ValueError("subagent max_runtime_seconds must be between 0 and 86400")
    if network_policy not in {"disabled", "allowlisted"}:
        raise ValueError("subagent network_policy must be disabled or allowlisted")
    profile_name = _safe_label(name)
    profile_id = _profile_id(profile_name)
    return {
        "profile_schema": "aegis.subagent.profile.v1",
        "id": profile_id,
        "name": profile_name,
        "role": _safe_label(role or profile_name),
        "enabled": True,
        "status": "enabled",
        "tool_allowlist": _safe_tool_allowlist(tool_allowlist),
        "max_parallel_cards": int(max_parallel_cards),
        "recursive_depth_limit": recursive_depth_limit,
        "max_tool_calls": int(max_tool_calls),
        "max_runtime_seconds": int(max_runtime_seconds),
        "network_policy": network_policy,
        "workspace_scope": _safe_label(workspace_scope, limit=160) or "current_workspace",
        "autonomous_runtime": False,
        "raw_instruction_forwarded_to_model": False,
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def _profiles_from_board(board: dict[str, Any]) -> dict[str, dict[str, Any]]:
    metadata = board.get("metadata", {})
    raw_profiles = metadata.get("subagent_profiles")
    profiles = raw_profiles if isinstance(raw_profiles, dict) else {}
    if SUBAGENT_DEFAULT_PROFILE_ID not in profiles:
        profiles = {SUBAGENT_DEFAULT_PROFILE_ID: _default_subagent_profile(str(board.get("created_at") or now_utc())), **profiles}
    return {str(key): dict(value) for key, value in profiles.items() if isinstance(value, dict)}


def _select_profile_for_role(profiles: dict[str, dict[str, Any]], role: str) -> dict[str, Any]:
    role_id = _profile_id(role)
    matched = profiles.get(role_id)
    if matched and matched.get("enabled", True):
        return matched
    default = profiles.get(SUBAGENT_DEFAULT_PROFILE_ID)
    if default:
        return default
    return _default_subagent_profile(now_utc())


def _profile_int(profile: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(profile.get(key, default))
    except (TypeError, ValueError):
        return default


def _open_profile_card_count(cards: list[dict[str, Any]], profile_id: str) -> int:
    count = 0
    for card in cards:
        if card.get("lane") == "done":
            continue
        metadata = card.get("metadata", {})
        if metadata.get("profile_id") == profile_id:
            count += 1
    return count


def _profile_budget_snapshot(profile: dict[str, Any], *, open_profile_cards: int) -> dict[str, Any]:
    return {
        "budget_schema": "aegis.subagent.budget.v1",
        "profile_id": profile.get("id"),
        "open_profile_cards_at_create": open_profile_cards,
        "max_parallel_cards": _profile_int(profile, "max_parallel_cards", 1),
        "recursive_depth_limit": _profile_int(profile, "recursive_depth_limit", 0),
        "max_tool_calls": _profile_int(profile, "max_tool_calls", 0),
        "max_runtime_seconds": _profile_int(profile, "max_runtime_seconds", 0),
        "network_policy": profile.get("network_policy", "disabled"),
        "workspace_scope": profile.get("workspace_scope", "current_workspace"),
        "autonomous_runtime": False,
        "enforcement": "delegation_queue_preflight",
    }


def _profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": profile.get("id"),
        "name": profile.get("name"),
        "role": profile.get("role"),
        "enabled": bool(profile.get("enabled", True)),
        "status": profile.get("status", "enabled" if profile.get("enabled", True) else "disabled"),
        "tool_allowlist": list(profile.get("tool_allowlist") or []),
        "max_parallel_cards": _profile_int(profile, "max_parallel_cards", 1),
        "recursive_depth_limit": _profile_int(profile, "recursive_depth_limit", 0),
        "max_tool_calls": _profile_int(profile, "max_tool_calls", 0),
        "max_runtime_seconds": _profile_int(profile, "max_runtime_seconds", 0),
        "network_policy": profile.get("network_policy", "disabled"),
        "workspace_scope": profile.get("workspace_scope", "current_workspace"),
        "autonomous_runtime": bool(profile.get("autonomous_runtime", False)),
        "raw_instruction_forwarded_to_model": bool(profile.get("raw_instruction_forwarded_to_model", False)),
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
    }


def _subagent_board_summary(board: dict[str, Any]) -> dict[str, Any]:
    profiles = _profiles_from_board(board)
    return {
        "id": board["id"],
        "name": board["name"],
        "updated_at": board["updated_at"],
        "metadata": {
            "purpose": board.get("metadata", {}).get("purpose"),
            "isolation": board.get("metadata", {}).get("isolation"),
            "execution_mode": board.get("metadata", {}).get("execution_mode"),
            "autonomous_runtime": bool(board.get("metadata", {}).get("autonomous_runtime", False)),
            "profile_lifecycle": board.get("metadata", {}).get("profile_lifecycle"),
            "profile_count": len(profiles),
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
        "profile_id": metadata.get("profile_id"),
        "profile_status": metadata.get("profile_status"),
        "profile_snapshot": metadata.get("profile_snapshot"),
        "budget_snapshot": metadata.get("budget_snapshot"),
        "budget_enforced": bool(metadata.get("budget_enforced", False)),
        "created_at": card.get("created_at"),
        "updated_at": card.get("updated_at"),
        "description_preview": _preview(str(card.get("description", ""))),
        "delegation_type": metadata.get("delegation_type"),
        "instructions_tainted": bool(metadata.get("instructions_tainted", True)),
        "approval_gate": metadata.get("approval_gate", "tool_catalog_required"),
        "handoff_receipt": metadata.get("handoff_receipt"),
        "handoff_receipts_recorded": _handoff_receipt_count(metadata),
        "last_handoff_receipt": metadata.get("last_handoff_receipt"),
        "raw_instruction_forwarded_to_model": bool(metadata.get("raw_instruction_forwarded_to_model", False)),
    }
