"""Local skill maintenance curator."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import json

from aegis.audit.logger import AuditLogger, redact
from aegis.security.taint import now_utc
from aegis.skills.registry import SkillRegistry
from aegis.storage.state import ensure_private_file


PROTECTED_SKILL_SOURCES = {"built-in", "bundled", "hub"}


class SkillCurator:
    """Metadata-first maintenance controls for locally authored skills."""

    def __init__(self, path: str | Path, audit_logger: AuditLogger, *, skills: SkillRegistry) -> None:
        self.path = Path(path)
        self.audit_logger = audit_logger
        self.skills = skills

    def status(self) -> dict[str, Any]:
        state = self._read_state()
        records = self._skill_records(state)
        return {
            "status": "curator_status",
            "mode": "local_skill_maintenance",
            "enabled": not bool(state["paused"]),
            "paused": bool(state["paused"]),
            "last_run_at": str(state["last_run_at"]),
            "skill_count": len(records),
            "managed_skill_count": sum(1 for record in records if record["managed_by_curator"]),
            "pinned": sorted(state["pinned"].keys()),
            "archived": sorted(state["archived"].keys()),
            "counts": _counts(records),
            "least_recently_updated": sorted(
                [
                    {
                        "id": record["id"],
                        "updated_at": record["updated_at"],
                        "state": record["curator_state"],
                    }
                    for record in records
                    if record["managed_by_curator"]
                ],
                key=lambda record: (record["updated_at"], record["id"]),
            )[:5],
            "skills": records,
            "raw_secret_values_included": False,
            "blocked_operations": _blocked_operations(),
        }

    def run(self, *, dry_run: bool = False) -> dict[str, Any]:
        state = self._read_state()
        records = self._skill_records(state)
        reviewed = [record for record in records if record["managed_by_curator"] and not record["pinned"]]
        recommendations = [_recommendation(record) for record in reviewed]
        timestamp = now_utc()
        if not dry_run and not state["paused"]:
            state["last_run_at"] = timestamp
            self._write_state(state)
            self.audit_logger.append(
                "skill.curator_run",
                redact(
                    {
                        "dry_run": False,
                        "reviewed": len(reviewed),
                        "recommendations": recommendations,
                    }
                ),
            )
        return {
            "status": "curator_run_dry_run" if dry_run else "curator_run_paused" if state["paused"] else "curator_run_completed",
            "mode": "deterministic_local_skill_scan",
            "dry_run": dry_run,
            "paused": bool(state["paused"]),
            "run_at": timestamp if not dry_run and not state["paused"] else "",
            "skills_reviewed": len(reviewed),
            "recommendations": recommendations,
            "mutations_performed": [] if dry_run or state["paused"] else ["last_run_at_recorded"],
            "llm_review": "not_enabled_for_dependency_light_runtime",
            "raw_secret_values_included": False,
            "blocked_operations": _blocked_operations(),
        }

    def pin(self, skill_id: str) -> dict[str, Any]:
        record = self._require_managed_skill(skill_id)
        state = self._read_state()
        if skill_id in state["archived"]:
            raise ValueError("restore archived skill before pinning it")
        state["pinned"][skill_id] = {"pinned_at": now_utc()}
        self._write_state(state)
        result = {"status": "curator_skill_pinned", "skill_id": skill_id, "name": record["name"], "pinned": True}
        self.audit_logger.append("skill.curator_pinned", redact(result))
        return result

    def unpin(self, skill_id: str) -> dict[str, Any]:
        self._require_managed_skill(skill_id)
        state = self._read_state()
        was_pinned = skill_id in state["pinned"]
        state["pinned"].pop(skill_id, None)
        self._write_state(state)
        result = {"status": "curator_skill_unpinned", "skill_id": skill_id, "pinned": False, "was_pinned": was_pinned}
        self.audit_logger.append("skill.curator_unpinned", redact(result))
        return result

    def archive(self, skill_id: str) -> dict[str, Any]:
        record = self._require_managed_skill(skill_id)
        state = self._read_state()
        if skill_id in state["pinned"]:
            raise PermissionError("pinned skills cannot be archived; unpin first")
        if skill_id not in state["archived"]:
            state["archived"][skill_id] = {"archived_at": now_utc(), "was_enabled": bool(record["enabled"])}
        self.skills.disable(skill_id)
        self._write_state(state)
        result = {
            "status": "curator_skill_archived",
            "skill_id": skill_id,
            "name": record["name"],
            "archived": True,
            "enabled": False,
            "restore_command": f"curator restore {skill_id}",
        }
        self.audit_logger.append("skill.curator_archived", redact(result))
        return result

    def restore(self, skill_id: str) -> dict[str, Any]:
        self._require_managed_skill(skill_id)
        state = self._read_state()
        archived = state["archived"].pop(skill_id, None)
        if archived is None:
            raise KeyError(skill_id)
        self._write_state(state)
        result = {
            "status": "curator_skill_restored",
            "skill_id": skill_id,
            "archived": False,
            "enabled": False,
            "enable_command": f"skills enable {skill_id}",
            "auto_reenable": False,
            "was_enabled": bool(archived.get("was_enabled", False)) if isinstance(archived, dict) else False,
        }
        self.audit_logger.append("skill.curator_restored", redact(result))
        return result

    def pause(self) -> dict[str, Any]:
        state = self._read_state()
        state["paused"] = True
        self._write_state(state)
        result = {"status": "curator_paused", "paused": True}
        self.audit_logger.append("skill.curator_paused", result)
        return result

    def resume(self) -> dict[str, Any]:
        state = self._read_state()
        state["paused"] = False
        self._write_state(state)
        result = {"status": "curator_resumed", "paused": False}
        self.audit_logger.append("skill.curator_resumed", result)
        return result

    def _require_managed_skill(self, skill_id: str) -> dict[str, Any]:
        state = self._read_state()
        for record in self._skill_records(state):
            if record["id"] != skill_id:
                continue
            if not record["managed_by_curator"]:
                raise PermissionError("built-in and hub skills are protected from curator mutation")
            return record
        raise KeyError(skill_id)

    def _skill_records(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for row in self.skills.list():
            manifest = row["manifest"]
            skill_id = str(row["id"])
            source = str(manifest.get("source") or "local")
            managed = source not in PROTECTED_SKILL_SOURCES and not skill_id.startswith("aegis.")
            pinned = skill_id in state["pinned"]
            archived = skill_id in state["archived"]
            curator_state = "protected" if not managed else "archived" if archived else "pinned" if pinned else "active" if row["enabled"] else "disabled"
            records.append(
                {
                    "id": skill_id,
                    "name": str(manifest.get("name", "")),
                    "version": str(manifest.get("version", "")),
                    "enabled": bool(row["enabled"]),
                    "risk_level": str(manifest.get("risk_level", "")),
                    "source": source,
                    "updated_at": str(manifest.get("updated_at") or ""),
                    "managed_by_curator": managed,
                    "pinned": pinned,
                    "archived": archived,
                    "curator_state": curator_state,
                }
            )
        return sorted(records, key=lambda record: record["id"])

    def _read_state(self) -> dict[str, Any]:
        if not self.path.exists():
            return _empty_state()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return _empty_state()
        if not isinstance(raw, dict):
            return _empty_state()
        pinned = raw.get("pinned", {})
        archived = raw.get("archived", {})
        return {
            "version": 1,
            "paused": bool(raw.get("paused", False)),
            "last_run_at": str(raw.get("last_run_at") or ""),
            "pinned": {str(key): dict(value) if isinstance(value, dict) else {} for key, value in pinned.items()} if isinstance(pinned, dict) else {},
            "archived": {str(key): dict(value) if isinstance(value, dict) else {} for key, value in archived.items()} if isinstance(archived, dict) else {},
        }

    def _write_state(self, state: dict[str, Any]) -> None:
        ensure_private_file(self.path)
        self.path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        ensure_private_file(self.path)


def _empty_state() -> dict[str, Any]:
    return {"version": 1, "paused": False, "last_run_at": "", "pinned": {}, "archived": {}}


def _counts(records: list[dict[str, Any]]) -> dict[str, int]:
    result = {"managed": 0, "protected": 0, "active": 0, "disabled": 0, "pinned": 0, "archived": 0}
    for record in records:
        result["managed" if record["managed_by_curator"] else "protected"] += 1
        state = str(record["curator_state"])
        if state in result:
            result[state] += 1
    return result


def _recommendation(record: dict[str, Any]) -> dict[str, Any]:
    if record["archived"]:
        action = "keep_archived"
        reason = "archived skill remains recoverable with curator restore"
    elif record["enabled"]:
        action = "keep_active"
        reason = "enabled skill has no deterministic maintenance action"
    else:
        action = "review_disabled"
        reason = "disabled local skill can be enabled through approvals or archived explicitly"
    return {
        "skill_id": record["id"],
        "action": action,
        "reason": reason,
        "risk_level": record["risk_level"],
    }


def _blocked_operations() -> list[str]:
    return [
        "unattended_skill_deletion",
        "unapproved_skill_enablement",
        "raw_secret_capture",
        "unbounded_llm_self_mutation",
    ]
