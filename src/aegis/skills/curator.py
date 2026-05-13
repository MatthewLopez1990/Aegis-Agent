"""Local skill maintenance curator."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4
import hashlib
import json

from aegis.audit.logger import AuditLogger, redact
from aegis.security.taint import now_utc
from aegis.skills.builder import create_skill_template
from aegis.skills.manifest import SkillManifest
from aegis.skills.registry import SkillRegistry
from aegis.skills.static_scan import scan_skill_manifest
from aegis.storage.state import ensure_private_dir, ensure_private_file


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
        candidates = self._candidate_records()
        return {
            "status": "curator_status",
            "mode": "local_skill_maintenance",
            "enabled": not bool(state["paused"]),
            "paused": bool(state["paused"]),
            "last_run_at": str(state["last_run_at"]),
            "skill_count": len(records),
            "managed_skill_count": sum(1 for record in records if record["managed_by_curator"]),
            "candidate_count": len(candidates),
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
            "candidates": candidates[:20],
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

    def draft_candidate(
        self,
        skill_id: str,
        *,
        name: str,
        description: str,
        actor: str = "operator",
        observed_task: str = "",
    ) -> dict[str, Any]:
        manifest = create_skill_template(skill_id, name=name, description=description, source="curator-draft")
        if observed_task.strip():
            manifest["changelog"] = ["Created disabled template from reviewed task observation."]
        validated = SkillManifest.from_dict(manifest).validate()
        static_scan = scan_skill_manifest(validated)
        if not static_scan["ok"]:
            self.audit_logger.append("skill.curator_draft_rejected", {"skill_id": skill_id, "scan": static_scan})
            raise PermissionError("skill draft static scan failed")
        candidate_id = uuid4().hex
        created_at = now_utc()
        payload = {
            "candidate_schema": "aegis.skill.curator_candidate.v1",
            "candidate_id": candidate_id,
            "created_at": created_at,
            "actor": _safe_actor(actor),
            "skill_id": validated.id,
            "manifest": validated.to_dict(),
            "manifest_sha256": _stable_json_sha256(validated.to_dict()),
            "observed_task_sha256": hashlib.sha256(observed_task.strip().encode("utf-8")).hexdigest() if observed_task.strip() else None,
            "observed_task_character_count": len(observed_task.strip()),
            "observed_task_included": False,
            "static_scan": static_scan,
            "status": "drafted_for_review",
            "approved_for_install": False,
            "raw_secret_values_included": False,
            "blocked_operations": _blocked_operations(),
        }
        path = self._candidate_path(candidate_id)
        _write_private_json(path, payload)
        receipt = _candidate_receipt(payload, path)
        self.audit_logger.append("skill.curator_candidate_drafted", redact(receipt))
        return {
            "ok": True,
            "status": "skill_candidate_drafted",
            "candidate_id": candidate_id,
            "skill_id": validated.id,
            "candidate_path": str(path),
            "manifest_sha256": payload["manifest_sha256"],
            "static_scan": static_scan,
            "receipt": receipt,
            "install_command": f"curator install-draft {candidate_id} --approved",
            "raw_secret_values_included": False,
        }

    def verify_candidate(self, candidate_id: str) -> dict[str, Any]:
        path = self._candidate_path(candidate_id)
        payload = self._read_candidate(candidate_id)
        manifest = SkillManifest.from_dict(payload.get("manifest") if isinstance(payload.get("manifest"), dict) else {}).validate()
        expected = str(payload.get("manifest_sha256") or "")
        actual = _stable_json_sha256(manifest.to_dict())
        static_scan = scan_skill_manifest(manifest)
        artifact_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        ok = (
            payload.get("candidate_schema") == "aegis.skill.curator_candidate.v1"
            and expected == actual
            and static_scan["ok"]
            and payload.get("observed_task_included") is False
            and payload.get("raw_secret_values_included") is False
        )
        receipt = {
            "receipt_schema": "aegis.skill.curator_candidate_verification.v1",
            "event_type": "skill.curator_candidate_verified",
            "candidate_id": candidate_id,
            "skill_id": manifest.id,
            "artifact": str(path),
            "artifact_sha256": artifact_sha256,
            "manifest_sha256": actual,
            "manifest_checksum_matches": expected == actual,
            "static_scan_ok": static_scan["ok"],
            "candidate_integrity_ok": ok,
            "raw_candidate_payload_included": False,
            "raw_secret_values_included": False,
            "verified_at": now_utc(),
        }
        self.audit_logger.append("skill.curator_candidate_verified", redact(receipt))
        return {
            "ok": ok,
            "status": "skill_candidate_verified" if ok else "skill_candidate_verification_failed",
            "candidate_id": candidate_id,
            "skill_id": manifest.id,
            "receipt": receipt,
            "static_scan": static_scan,
            "raw_secret_values_included": False,
        }

    def install_candidate(self, candidate_id: str, *, actor: str = "operator", approved: bool = False) -> dict[str, Any]:
        if not approved:
            result = {
                "status": "approval_required",
                "candidate_id": candidate_id,
                "reason": "skill draft installation requires explicit approval",
                "approval_required": True,
                "auto_enable": False,
                "raw_secret_values_included": False,
            }
            self.audit_logger.append("skill.curator_candidate_install_blocked", redact(result))
            return result
        verified = self.verify_candidate(candidate_id)
        if not verified["ok"]:
            raise ValueError("skill candidate verification failed")
        payload = self._read_candidate(candidate_id)
        manifest = SkillManifest.from_dict(payload.get("manifest") if isinstance(payload.get("manifest"), dict) else {}).validate()
        registered = self.skills.register(manifest, enable=False, require_signature=False)
        payload["status"] = "installed_disabled"
        payload["approved_for_install"] = True
        payload["installed_at"] = now_utc()
        payload["installed_by"] = _safe_actor(actor)
        _write_private_json(self._candidate_path(candidate_id), payload)
        receipt = {
            "receipt_schema": "aegis.skill.curator_candidate_install.v1",
            "event_type": "skill.curator_candidate_installed",
            "candidate_id": candidate_id,
            "skill_id": registered.id,
            "actor": _safe_actor(actor),
            "installed_enabled": False,
            "manifest_sha256": _stable_json_sha256(registered.to_dict()),
            "verification_receipt_sha256": _stable_json_sha256(verified["receipt"]),
            "raw_candidate_payload_included": False,
            "raw_secret_values_included": False,
            "installed_at": payload["installed_at"],
        }
        self.audit_logger.append("skill.curator_candidate_installed", redact(receipt))
        return {
            "ok": True,
            "status": "skill_candidate_installed_disabled",
            "candidate_id": candidate_id,
            "skill_id": registered.id,
            "receipt": receipt,
            "enable_command": f"skills enable {registered.id}",
            "auto_enable": False,
            "raw_secret_values_included": False,
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

    def _candidate_records(self) -> list[dict[str, Any]]:
        directory = self.path.parent / "skill-candidates"
        if not directory.exists():
            return []
        records: list[dict[str, Any]] = []
        for path in sorted(directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict) or payload.get("candidate_schema") != "aegis.skill.curator_candidate.v1":
                continue
            records.append(
                {
                    "candidate_id": str(payload.get("candidate_id") or path.stem),
                    "skill_id": str(payload.get("skill_id") or ""),
                    "status": str(payload.get("status") or "unknown"),
                    "created_at": str(payload.get("created_at") or ""),
                    "manifest_sha256": str(payload.get("manifest_sha256") or ""),
                    "approved_for_install": bool(payload.get("approved_for_install", False)),
                    "observed_task_included": payload.get("observed_task_included") is True,
                    "raw_secret_values_included": False,
                }
            )
        return sorted(records, key=lambda record: (record["created_at"], record["candidate_id"]), reverse=True)

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

    def _candidate_dir(self) -> Path:
        return ensure_private_dir(self.path.parent / "skill-candidates")

    def _candidate_path(self, candidate_id: str) -> Path:
        normalized = str(candidate_id or "").strip()
        if not normalized or not all(char.isalnum() or char in {"-", "_"} for char in normalized):
            raise ValueError("invalid skill candidate id")
        return ensure_private_file(self._candidate_dir() / f"{normalized}.json")

    def _read_candidate(self, candidate_id: str) -> dict[str, Any]:
        path = self._candidate_path(candidate_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("skill candidate must be valid JSON") from exc
        if not isinstance(raw, dict):
            raise ValueError("skill candidate must be a JSON object")
        return raw


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
        "unapproved_skill_install",
        "raw_secret_capture",
        "unbounded_llm_self_mutation",
    ]


def _safe_actor(value: str, *, limit: int = 80) -> str:
    normalized = " ".join(str(value or "operator").split())
    return (normalized or "operator")[:limit]


def _stable_json_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_private_file(path)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ensure_private_file(path)


def _candidate_receipt(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "receipt_schema": "aegis.skill.curator_candidate.v1",
        "event_type": "skill.curator_candidate_drafted",
        "candidate_id": payload["candidate_id"],
        "skill_id": payload["skill_id"],
        "actor": payload["actor"],
        "artifact": str(path),
        "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "manifest_sha256": payload["manifest_sha256"],
        "static_scan_ok": bool(payload.get("static_scan", {}).get("ok")),
        "observed_task_included": False,
        "raw_candidate_payload_included": False,
        "raw_secret_values_included": False,
        "created_at": payload["created_at"],
    }
