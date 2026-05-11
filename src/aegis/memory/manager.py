"""Governed memory CRUD, retrieval, conflict checks, and safety gates."""

from __future__ import annotations

import json
import hashlib
import math
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.memory.candidates import MemoryCandidate, candidate_to_create_kwargs
from aegis.memory.models import MemoryRecord, MemoryType
from aegis.memory.store import LocalStore, STOPWORDS
from aegis.security.context_firewall import redact_secret_values
from aegis.security.taint import Sensitivity, TrustClass, now_utc


SECRET_LIKE = re.compile(
    r"(api[_ -]?key|secret|password|refresh[_ -]?token|ssh[-_ ]?private|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.I,
)
EMBEDDING_MODEL = "aegis-local-hash-v1"
SEMANTIC_ALIASES = {
    "bug": "defect",
    "bugs": "defect",
    "failure": "defect",
    "failures": "defect",
    "error": "defect",
    "errors": "defect",
    "crash": "defect",
    "crashes": "defect",
    "repair": "fix",
    "repairs": "fix",
    "fixed": "fix",
    "resolve": "fix",
    "resolved": "fix",
    "resolution": "fix",
    "paraphrase": "semantic",
    "similar": "semantic",
    "meaning": "semantic",
    "recall": "retrieve",
    "retrieval": "retrieve",
    "remember": "memory",
    "remembered": "memory",
    "durable": "persistent",
    "persisted": "persistent",
    "database": "sqlite",
    "db": "sqlite",
}


class MemorySafetyError(ValueError):
    pass


class MemoryManager:
    def __init__(
        self,
        store: LocalStore,
        audit_logger: AuditLogger,
        *,
        default_ttl_days: int | None = None,
        ttl_days_by_type: dict[str, int] | None = None,
        default_recertification_days: int | None = 90,
        recertification_days_by_type: dict[str, int | None] | None = None,
        escalation_routes: dict[str, dict[str, object]] | None = None,
    ) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.default_ttl_days = _positive_ttl(default_ttl_days)
        self.ttl_days_by_type = {str(key): int(value) for key, value in (ttl_days_by_type or {}).items() if _positive_ttl(value) is not None}
        self.default_recertification_days = _positive_ttl(default_recertification_days)
        self.recertification_days_by_type = {str(key): _positive_ttl(value) for key, value in (recertification_days_by_type or {}).items()}
        self.escalation_routes = _normalize_escalation_routes(escalation_routes or {})

    def create_memory(
        self,
        *,
        memory_type: MemoryType,
        content: str,
        source: str,
        provenance: dict[str, Any],
        confidence: float,
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
        owner: str = "local-user",
        scope: str = "workspace",
        tags: tuple[str, ...] = (),
        confirmed: bool = False,
        ttl_days: int | None = None,
    ) -> MemoryRecord:
        if SECRET_LIKE.search(content):
            raise MemorySafetyError("refusing to store secret-like content as normal memory")
        if sensitivity in {Sensitivity.CONFIDENTIAL, Sensitivity.SECRET} and not confirmed:
            raise MemorySafetyError("sensitive memory requires explicit confirmation")
        if confidence < 0.5 and not confirmed:
            raise MemorySafetyError("uncertain memory requires confirmation before storage")
        summary = summarize(content)
        record = MemoryRecord(
            type=memory_type,
            content=content,
            summary=summary,
            source=source,
            provenance=provenance,
            confidence=max(0.0, min(confidence, 1.0)),
            sensitivity=sensitivity,
            owner=owner,
            scope=scope,
            tags=tags,
            last_confirmed_at=now_utc() if confirmed else None,
            expires_at=self._expires_at(memory_type, ttl_days=ttl_days),
        )
        self.store.insert_memory(record.to_row())
        self.store.upsert_memory_embedding(record.id, embedding=local_embedding(record.content, tags=record.tags), model=EMBEDDING_MODEL)
        self.audit_logger.append(
            "memory.created",
            {
                "memory_id": record.id,
                "type": record.type.value,
                "source": record.source,
                "confidence": record.confidence,
                "sensitivity": record.sensitivity.value,
                "expires_at": record.expires_at,
                "provenance": provenance,
            },
        )
        return record

    def create_from_candidate(self, candidate: dict[str, Any], *, confirmed: bool = False, reviewer: str = "local-user") -> MemoryRecord:
        parsed = MemoryCandidate.from_dict(candidate)
        record = self.create_memory(**candidate_to_create_kwargs(parsed, confirmed=confirmed, reviewer=reviewer))
        self.audit_logger.append(
            "memory.candidate_committed",
            {
                "memory_id": record.id,
                "candidate_id": parsed.id,
                "source": parsed.source,
                "owner": parsed.owner,
                "scope": parsed.scope,
                "confirmed": confirmed,
                "reviewer": reviewer,
            },
        )
        return record

    def retention_policy(self) -> dict[str, Any]:
        return {
            "default_ttl_days": self.default_ttl_days,
            "ttl_days_by_type": dict(sorted(self.ttl_days_by_type.items())),
            "default_recertification_days": self.default_recertification_days,
            "recertification_days_by_type": dict(sorted(self.recertification_days_by_type.items())),
            "escalation_routes": dict(sorted(self.escalation_routes.items())),
            "default": "indefinite" if self.default_ttl_days is None else f"{self.default_ttl_days} days",
        }

    def preview_session_memory_candidates(
        self,
        *,
        session_id: str,
        messages: list[dict[str, Any]],
        owner: str = "local-user",
        scope: str = "workspace",
        limit: int = 25,
    ) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for message in messages:
            if len(candidates) >= limit:
                break
            if message.get("role") != "user":
                continue
            message_id = str(message.get("id") or "")
            trust_class = str(message.get("trust_class") or TrustClass.UNKNOWN_UNTRUSTED.value)
            if trust_class != TrustClass.USER_DIRECTIVE.value:
                skipped.append({"message_id": message_id, "reason": "untrusted_session_turn", "trust_class": trust_class})
                continue
            for text in _extract_session_memory_statements(str(message.get("content") or "")):
                if len(candidates) >= limit:
                    break
                candidate = _session_memory_candidate(
                    text,
                    session_id=session_id,
                    message_id=message_id,
                    owner=owner,
                    scope=scope,
                    trust_class=trust_class,
                )
                if candidate["blocked"]:
                    blocked.append(candidate)
                else:
                    candidates.append(candidate)
        result = {
            "session_id": session_id,
            "mode": "dry_run_session_memory_preview",
            "candidate_count": len(candidates),
            "blocked_count": len(blocked),
            "skipped_count": len(skipped),
            "candidates": candidates,
            "blocked": blocked,
            "skipped": skipped,
            "persistence": "not_persisted_requires_memory_create_or_review_action",
        }
        self.audit_logger.append(
            "memory.session_previewed",
            {
                "session_id": session_id,
                "candidate_count": len(candidates),
                "blocked_count": len(blocked),
                "skipped_count": len(skipped),
                "owner": owner,
                "scope": scope,
            },
        )
        return result

    def commit_session_memory_candidates(
        self,
        *,
        session_id: str,
        messages: list[dict[str, Any]],
        owner: str = "local-user",
        scope: str = "workspace",
        limit: int = 25,
        candidate_ids: list[str] | None = None,
        confirmed: bool = False,
    ) -> dict[str, Any]:
        preview = self.preview_session_memory_candidates(
            session_id=session_id,
            messages=messages,
            owner=owner,
            scope=scope,
            limit=limit,
        )
        selected = set(candidate_ids) if candidate_ids is not None else None
        committed: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for candidate in preview["candidates"]:
            if selected is not None and candidate["id"] not in selected:
                skipped.append({"candidate_id": candidate["id"], "reason": "not_selected"})
                continue
            record = self.create_from_candidate(candidate, confirmed=confirmed)
            committed.append(record.to_row())
        for blocked in preview["blocked"]:
            if selected is None or blocked["id"] in selected:
                skipped.append({"candidate_id": blocked["id"], "reason": blocked.get("reason", "blocked")})
        result = {
            "session_id": session_id,
            "mode": "session_memory_commit",
            "committed_count": len(committed),
            "skipped_count": len(skipped),
            "blocked_count": preview["blocked_count"],
            "candidate_count": preview["candidate_count"],
            "confirmed": confirmed,
            "memories": committed,
            "skipped": skipped,
        }
        self.audit_logger.append(
            "memory.session_candidates_committed",
            {
                "session_id": session_id,
                "committed_count": len(committed),
                "skipped_count": len(skipped),
                "blocked_count": preview["blocked_count"],
                "owner": owner,
                "scope": scope,
                "confirmed": confirmed,
            },
        )
        return result

    def commit_preview_candidates(
        self,
        preview: dict[str, Any],
        *,
        candidate_ids: list[str] | None = None,
        confirmed: bool = False,
        reviewer: str = "local-user",
    ) -> dict[str, Any]:
        selected = set(candidate_ids) if candidate_ids is not None else None
        candidates = preview.get("candidates", [])
        blocked = preview.get("blocked", [])
        if not isinstance(candidates, list) or not isinstance(blocked, list):
            raise ValueError("memory preview payload must include candidate and blocked lists")
        committed: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                skipped.append({"candidate_id": "", "reason": "invalid_candidate_shape"})
                continue
            if selected is not None and candidate.get("id") not in selected:
                skipped.append({"candidate_id": str(candidate.get("id", "")), "reason": "not_selected"})
                continue
            record = self.create_from_candidate(candidate, confirmed=confirmed, reviewer=reviewer)
            committed.append(record.to_row())
        for item in blocked:
            if isinstance(item, dict) and (selected is None or item.get("id") in selected):
                skipped.append({"candidate_id": str(item.get("id", item.get("path", ""))), "reason": str(item.get("reason", "blocked"))})
        result = {
            "mode": "memory_preview_commit",
            "platform": preview.get("platform"),
            "root": preview.get("root"),
            "committed_count": len(committed),
            "skipped_count": len(skipped),
            "blocked_count": int(preview.get("blocked_count", len(blocked)) or 0),
            "candidate_count": int(preview.get("candidate_count", len(candidates)) or 0),
            "confirmed": confirmed,
            "memories": committed,
            "skipped": skipped,
        }
        self.audit_logger.append(
            "memory.preview_candidates_committed",
            {
                "platform": preview.get("platform"),
                "committed_count": len(committed),
                "skipped_count": len(skipped),
                "blocked_count": result["blocked_count"],
                "confirmed": confirmed,
                "reviewer": reviewer,
            },
        )
        return result

    def retrieve_relevant(self, query: str, *, limit: int = 10, owner: str = "local-user", scope: str | None = "workspace") -> list[dict[str, Any]]:
        rows = self.store.search_memories(query, limit=limit, owner=owner, scope=scope)
        ranked = self._semantic_rerank(query, rows, limit=limit, owner=owner, scope=scope)
        self.audit_logger.append("memory.retrieved", {"query": query, "count": len(ranked), "owner": owner, "scope": scope, "mode": "lexical_semantic"})
        return [decode_memory_row(row) for row in ranked]

    def unresolved_conflicts(
        self,
        query: str,
        *,
        limit: int = 5,
        owner: str = "local-user",
        scope: str | None = "workspace",
    ) -> list[dict[str, Any]]:
        rows = self.store.search_memories(query, limit=50, owner=owner, scope=scope)
        decoded = [decode_memory_row(row) for row in rows]
        conflicts: list[dict[str, Any]] = []
        for index, primary in enumerate(decoded):
            if "conflict-reviewed" in set(primary.get("tags", [])):
                continue
            primary_terms = _memory_terms(str(primary.get("content", "")))
            for conflicting in decoded[index + 1 :]:
                if "conflict-reviewed" in set(conflicting.get("tags", [])):
                    continue
                if primary.get("id") == conflicting.get("id"):
                    continue
                shared_terms = sorted(primary_terms & _memory_terms(str(conflicting.get("content", ""))))
                if len(shared_terms) < 3:
                    continue
                if str(primary.get("content", "")).strip().lower() == str(conflicting.get("content", "")).strip().lower():
                    continue
                conflicts.append(
                    {
                        "primary_id": primary["id"],
                        "conflicting_id": conflicting["id"],
                        "primary_summary": primary["summary"],
                        "conflicting_summary": conflicting["summary"],
                        "conflict_score": len(shared_terms),
                        "shared_terms": shared_terms[:12],
                    }
                )
                if len(conflicts) >= limit:
                    self.audit_logger.append("memory.conflicts_surfaced", {"query": query, "count": len(conflicts), "owner": owner, "scope": scope})
                    return conflicts
        if conflicts:
            self.audit_logger.append("memory.conflicts_surfaced", {"query": query, "count": len(conflicts), "owner": owner, "scope": scope})
        return conflicts

    def review_queue(
        self,
        *,
        limit: int = 50,
        owner: str = "local-user",
        scope: str | None = "workspace",
        log_empty: bool = True,
    ) -> dict[str, Any]:
        rows = self.store.search_memories("%", limit=500, owner=owner, scope=scope)
        memories = [decode_memory_row(row) for row in rows]
        items: list[dict[str, Any]] = []
        seen_conflicts: set[tuple[str, str]] = set()
        for index, primary in enumerate(memories):
            primary_tags = set(primary.get("tags", []))
            if "conflict-reviewed" not in primary_tags:
                primary_terms = _memory_terms(str(primary.get("content", "")))
                for conflicting in memories[index + 1 :]:
                    if "conflict-reviewed" in set(conflicting.get("tags", [])):
                        continue
                    shared_terms = sorted(primary_terms & _memory_terms(str(conflicting.get("content", ""))))
                    if len(shared_terms) < 3:
                        continue
                    if str(primary.get("content", "")).strip().lower() == str(conflicting.get("content", "")).strip().lower():
                        continue
                    key = tuple(sorted((str(primary["id"]), str(conflicting["id"]))))
                    if key in seen_conflicts:
                        continue
                    seen_conflicts.add(key)
                    items.append(
                        {
                            "kind": "unresolved_conflict",
                            "severity": "high",
                            "primary_id": primary["id"],
                            "conflicting_id": conflicting["id"],
                            "primary_summary": primary["summary"],
                            "conflicting_summary": conflicting["summary"],
                            "conflict_score": len(shared_terms),
                            "shared_terms": shared_terms[:12],
                            "action": "resolve-conflict",
                        }
                    )
            confidence = float(primary.get("confidence", 0.0))
            recertification_due = "recertification-due" in primary_tags
            if confidence < 0.7 or not primary.get("last_confirmed_at") or recertification_due:
                reasons: list[str] = []
                if confidence < 0.7:
                    reasons.append("low_confidence")
                if not primary.get("last_confirmed_at"):
                    reasons.append("unconfirmed")
                if recertification_due:
                    reasons.append("stale_confirmation")
                items.append(
                    {
                        "kind": "memory_review",
                        "severity": "medium" if confidence >= 0.5 else "high",
                        "memory_id": primary["id"],
                        "summary": primary["summary"],
                        "confidence": confidence,
                        "reasons": reasons,
                        "action": "update --confirmed or delete",
                    }
                )
        items.sort(key=lambda item: (_review_severity_rank(str(item["severity"])), int(item.get("conflict_score", 0))), reverse=True)
        result = {"items": items[:limit], "count": min(len(items), limit), "total": len(items), "owner": owner, "scope": scope}
        self.audit_logger.append("memory.review_queue_listed", {"count": result["count"], "total": result["total"], "owner": owner, "scope": scope})
        return result

    def review_digest(
        self,
        *,
        limit: int = 10,
        owner: str = "local-user",
        scope: str | None = "workspace",
    ) -> dict[str, Any]:
        queue = self.review_queue(limit=max(limit, 50), owner=owner, scope=scope, log_empty=False)
        items = list(queue["items"])
        severity_counts = Counter(str(item.get("severity", "unknown")) for item in items)
        kind_counts = Counter(str(item.get("kind", "unknown")) for item in items)
        reason_counts: Counter[str] = Counter()
        for item in items:
            for reason in item.get("reasons", []) or []:
                reason_counts[str(reason)] += 1
        top_items = [_digest_item(item) for item in items[:limit]]
        result = {
            "ok": True,
            "generated_at": now_utc(),
            "owner": owner,
            "scope": scope,
            "total": queue["total"],
            "included": len(top_items),
            "severity_counts": dict(sorted(severity_counts.items())),
            "kind_counts": dict(sorted(kind_counts.items())),
            "reason_counts": dict(sorted(reason_counts.items())),
            "top_items": top_items,
            "next_actions": _digest_next_actions(kind_counts, reason_counts),
        }
        self.audit_logger.append(
            "memory.review_digest_generated",
            {
                "total": result["total"],
                "included": result["included"],
                "severity_counts": result["severity_counts"],
                "kind_counts": result["kind_counts"],
                "reason_counts": result["reason_counts"],
                "owner": owner,
                "scope": scope,
            },
        )
        return result

    def review_escalation(
        self,
        *,
        max_age_days: int = 7,
        limit: int = 10,
        owner: str = "local-user",
        scope: str | None = "workspace",
        route: str = "operator",
    ) -> dict[str, Any]:
        route_policy = self.escalation_routes.get(str(route), {})
        policy_applied = bool(route_policy)
        age_days = _positive_ttl(route_policy.get("max_age_days") if int(max_age_days) == 7 and route_policy.get("max_age_days") is not None else max_age_days)
        if age_days is None:
            raise ValueError("max_age_days must be positive")
        effective_limit = int(route_policy.get("limit")) if int(limit) == 10 and route_policy.get("limit") is not None else int(limit)
        effective_scope = str(route_policy.get("scope")) if scope == "workspace" and route_policy.get("scope") is not None else scope
        cutoff = datetime.now(UTC) - timedelta(days=age_days)
        queue = self.review_queue(limit=max(effective_limit, 500), owner=owner, scope=effective_scope, log_empty=False)
        overdue: list[dict[str, Any]] = []
        for item in queue["items"]:
            aged_item = self._review_item_with_age(item, cutoff=cutoff)
            if aged_item is not None:
                overdue.append(aged_item)
            if len(overdue) >= effective_limit:
                break
        result = {
            "ok": True,
            "generated_at": now_utc(),
            "owner": owner,
            "scope": effective_scope,
            "route": summarize(route, limit=80),
            "route_policy_applied": policy_applied,
            "route_policy": dict(route_policy),
            "max_age_days": age_days,
            "limit": effective_limit,
            "cutoff": cutoff.isoformat(),
            "total_review_items": queue["total"],
            "overdue": len(overdue),
            "items": overdue,
            "message": _escalation_message(overdue, route=summarize(route, limit=80), max_age_days=age_days),
            "next_actions": _escalation_next_actions(overdue),
        }
        self.audit_logger.append(
            "memory.review_escalation_generated",
            {
                "route": result["route"],
                "max_age_days": age_days,
                "total_review_items": queue["total"],
                "overdue": result["overdue"],
                "owner": owner,
                "scope": effective_scope,
                "route_policy_applied": policy_applied,
            },
        )
        return result

    def update_memory(self, memory_id: str, *, content: str | None = None, confidence: float | None = None, confirmed: bool = False) -> dict[str, Any]:
        changes: dict[str, Any] = {}
        if content is not None:
            if SECRET_LIKE.search(content):
                raise MemorySafetyError("refusing to store secret-like content as normal memory")
            changes["content"] = content
            changes["summary"] = summarize(content)
            changes["search_text"] = content.lower()
        if confidence is not None:
            changes["confidence"] = max(0.0, min(confidence, 1.0))
        if confirmed:
            changes["last_confirmed_at"] = now_utc()
        updated = decode_memory_row(self.store.update_memory(memory_id, changes))
        if content is not None:
            self.store.upsert_memory_embedding(memory_id, embedding=local_embedding(updated["content"], tags=tuple(updated["tags"])), model=EMBEDDING_MODEL)
        self.audit_logger.append("memory.updated", {"memory_id": memory_id, "changes": sorted(changes)})
        return updated

    def review_memory(
        self,
        memory_id: str,
        *,
        action: str,
        confidence: float | None = None,
        rationale: str = "",
    ) -> dict[str, Any]:
        row = self.store.get_memory(memory_id)
        if not row:
            raise KeyError(memory_id)
        if action not in {"confirm", "delete"}:
            raise ValueError("invalid memory review action")
        if SECRET_LIKE.search(rationale):
            raise MemorySafetyError("refusing to store secret-like memory review rationale")
        if action == "delete":
            self.delete_memory(memory_id)
            result = {"ok": True, "action": action, "memory_id": memory_id, "deleted": True}
            self.audit_logger.append("memory.review_action", {"memory_id": memory_id, "action": action, "rationale": summarize(rationale, limit=160)})
            return result

        decoded = decode_memory_row(row)
        next_confidence = max(float(decoded["confidence"]), 0.7)
        if confidence is not None:
            next_confidence = max(0.0, min(confidence, 1.0))
        updated = self.update_memory(memory_id, confidence=next_confidence, confirmed=True)
        if "recertification-due" in set(updated.get("tags", [])):
            tags = sorted(set(updated["tags"]) - {"recertification-due"})
            updated = decode_memory_row(self.store.update_memory(memory_id, {"tags_json": json.dumps(tags)}))
        self.audit_logger.append(
            "memory.review_action",
            {"memory_id": memory_id, "action": action, "confidence": next_confidence, "rationale": summarize(rationale, limit=160)},
        )
        return {"ok": True, "action": action, "memory": updated}

    def review_memory_batch(
        self,
        memory_ids: list[str],
        *,
        action: str,
        confidence: float | None = None,
        rationale: str = "",
    ) -> dict[str, Any]:
        if action not in {"confirm", "delete"}:
            raise ValueError("invalid memory review action")
        if SECRET_LIKE.search(rationale):
            raise MemorySafetyError("refusing to store secret-like memory review rationale")
        results: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for memory_id in memory_ids:
            try:
                results.append(self.review_memory(memory_id, action=action, confidence=confidence, rationale=rationale))
            except KeyError:
                errors.append({"memory_id": memory_id, "error": "not_found"})
        summary = {
            "ok": not errors,
            "action": action,
            "requested": len(memory_ids),
            "succeeded": len(results),
            "failed": len(errors),
            "results": results,
            "errors": errors,
        }
        self.audit_logger.append(
            "memory.review_batch",
            {
                "action": action,
                "requested": len(memory_ids),
                "succeeded": len(results),
                "failed": len(errors),
                "memory_ids": [result.get("memory_id") or result.get("memory", {}).get("id") for result in results],
                "rationale": summarize(rationale, limit=160),
            },
        )
        return summary

    def delete_memory(self, memory_id: str) -> None:
        self.store.update_memory(memory_id, {"deleted": 1})
        self.audit_logger.append("memory.deleted", {"memory_id": memory_id})

    def expire_memory(self, memory_id: str) -> dict[str, Any]:
        expired = decode_memory_row(self.store.update_memory(memory_id, {"expires_at": now_utc(), "deleted": 1}))
        self.audit_logger.append("memory.expired", {"memory_id": memory_id})
        return expired

    def cleanup_expired(self, *, log_empty: bool = True) -> dict[str, Any]:
        expired_ids = self.store.mark_expired_memories_deleted()
        result = {"ok": True, "expired": len(expired_ids), "memory_ids": expired_ids}
        if expired_ids or log_empty:
            self.audit_logger.append("memory.cleanup_expired", result)
        return result

    def recertify_due(
        self,
        *,
        max_age_days: int | None = None,
        limit: int = 50,
        owner: str = "local-user",
        scope: str | None = "workspace",
        dry_run: bool = False,
        log_empty: bool = True,
    ) -> dict[str, Any]:
        override_age = _positive_ttl(max_age_days) if max_age_days is not None else None
        if max_age_days is not None and override_age is None:
            raise ValueError("max_age_days must be positive")
        now = datetime.now(UTC)
        rows = self.store.search_memories("%", limit=1000, owner=owner, scope=scope)
        marked: list[dict[str, Any]] = []
        cutoffs: dict[str, str] = {}
        for row in rows:
            decoded = decode_memory_row(row)
            tags = set(decoded.get("tags", []))
            if "recertification-due" in tags:
                continue
            memory_type = str(decoded.get("type", ""))
            max_age = override_age if override_age is not None else self.recertification_days_by_type.get(memory_type, self.default_recertification_days)
            if max_age is None:
                continue
            cutoff = now - timedelta(days=max_age)
            cutoffs[memory_type] = cutoff.isoformat()
            confirmed_at = _parse_datetime(decoded.get("last_confirmed_at"))
            if confirmed_at is None or confirmed_at > cutoff:
                continue
            if dry_run:
                updated = decoded
            else:
                next_tags = sorted(tags | {"recertification-due"})
                updated = decode_memory_row(self.store.update_memory(decoded["id"], {"tags_json": json.dumps(next_tags)}))
            marked.append(
                {
                    "memory_id": updated["id"],
                    "summary": updated["summary"],
                    "type": updated["type"],
                    "last_confirmed_at": updated["last_confirmed_at"],
                    "max_age_days": max_age,
                }
            )
            if len(marked) >= limit:
                break
        result = {
            "ok": True,
            "marked": len(marked),
            "memory_ids": [item["memory_id"] for item in marked],
            "items": marked,
            "max_age_days": override_age,
            "policy": "override" if override_age is not None else "configured",
            "dry_run": dry_run,
            "recertification_policy": self.recertification_policy(),
            "cutoff_by_type": dict(sorted(cutoffs.items())),
            "owner": owner,
            "scope": scope,
        }
        if marked or log_empty:
            self.audit_logger.append(
                "memory.recertification_previewed" if dry_run else "memory.recertification_marked",
                {
                    "marked": result["marked"],
                    "memory_ids": result["memory_ids"],
                    "max_age_days": override_age,
                    "policy": result["policy"],
                    "dry_run": dry_run,
                    "cutoff_by_type": result["cutoff_by_type"],
                    "owner": owner,
                    "scope": scope,
                },
            )
        return result

    def recertification_policy(self) -> dict[str, Any]:
        return {
            "default_recertification_days": self.default_recertification_days,
            "recertification_days_by_type": dict(sorted(self.recertification_days_by_type.items())),
            "default": "disabled" if self.default_recertification_days is None else f"{self.default_recertification_days} days",
        }

    def merge_duplicate(self, primary_id: str, duplicate_id: str) -> dict[str, Any]:
        primary = self.store.get_memory(primary_id)
        duplicate = self.store.get_memory(duplicate_id)
        if not primary or not duplicate:
            raise KeyError("primary or duplicate memory not found")
        primary_decoded = decode_memory_row(primary)
        duplicate_decoded = decode_memory_row(duplicate)
        merged_tags = sorted(set(primary_decoded["tags"]) | set(duplicate_decoded["tags"]))
        merged_content = primary_decoded["content"]
        if duplicate_decoded["content"] not in merged_content:
            merged_content = f"{merged_content}\n\nMerged duplicate note: {duplicate_decoded['content']}"
        updated = self.store.update_memory(
            primary_id,
            {
                "content": merged_content,
                "summary": summarize(merged_content),
                "tags_json": json.dumps(merged_tags),
                "search_text": " ".join([merged_content, " ".join(merged_tags)]).lower(),
                "confidence": max(primary_decoded["confidence"], duplicate_decoded["confidence"]),
            },
        )
        self.store.upsert_memory_embedding(primary_id, embedding=local_embedding(merged_content, tags=tuple(merged_tags)), model=EMBEDDING_MODEL)
        self.store.update_memory(duplicate_id, {"deleted": 1})
        self.audit_logger.append("memory.merged", {"primary_id": primary_id, "duplicate_id": duplicate_id})
        return decode_memory_row(updated)

    def resolve_conflict(
        self,
        primary_id: str,
        conflicting_id: str,
        *,
        strategy: str,
        rationale: str,
    ) -> dict[str, Any]:
        if strategy not in {"keep_primary", "keep_conflicting", "synthesize", "keep_both"}:
            raise ValueError("invalid memory conflict resolution strategy")
        primary = self.store.get_memory(primary_id)
        conflicting = self.store.get_memory(conflicting_id)
        if not primary or not conflicting:
            raise KeyError("primary or conflicting memory not found")
        primary_decoded = decode_memory_row(primary)
        conflicting_decoded = decode_memory_row(conflicting)
        rationale_text = summarize(rationale or f"Resolved conflict with strategy {strategy}.", limit=240)
        if SECRET_LIKE.search(rationale_text):
            raise MemorySafetyError("refusing to store secret-like conflict rationale")

        if strategy == "keep_primary":
            resolved = self._mark_conflict_resolution(
                primary_decoded,
                conflicting_decoded,
                kept_id=primary_id,
                retired_id=conflicting_id,
                rationale=rationale_text,
            )
        elif strategy == "keep_conflicting":
            resolved = self._mark_conflict_resolution(
                conflicting_decoded,
                primary_decoded,
                kept_id=conflicting_id,
                retired_id=primary_id,
                rationale=rationale_text,
            )
        elif strategy == "synthesize":
            resolved = self._synthesize_conflict(primary_decoded, conflicting_decoded, rationale=rationale_text)
        else:
            resolved = {
                "primary": self._tag_conflict_reviewed(primary_decoded, rationale=rationale_text),
                "conflicting": self._tag_conflict_reviewed(conflicting_decoded, rationale=rationale_text),
            }

        self.audit_logger.append(
            "memory.conflict_resolved",
            {
                "primary_id": primary_id,
                "conflicting_id": conflicting_id,
                "strategy": strategy,
                "rationale": rationale_text,
                "resolved_ids": _resolved_memory_ids(resolved),
            },
        )
        return {"ok": True, "strategy": strategy, "rationale": rationale_text, "resolution": resolved}

    def export_memory(self, query: str = "") -> list[dict[str, Any]]:
        rows = self.store.search_memories(query or "%", limit=1000)
        self.audit_logger.append("memory.exported", {"query": query, "count": len(rows)})
        return [decode_memory_row(row) for row in rows]

    def explain_usage(self, memory_id: str, query: str) -> str:
        row = self.store.get_memory(memory_id)
        if not row:
            raise KeyError(memory_id)
        decoded = decode_memory_row(row)
        tags = ", ".join(decoded["tags"]) or "no tags"
        return (
            f"Memory {memory_id} was considered for query {query!r} because its "
            f"summary/source/tags matched retrieval text. Source={decoded['source']}; "
            f"confidence={decoded['confidence']}; tags={tags}."
        )

    def detect_conflicts(self, candidate_content: str, *, scope: str = "workspace") -> list[dict[str, Any]]:
        rows = self.store.search_memories(scope, limit=100, scope=scope)
        conflicts: list[dict[str, Any]] = []
        candidate_terms = _memory_terms(candidate_content)
        for row in rows:
            if row["scope"] != scope:
                continue
            existing_terms = _memory_terms(str(row["content"]))
            overlap = len(candidate_terms & existing_terms)
            if overlap >= 3 and candidate_content.strip().lower() != str(row["content"]).strip().lower():
                decoded = decode_memory_row(row)
                decoded["conflict_score"] = overlap
                decoded["shared_terms"] = sorted(candidate_terms & existing_terms)[:12]
                conflicts.append(decoded)
        return conflicts

    def _mark_conflict_resolution(
        self,
        kept: dict[str, Any],
        retired: dict[str, Any],
        *,
        kept_id: str,
        retired_id: str,
        rationale: str,
    ) -> dict[str, Any]:
        kept_tags = sorted(set(kept["tags"]) | {"conflict-reviewed", "conflict-winner"})
        kept_content = kept["content"]
        note = f"Conflict resolution: kept over {retired_id}. Rationale: {rationale}"
        if note not in kept_content:
            kept_content = f"{kept_content}\n\n{note}"
        updated = self.store.update_memory(
            kept_id,
            {
                "content": kept_content,
                "summary": summarize(kept_content),
                "tags_json": json.dumps(kept_tags),
                "search_text": " ".join([kept_content, " ".join(kept_tags)]).lower(),
                "confidence": max(float(kept["confidence"]), float(retired["confidence"])),
                "last_confirmed_at": now_utc(),
            },
        )
        self.store.upsert_memory_embedding(kept_id, embedding=local_embedding(kept_content, tags=tuple(kept_tags)), model=EMBEDDING_MODEL)
        retired_tags = sorted(set(retired["tags"]) | {"conflict-reviewed", "conflict-retired"})
        self.store.update_memory(retired_id, {"tags_json": json.dumps(retired_tags), "deleted": 1})
        return {"kept": decode_memory_row(updated), "retired_id": retired_id}

    def _synthesize_conflict(self, primary: dict[str, Any], conflicting: dict[str, Any], *, rationale: str) -> dict[str, Any]:
        tags = sorted(set(primary["tags"]) | set(conflicting["tags"]) | {"conflict-reviewed", "conflict-synthesized"})
        content = "\n\n".join(
            [
                primary["content"],
                f"Resolved conflicting memory {conflicting['id']}: {conflicting['content']}",
                f"Resolution rationale: {rationale}",
            ]
        )
        updated = self.store.update_memory(
            primary["id"],
            {
                "content": content,
                "summary": summarize(content),
                "tags_json": json.dumps(tags),
                "search_text": " ".join([content, " ".join(tags)]).lower(),
                "confidence": max(float(primary["confidence"]), float(conflicting["confidence"])),
                "last_confirmed_at": now_utc(),
            },
        )
        self.store.upsert_memory_embedding(primary["id"], embedding=local_embedding(content, tags=tuple(tags)), model=EMBEDDING_MODEL)
        self.store.update_memory(conflicting["id"], {"deleted": 1})
        return {"synthesized": decode_memory_row(updated), "retired_id": conflicting["id"]}

    def _tag_conflict_reviewed(self, memory: dict[str, Any], *, rationale: str) -> dict[str, Any]:
        tags = sorted(set(memory["tags"]) | {"conflict-reviewed", "kept-with-conflict"})
        content = memory["content"]
        note = f"Conflict review: kept alongside another memory. Rationale: {rationale}"
        if note not in content:
            content = f"{content}\n\n{note}"
        updated = self.store.update_memory(
            memory["id"],
            {
                "content": content,
                "summary": summarize(content),
                "tags_json": json.dumps(tags),
                "search_text": " ".join([content, " ".join(tags)]).lower(),
                "last_confirmed_at": now_utc(),
            },
        )
        self.store.upsert_memory_embedding(memory["id"], embedding=local_embedding(content, tags=tuple(tags)), model=EMBEDDING_MODEL)
        return decode_memory_row(updated)

    def _semantic_rerank(
        self,
        query: str,
        lexical_rows: list[dict[str, Any]],
        *,
        limit: int,
        owner: str | None,
        scope: str | None,
    ) -> list[dict[str, Any]]:
        query_embedding = local_embedding(query)
        candidates = {row["id"]: row for row in lexical_rows}
        for row in self.store.candidate_memories(owner=owner, scope=scope, limit=max(200, limit * 10)):
            candidates.setdefault(row["id"], row)
        scored: list[tuple[float, dict[str, Any]]] = []
        lexical_ids = {row["id"] for row in lexical_rows}
        for row in candidates.values():
            embedding = json.loads(row.get("embedding_json") or "{}")
            if not embedding:
                embedding = local_embedding(str(row.get("content", "")), tags=tuple(json.loads(row.get("tags_json", "[]"))))
                self.store.upsert_memory_embedding(row["id"], embedding=embedding, model=EMBEDDING_MODEL)
            similarity = cosine_similarity(query_embedding, embedding)
            score = similarity
            if row["id"] in lexical_ids:
                score += 0.35
            score += min(float(row.get("confidence", 0.0)), 1.0) * 0.05
            if similarity > 0 or row["id"] in lexical_ids:
                scored.append((score, row))
        scored.sort(key=lambda item: (item[0], item[1].get("updated_at", "")), reverse=True)
        return [row for _, row in scored[:limit]]

    def _expires_at(self, memory_type: MemoryType, *, ttl_days: int | None) -> str | None:
        days = _positive_ttl(ttl_days)
        if days is None:
            days = self.ttl_days_by_type.get(memory_type.value, self.default_ttl_days)
        if days is None:
            return None
        return (datetime.now(UTC) + timedelta(days=days)).isoformat()

    def _review_item_with_age(self, item: dict[str, Any], *, cutoff: datetime) -> dict[str, Any] | None:
        memory_ids = [str(item["memory_id"])] if item.get("memory_id") else [str(value) for value in (item.get("primary_id"), item.get("conflicting_id")) if value]
        timestamps: list[datetime] = []
        for memory_id in memory_ids:
            row = self.store.get_memory(memory_id)
            if not row:
                continue
            updated_at = _parse_datetime(row.get("updated_at"))
            created_at = _parse_datetime(row.get("created_at"))
            timestamp = updated_at or created_at
            if timestamp is not None:
                timestamps.append(timestamp)
        if not timestamps:
            return None
        oldest_review_at = min(timestamps)
        if oldest_review_at > cutoff:
            return None
        aged = dict(item)
        aged["overdue_since"] = oldest_review_at.isoformat()
        aged["age_days"] = max(0, (datetime.now(UTC) - oldest_review_at).days)
        aged["escalation_action"] = _review_escalation_action(item)
        return aged


def summarize(content: str, limit: int = 180) -> str:
    normalized = re.sub(r"\s+", " ", content).strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def _memory_terms(content: str) -> set[str]:
    return {term for term in re.findall(r"[a-z0-9_]+", content.lower()) if term not in STOPWORDS}


def _review_severity_rank(severity: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(severity, 0)


def _digest_item(item: dict[str, Any]) -> dict[str, Any]:
    if item.get("kind") == "unresolved_conflict":
        return {
            "kind": "unresolved_conflict",
            "severity": item.get("severity"),
            "primary_id": item.get("primary_id"),
            "conflicting_id": item.get("conflicting_id"),
            "summary": f"{item.get('primary_summary', '')} / {item.get('conflicting_summary', '')}",
            "action": item.get("action"),
            "shared_terms": item.get("shared_terms", []),
        }
    return {
        "kind": item.get("kind"),
        "severity": item.get("severity"),
        "memory_id": item.get("memory_id"),
        "summary": item.get("summary"),
        "confidence": item.get("confidence"),
        "reasons": item.get("reasons", []),
        "action": item.get("action"),
    }


def _digest_next_actions(kind_counts: Counter[str], reason_counts: Counter[str]) -> list[str]:
    actions: list[str] = []
    if kind_counts.get("unresolved_conflict", 0):
        actions.append("Resolve high-severity memory conflicts before relying on affected recall.")
    if reason_counts.get("stale_confirmation", 0):
        actions.append("Review stale confirmed memories and either reconfirm or delete outdated recall.")
    if reason_counts.get("unconfirmed", 0):
        actions.append("Confirm useful unconfirmed memories or delete records that should not influence future tasks.")
    if reason_counts.get("low_confidence", 0):
        actions.append("Raise confidence only after operator review; otherwise keep low-confidence items out of trusted context.")
    if not actions:
        actions.append("No memory review action is currently queued.")
    return actions


def _escalation_message(items: list[dict[str, Any]], *, route: str, max_age_days: int) -> str:
    if not items:
        return f"No memory review items are overdue for {route} at the {max_age_days}-day threshold."
    lines = [f"Memory review escalation for {route}: {len(items)} item(s) overdue for at least {max_age_days} day(s)."]
    for item in items[:5]:
        label = item.get("memory_id") or f"{item.get('primary_id')} / {item.get('conflicting_id')}"
        summary = item.get("summary") or f"{item.get('primary_summary', '')} / {item.get('conflicting_summary', '')}"
        lines.append(f"- {item.get('severity', 'unknown')} {item.get('kind', 'review')} {label}: {summarize(str(summary), limit=120)}")
    if len(items) > 5:
        lines.append(f"- {len(items) - 5} additional overdue item(s) omitted from this summary.")
    return "\n".join(lines)


def _escalation_next_actions(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["No escalation is needed at the current threshold."]
    actions = ["Route the message through an approval-gated channel if operators need an out-of-band reminder."]
    if any(item.get("kind") == "unresolved_conflict" for item in items):
        actions.append("Resolve overdue conflicts before using affected memories in high-impact tasks.")
    if any(item.get("kind") == "memory_review" for item in items):
        actions.append("Confirm useful overdue memories or delete records that should no longer influence recall.")
    return actions


def _review_escalation_action(item: dict[str, Any]) -> str:
    if item.get("kind") == "unresolved_conflict":
        return "resolve-conflict"
    return "review-action confirm|delete"


def _extract_session_memory_statements(content: str) -> list[str]:
    statements: list[str] = []
    for raw in re.split(r"[\n.!?]+", content):
        text = re.sub(r"\s+", " ", raw).strip(" -\t")
        if len(text) < 8:
            continue
        lowered = text.lower()
        explicit_memory = lowered.startswith(("remember that ", "please remember that ", "note that "))
        if lowered.startswith(("remember that ", "please remember that ", "note that ")):
            text = re.sub(r"^(please\s+)?remember that\s+", "", text, flags=re.I)
            text = re.sub(r"^note that\s+", "", text, flags=re.I)
        if explicit_memory or _looks_like_stable_memory(text):
            statements.append(text[:1000])
    return statements


def _looks_like_stable_memory(text: str) -> bool:
    lowered = text.lower()
    patterns = (
        r"\bprefer(s|red)?\b",
        r"\bmy name is\b",
        r"\bcall me\b",
        r"\bi am\b",
        r"\bi work\b",
        r"\bthis project\b",
        r"\bthe project\b",
        r"\bworkspace\b",
        r"\bremember that\b",
        r"\bnote that\b",
        r"\bworkflow\b",
        r"\brunbook\b",
        r"\brepair\b",
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _session_memory_candidate(
    text: str,
    *,
    session_id: str,
    message_id: str,
    owner: str,
    scope: str,
    trust_class: str,
) -> dict[str, Any]:
    redacted = redact_secret_values(text)
    secret_like = SECRET_LIKE.search(text) is not None or redacted != text
    memory_type = _session_memory_type(text)
    candidate_id = hashlib.sha256(f"{session_id}:{message_id}:{redacted}".encode("utf-8", errors="replace")).hexdigest()[:16]
    base = {
        "id": f"session-{candidate_id}",
        "type": memory_type.value,
        "source": f"session:{session_id}",
        "provenance": {
            "session_id": session_id,
            "message_id": message_id,
            "trust_class": trust_class,
            "dry_run": True,
        },
        "confidence": 0.6,
        "sensitivity": Sensitivity.INTERNAL.value,
        "owner": owner,
        "scope": scope,
        "tags": sorted({"session-extract", memory_type.value.removesuffix("_memory")}),
        "import_action": "review_required",
        "blocked": secret_like,
        "redaction_status": "secret_like_blocked" if secret_like else "not_redacted",
    }
    if secret_like:
        return {
            **base,
            "content": "[BLOCKED_SECRET_LIKE_CONTENT]",
            "summary": "Secret-like trusted session memory candidate blocked for manual review.",
            "reason": "secret_like_content",
        }
    return {**base, "content": redacted, "summary": summarize(redacted, limit=160)}


def _session_memory_type(text: str) -> MemoryType:
    lowered = text.lower()
    if re.search(r"\b(prefer|prefers|preferred)\b", lowered):
        return MemoryType.PREFERENCE
    if re.search(r"\b(my name is|call me|i am|i work)\b", lowered):
        return MemoryType.PROFILE
    if re.search(r"\b(workflow|runbook|repair|procedure)\b", lowered):
        return MemoryType.PROCEDURAL
    return MemoryType.PROJECT


def local_embedding(content: str, *, tags: tuple[str, ...] = ()) -> dict[str, float]:
    tokens = semantic_tokens(" ".join((content, " ".join(tags))))
    counts: dict[str, float] = {}
    for token in tokens:
        counts[token] = counts.get(token, 0.0) + 1.0
    magnitude = math.sqrt(sum(value * value for value in counts.values()))
    if magnitude == 0:
        return {}
    return {token: round(value / magnitude, 6) for token, value in counts.items()}


def semantic_tokens(value: str) -> list[str]:
    raw = re.findall(r"[a-z0-9]+", value.lower())
    tokens: list[str] = []
    for token in raw:
        if token in STOPWORDS:
            continue
        normalized = SEMANTIC_ALIASES.get(_stem(token), SEMANTIC_ALIASES.get(token, _stem(token)))
        if len(normalized) >= 3:
            tokens.append(normalized)
    for first, second in zip(tokens, tokens[1:]):
        tokens.append(f"{first}_{second}")
    return tokens


def cosine_similarity(left: dict[str, float], right: dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    if len(left) > len(right):
        left, right = right, left
    return sum(value * right.get(key, 0.0) for key, value in left.items())


def _stem(token: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if len(token) > len(suffix) + 3 and token.endswith(suffix):
            return token[: -len(suffix)]
    return token


def _positive_ttl(value: int | None) -> int | None:
    if value is None:
        return None
    parsed = int(value)
    return parsed if parsed > 0 else None


def _normalize_escalation_routes(routes: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    normalized: dict[str, dict[str, object]] = {}
    for route, raw_policy in routes.items():
        policy: dict[str, object] = {}
        max_age_days = _positive_ttl(raw_policy.get("max_age_days"))  # type: ignore[arg-type]
        limit = _positive_ttl(raw_policy.get("limit"))  # type: ignore[arg-type]
        scope = raw_policy.get("scope")
        if max_age_days is not None:
            policy["max_age_days"] = max_age_days
        if limit is not None:
            policy["limit"] = limit
        if scope:
            policy["scope"] = summarize(str(scope), limit=80)
        if policy:
            normalized[summarize(str(route), limit=80)] = policy
    return normalized


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def decode_memory_row(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["provenance"] = json.loads(decoded.pop("provenance_json", "{}"))
    decoded["tags"] = json.loads(decoded.pop("tags_json", "[]"))
    decoded["deleted"] = bool(decoded["deleted"])
    return decoded


def _resolved_memory_ids(resolution: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for value in resolution.values():
        if isinstance(value, dict):
            if value.get("id"):
                ids.append(str(value["id"]))
            if value.get("retired_id"):
                ids.append(str(value["retired_id"]))
            ids.extend(str(item["id"]) for item in value.values() if isinstance(item, dict) and item.get("id"))
    return sorted(set(ids))
