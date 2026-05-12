"""SQLite persistence for local-first durable state."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from contextlib import contextmanager
import json
import sqlite3

from aegis.security.taint import now_utc
from aegis.storage.migrations import apply_migrations, backup_sqlite_database, external_migration_plan, external_migration_runner, migration_plan, migration_status
from aegis.storage.state import ensure_private_file

STOPWORDS = {"a", "an", "and", "are", "as", "for", "in", "is", "it", "of", "on", "or", "the", "to", "was", "with"}


class LocalStore:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        ensure_private_file(self.database_path)
        self.initialize()
        ensure_private_file(self.database_path)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as db:
            apply_migrations(db)

    def schema_status(self) -> dict[str, object]:
        with self.connect() as db:
            return migration_status(db)

    def schema_plan(self) -> dict[str, object]:
        with self.connect() as db:
            return migration_plan(db)

    def backup(self, destination: str | Path | None = None) -> dict[str, object]:
        return backup_sqlite_database(self.database_path, destination)

    def external_schema_plan(self, target: str) -> dict[str, object]:
        return external_migration_plan(target)

    def external_schema_runner(self, target: str, *, output_dir: str | Path, force: bool = False) -> dict[str, object]:
        return external_migration_runner(target, output_dir=output_dir, force=force)

    def insert_task(
        self,
        *,
        task_id: str,
        user_request: str,
        interpretation: str,
        status: str,
        plan: list[dict[str, Any]],
        risk_level: str,
        session_id: str | None = None,
    ) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO tasks (
                  id, user_request, interpretation, status, plan_json, risk_level,
                  created_at, updated_at, checkpoint_json, receipt_json, session_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    user_request,
                    interpretation,
                    status,
                    json.dumps(plan),
                    risk_level,
                    timestamp,
                    timestamp,
                    json.dumps({}),
                    None,
                    session_id,
                ),
            )

    def update_task(self, task_id: str, *, status: str | None = None, checkpoint: dict[str, Any] | None = None, receipt: dict[str, Any] | None = None) -> None:
        task = self.get_task(task_id)
        if not task:
            raise KeyError(task_id)
        next_status = status or task["status"]
        next_checkpoint = checkpoint if checkpoint is not None else json.loads(task["checkpoint_json"])
        next_receipt = receipt if receipt is not None else (json.loads(task["receipt_json"]) if task["receipt_json"] else None)
        with self.connect() as db:
            db.execute(
                """
                UPDATE tasks
                SET status = ?, checkpoint_json = ?, receipt_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (next_status, json.dumps(next_checkpoint), json.dumps(next_receipt) if next_receipt else None, now_utc(), task_id),
            )

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return dict(row) if row else None

    def list_tasks(self, limit: int = 20, *, session_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            if session_id:
                rows = db.execute("SELECT * FROM tasks WHERE session_id = ? ORDER BY created_at DESC LIMIT ?", (session_id, limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def insert_memory(self, record: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO memories (
                  id, type, content, summary, source, provenance_json, confidence,
                  sensitivity, created_at, updated_at, last_confirmed_at, expires_at,
                  owner, scope, tags_json, search_text, redaction_status, deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["type"],
                    record["content"],
                    record["summary"],
                    record["source"],
                    json.dumps(record["provenance"]),
                    record["confidence"],
                    record["sensitivity"],
                    record["created_at"],
                    record["updated_at"],
                    record.get("last_confirmed_at"),
                    record.get("expires_at"),
                    record["owner"],
                    record["scope"],
                    json.dumps(record["tags"]),
                    record["search_text"],
                    record["redaction_status"],
                    int(record.get("deleted", False)),
                ),
            )

    def upsert_memory_embedding(self, memory_id: str, *, embedding: dict[str, float], model: str) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO memory_embeddings (memory_id, embedding_json, model, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(memory_id) DO UPDATE SET
                  embedding_json = excluded.embedding_json,
                  model = excluded.model,
                  updated_at = excluded.updated_at
                """,
                (memory_id, json.dumps(embedding, sort_keys=True), model, now_utc()),
            )

    def update_memory(self, memory_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_memory(memory_id)
        if not existing:
            raise KeyError(memory_id)
        allowed = {"content", "summary", "confidence", "last_confirmed_at", "expires_at", "tags_json", "search_text", "redaction_status", "deleted"}
        assignments: list[str] = []
        values: list[Any] = []
        for key, value in changes.items():
            if key not in allowed:
                raise ValueError(f"unsupported memory field: {key}")
            assignments.append(f"{key} = ?")
            values.append(value)
        assignments.append("updated_at = ?")
        values.append(now_utc())
        values.append(memory_id)
        with self.connect() as db:
            db.execute(f"UPDATE memories SET {', '.join(assignments)} WHERE id = ?", tuple(values))
        updated = self.get_memory(memory_id)
        if not updated:
            raise KeyError(memory_id)
        return updated

    def get_memory(self, memory_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
        return dict(row) if row else None

    def mark_expired_memories_deleted(self) -> list[str]:
        timestamp = now_utc()
        with self.connect() as db:
            rows = db.execute(
                "SELECT id FROM memories WHERE deleted = 0 AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY expires_at ASC",
                (timestamp,),
            ).fetchall()
            ids = [str(row["id"]) for row in rows]
            if ids:
                db.executemany("UPDATE memories SET deleted = 1, updated_at = ? WHERE id = ?", [(timestamp, memory_id) for memory_id in ids])
        return ids

    def search_memories(
        self,
        query: str,
        *,
        limit: int = 10,
        include_deleted: bool = False,
        owner: str | None = None,
        scope: str | None = None,
    ) -> list[dict[str, Any]]:
        terms = [term for term in query.lower().replace("%", " ").split() if term and term not in STOPWORDS and len(term) > 2]
        if not terms:
            terms = [""]
        like_clauses = " OR ".join("lower(search_text) LIKE ?" for _ in terms)
        deleted_clause = "" if include_deleted else "AND deleted = 0"
        expiry_clause = "" if include_deleted else "AND (expires_at IS NULL OR expires_at > ?)"
        owner_clause = "AND owner = ?" if owner is not None else ""
        scope_clause = "AND scope = ?" if scope is not None else ""
        likes = [f"%{term}%" for term in terms]
        filters: list[Any] = []
        if not include_deleted:
            filters.append(now_utc())
        if owner is not None:
            filters.append(owner)
        if scope is not None:
            filters.append(scope)
        params: tuple[Any, ...] = (*likes, *filters, limit)
        with self.connect() as db:
            rows = db.execute(
                f"""
                SELECT * FROM memories
                WHERE ({like_clauses}) {deleted_clause} {expiry_clause} {owner_clause} {scope_clause}
                ORDER BY confidence DESC, updated_at DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def candidate_memories(
        self,
        *,
        include_deleted: bool = False,
        owner: str | None = None,
        scope: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        deleted_clause = "" if include_deleted else "AND memories.deleted = 0"
        expiry_clause = "" if include_deleted else "AND (memories.expires_at IS NULL OR memories.expires_at > ?)"
        owner_clause = "AND memories.owner = ?" if owner is not None else ""
        scope_clause = "AND memories.scope = ?" if scope is not None else ""
        filters: list[Any] = []
        if not include_deleted:
            filters.append(now_utc())
        if owner is not None:
            filters.append(owner)
        if scope is not None:
            filters.append(scope)
        filters.append(limit)
        with self.connect() as db:
            rows = db.execute(
                f"""
                SELECT memories.*, memory_embeddings.embedding_json, memory_embeddings.model AS embedding_model
                FROM memories
                LEFT JOIN memory_embeddings ON memory_embeddings.memory_id = memories.id
                WHERE 1 = 1 {deleted_clause} {expiry_clause} {owner_clause} {scope_clause}
                ORDER BY memories.updated_at DESC
                LIMIT ?
                """,
                tuple(filters),
            ).fetchall()
        return [dict(row) for row in rows]

    def insert_skill(self, skill_id: str, manifest: dict[str, Any], *, enabled: bool) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO skills (id, manifest_json, enabled, created_at, updated_at)
                VALUES (?, ?, ?, COALESCE((SELECT created_at FROM skills WHERE id = ?), ?), ?)
                """,
                (skill_id, json.dumps(manifest), int(enabled), skill_id, timestamp, timestamp),
            )

    def get_skill(self, skill_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM skills WHERE id = ?", (skill_id,)).fetchone()
        return dict(row) if row else None

    def list_skills(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM skills ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def set_skill_enabled(self, skill_id: str, enabled: bool) -> None:
        with self.connect() as db:
            db.execute("UPDATE skills SET enabled = ?, updated_at = ? WHERE id = ?", (int(enabled), now_utc(), skill_id))

    def delete_skill(self, skill_id: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM skills WHERE id = ?", (skill_id,))

    def insert_approval(self, approval: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO approvals (id, task_id, reason, status, risk_level, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval["id"],
                    approval.get("task_id"),
                    approval["reason"],
                    approval["status"],
                    approval["risk_level"],
                    json.dumps(approval["payload"]),
                    approval["created_at"],
                    approval["updated_at"],
                ),
            )

    def update_approval(self, approval_id: str, status: str, decision_metadata: dict[str, Any] | None = None) -> None:
        with self.connect() as db:
            existing_row = db.execute("SELECT status, payload_json FROM approvals WHERE id = ?", (approval_id,)).fetchone()
            if not existing_row:
                raise KeyError(approval_id)
            if existing_row["status"] != "pending":
                raise ValueError(f"approval is already {existing_row['status']}")
            payload = json.loads(existing_row["payload_json"] or "{}")
            if decision_metadata:
                payload["_decision"] = decision_metadata
            cursor = db.execute(
                "UPDATE approvals SET status = ?, payload_json = ?, updated_at = ? WHERE id = ? AND status = 'pending'",
                (status, json.dumps(payload), now_utc(), approval_id),
            )
            if cursor.rowcount == 0:
                latest = db.execute("SELECT status FROM approvals WHERE id = ?", (approval_id,)).fetchone()
                if not latest:
                    raise KeyError(approval_id)
                raise ValueError(f"approval is already {latest['status']}")

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return dict(row) if row else None

    def list_approvals(self, status: str | None = None, *, limit: int | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            limit_clause = " LIMIT ?" if limit is not None else ""
            if status:
                params: tuple[Any, ...] = (status, limit) if limit is not None else (status,)
                rows = db.execute(f"SELECT * FROM approvals WHERE status = ? ORDER BY updated_at DESC, created_at DESC{limit_clause}", params).fetchall()
            else:
                params = (limit,) if limit is not None else ()
                rows = db.execute(f"SELECT * FROM approvals ORDER BY updated_at DESC, created_at DESC{limit_clause}", params).fetchall()
        return [dict(row) for row in rows]

    def insert_session(self, row: dict[str, Any]) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO sessions (id, title, channel, status, model, personality, created_at, updated_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["title"],
                    row["channel"],
                    row["status"],
                    row.get("model"),
                    row.get("personality"),
                    row.get("created_at", timestamp),
                    row.get("updated_at", timestamp),
                    json.dumps(row.get("metadata", {})),
                ),
            )

    def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def update_session(self, session_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_session(session_id)
        if not existing:
            raise KeyError(session_id)
        allowed = {"title", "status", "model", "personality", "metadata_json"}
        assignments: list[str] = []
        values: list[Any] = []
        for key, value in changes.items():
            if key not in allowed:
                raise ValueError(f"unsupported session field: {key}")
            assignments.append(f"{key} = ?")
            values.append(value)
        assignments.append("updated_at = ?")
        values.append(now_utc())
        values.append(session_id)
        with self.connect() as db:
            db.execute(f"UPDATE sessions SET {', '.join(assignments)} WHERE id = ?", tuple(values))
        updated = self.get_session(session_id)
        if not updated:
            raise KeyError(session_id)
        return updated

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return dict(row) if row else None

    def insert_message(self, row: dict[str, Any]) -> None:
        if not self.get_session(row["session_id"]):
            raise KeyError(row["session_id"])
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO messages (id, session_id, role, content, trust_class, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["session_id"],
                    row["role"],
                    row["content"],
                    row["trust_class"],
                    row.get("created_at", now_utc()),
                    json.dumps(row.get("metadata", {})),
                ),
            )
            db.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (now_utc(), row["session_id"]))

    def list_messages(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM messages WHERE session_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def insert_schedule(self, row: dict[str, Any]) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO schedules (
                  id, name, natural_language, cron, task_request, channel, status,
                  next_run_at, last_run_at, created_at, updated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["name"],
                    row["natural_language"],
                    row["cron"],
                    row["task_request"],
                    row["channel"],
                    row["status"],
                    row.get("next_run_at"),
                    row.get("last_run_at"),
                    row.get("created_at", timestamp),
                    row.get("updated_at", timestamp),
                    json.dumps(row.get("metadata", {})),
                ),
            )

    def list_schedules(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def update_schedule(self, schedule_id: str, changes: dict[str, Any]) -> None:
        allowed = {"status", "next_run_at", "last_run_at", "metadata_json"}
        assignments: list[str] = []
        values: list[Any] = []
        for key, value in changes.items():
            if key not in allowed:
                raise ValueError(f"unsupported schedule field: {key}")
            assignments.append(f"{key} = ?")
            values.append(value)
        assignments.append("updated_at = ?")
        values.append(now_utc())
        values.append(schedule_id)
        with self.connect() as db:
            db.execute(f"UPDATE schedules SET {', '.join(assignments)} WHERE id = ?", tuple(values))

    def claim_due_schedule(self, schedule_id: str, *, expected_next_run_at: str) -> bool:
        with self.connect() as db:
            cursor = db.execute(
                """
                UPDATE schedules
                SET status = 'running', updated_at = ?
                WHERE id = ? AND status = 'active' AND next_run_at = ?
                """,
                (now_utc(), schedule_id, expected_next_run_at),
            )
            return cursor.rowcount == 1

    def insert_channel_event(self, row: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO channel_events (id, channel, direction, session_id, payload_json, normalized_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["channel"],
                    row["direction"],
                    row.get("session_id"),
                    json.dumps(row.get("payload", {})),
                    json.dumps(row.get("normalized", {})),
                    row["status"],
                    row.get("created_at", now_utc()),
                ),
            )

    def list_channel_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM channel_events ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_channel_event(self, event_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM channel_events WHERE id = ?", (event_id,)).fetchone()
        return dict(row) if row else None

    def insert_model_usage(self, row: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO model_usage (
                  id, provider, model, task_id, session_id, input_tokens,
                  output_tokens, estimated_cost, created_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["provider"],
                    row["model"],
                    row.get("task_id"),
                    row.get("session_id"),
                    int(row.get("input_tokens", 0)),
                    int(row.get("output_tokens", 0)),
                    float(row.get("estimated_cost", 0.0)),
                    row.get("created_at", now_utc()),
                    json.dumps(row.get("metadata", {})),
                ),
            )

    def list_model_usage(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM model_usage ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def set_model_route_setting(self, key: str, value: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO model_route_settings (key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                  value_json = excluded.value_json,
                  updated_at = excluded.updated_at
                """,
                (key, json.dumps(value, sort_keys=True), now_utc()),
            )

    def list_model_route_settings(self) -> dict[str, dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT key, value_json FROM model_route_settings").fetchall()
        return {str(row["key"]): json.loads(row["value_json"]) for row in rows}

    def insert_improvement_proposal(self, row: dict[str, Any]) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO improvement_proposals (
                  id, task_id, kind, summary, status, approval_required, default_state,
                  evidence_json, created_at, updated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row.get("task_id"),
                    row["kind"],
                    row["summary"],
                    row.get("status", "proposed"),
                    int(row.get("approval_required", True)),
                    row.get("default_state", "disabled_until_review"),
                    json.dumps(row.get("evidence", [])),
                    row.get("created_at", timestamp),
                    row.get("updated_at", timestamp),
                    json.dumps(row.get("metadata", {})),
                ),
            )

    def list_improvement_proposals(self, *, status: str | None = None, task_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as db:
            if status and task_id:
                rows = db.execute(
                    "SELECT * FROM improvement_proposals WHERE status = ? AND task_id = ? ORDER BY created_at DESC LIMIT ?",
                    (status, task_id, limit),
                ).fetchall()
            elif status:
                rows = db.execute(
                    "SELECT * FROM improvement_proposals WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            elif task_id:
                rows = db.execute(
                    "SELECT * FROM improvement_proposals WHERE task_id = ? ORDER BY created_at DESC LIMIT ?",
                    (task_id, limit),
                ).fetchall()
            else:
                rows = db.execute("SELECT * FROM improvement_proposals ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_improvement_proposal(self, proposal_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM improvement_proposals WHERE id = ?", (proposal_id,)).fetchone()
        return dict(row) if row else None

    def update_improvement_proposal(self, proposal_id: str, *, status: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        existing = self.get_improvement_proposal(proposal_id)
        if not existing:
            raise KeyError(proposal_id)
        metadata_json = existing.get("metadata_json") or "{}"
        merged_metadata = json.loads(metadata_json)
        if metadata is not None:
            merged_metadata.update(metadata)
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE improvement_proposals SET status = ?, metadata_json = ?, updated_at = ? WHERE id = ?",
                (status, json.dumps(merged_metadata), now_utc(), proposal_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(proposal_id)
        updated = self.get_improvement_proposal(proposal_id)
        if not updated:
            raise KeyError(proposal_id)
        return updated

    def insert_kanban_board(self, row: dict[str, Any]) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO kanban_boards (id, name, created_at, updated_at, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (row["id"], row["name"], row.get("created_at", timestamp), row.get("updated_at", timestamp), json.dumps(row.get("metadata", {}))),
            )

    def insert_kanban_card(self, row: dict[str, Any]) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO kanban_cards (
                  id, board_id, title, description, lane, owner, risk_level,
                  task_id, created_at, updated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["board_id"],
                    row["title"],
                    row["description"],
                    row["lane"],
                    row.get("owner"),
                    row["risk_level"],
                    row.get("task_id"),
                    row.get("created_at", timestamp),
                    row.get("updated_at", timestamp),
                    json.dumps(row.get("metadata", {})),
                ),
            )

    def move_kanban_card(self, card_id: str, lane: str) -> None:
        with self.connect() as db:
            cursor = db.execute("UPDATE kanban_cards SET lane = ?, updated_at = ? WHERE id = ?", (lane, now_utc(), card_id))
            if cursor.rowcount == 0:
                raise KeyError(card_id)

    def get_kanban_board(self, board_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM kanban_boards WHERE id = ?", (board_id,)).fetchone()
        return dict(row) if row else None

    def get_kanban_card(self, card_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM kanban_cards WHERE id = ?", (card_id,)).fetchone()
        return dict(row) if row else None

    def list_kanban_boards(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM kanban_boards ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def list_kanban_cards(self, board_id: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM kanban_cards WHERE board_id = ? ORDER BY created_at ASC", (board_id,)).fetchall()
        return [dict(row) for row in rows]

    def insert_mcp_server(self, row: dict[str, Any]) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO mcp_servers (
                  id, name, command, allowed_tools_json, enabled,
                  approval_required, created_at, updated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM mcp_servers WHERE id = ?), ?), ?, ?)
                """,
                (
                    row["id"],
                    row["name"],
                    row["command"],
                    json.dumps(row.get("allowed_tools", [])),
                    int(row.get("enabled", False)),
                    int(row.get("approval_required", True)),
                    row["id"],
                    timestamp,
                    timestamp,
                    json.dumps(row.get("metadata", {})),
                ),
            )

    def list_mcp_servers(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM mcp_servers ORDER BY name").fetchall()
        return [dict(row) for row in rows]

    def set_mcp_server_enabled(self, server_id: str, enabled: bool) -> None:
        with self.connect() as db:
            db.execute("UPDATE mcp_servers SET enabled = ?, updated_at = ? WHERE id = ?", (int(enabled), now_utc(), server_id))

    def delete_mcp_server(self, server_id: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM mcp_servers WHERE id = ?", (server_id,))
