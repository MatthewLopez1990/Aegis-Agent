"""SQLite persistence for local-first durable state."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from contextlib import contextmanager
import json
import sqlite3

from aegis.security.taint import now_utc


class LocalStore:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

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
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                  id TEXT PRIMARY KEY,
                  user_request TEXT NOT NULL,
                  interpretation TEXT NOT NULL,
                  status TEXT NOT NULL,
                  plan_json TEXT NOT NULL,
                  risk_level TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  checkpoint_json TEXT NOT NULL,
                  receipt_json TEXT
                );

                CREATE TABLE IF NOT EXISTS memories (
                  id TEXT PRIMARY KEY,
                  type TEXT NOT NULL,
                  content TEXT NOT NULL,
                  summary TEXT NOT NULL,
                  source TEXT NOT NULL,
                  provenance_json TEXT NOT NULL,
                  confidence REAL NOT NULL,
                  sensitivity TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  last_confirmed_at TEXT,
                  expires_at TEXT,
                  owner TEXT NOT NULL,
                  scope TEXT NOT NULL,
                  tags_json TEXT NOT NULL,
                  search_text TEXT NOT NULL,
                  redaction_status TEXT NOT NULL,
                  deleted INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS skills (
                  id TEXT PRIMARY KEY,
                  manifest_json TEXT NOT NULL,
                  enabled INTEGER NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approvals (
                  id TEXT PRIMARY KEY,
                  task_id TEXT,
                  reason TEXT NOT NULL,
                  status TEXT NOT NULL,
                  risk_level TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                  id TEXT PRIMARY KEY,
                  title TEXT NOT NULL,
                  channel TEXT NOT NULL,
                  status TEXT NOT NULL,
                  model TEXT,
                  personality TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS messages (
                  id TEXT PRIMARY KEY,
                  session_id TEXT NOT NULL,
                  role TEXT NOT NULL,
                  content TEXT NOT NULL,
                  trust_class TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS schedules (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  natural_language TEXT NOT NULL,
                  cron TEXT NOT NULL,
                  task_request TEXT NOT NULL,
                  channel TEXT NOT NULL,
                  status TEXT NOT NULL,
                  next_run_at TEXT,
                  last_run_at TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS channel_events (
                  id TEXT PRIMARY KEY,
                  channel TEXT NOT NULL,
                  direction TEXT NOT NULL,
                  session_id TEXT,
                  payload_json TEXT NOT NULL,
                  normalized_json TEXT NOT NULL,
                  status TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS model_usage (
                  id TEXT PRIMARY KEY,
                  provider TEXT NOT NULL,
                  model TEXT NOT NULL,
                  task_id TEXT,
                  session_id TEXT,
                  input_tokens INTEGER NOT NULL,
                  output_tokens INTEGER NOT NULL,
                  estimated_cost REAL NOT NULL,
                  created_at TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS kanban_boards (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS kanban_cards (
                  id TEXT PRIMARY KEY,
                  board_id TEXT NOT NULL,
                  title TEXT NOT NULL,
                  description TEXT NOT NULL,
                  lane TEXT NOT NULL,
                  owner TEXT,
                  risk_level TEXT NOT NULL,
                  task_id TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS mcp_servers (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  command TEXT NOT NULL,
                  allowed_tools_json TEXT NOT NULL,
                  enabled INTEGER NOT NULL,
                  approval_required INTEGER NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  metadata_json TEXT NOT NULL
                );
                """
            )

    def insert_task(self, *, task_id: str, user_request: str, interpretation: str, status: str, plan: list[dict[str, Any]], risk_level: str) -> None:
        timestamp = now_utc()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO tasks (
                  id, user_request, interpretation, status, plan_json, risk_level,
                  created_at, updated_at, checkpoint_json, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    def list_tasks(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as db:
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

    def search_memories(self, query: str, *, limit: int = 10, include_deleted: bool = False) -> list[dict[str, Any]]:
        like = f"%{query.lower()}%"
        deleted_clause = "" if include_deleted else "AND deleted = 0"
        with self.connect() as db:
            rows = db.execute(
                f"""
                SELECT * FROM memories
                WHERE lower(search_text) LIKE ? {deleted_clause}
                ORDER BY confidence DESC, updated_at DESC
                LIMIT ?
                """,
                (like, limit),
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

    def update_approval(self, approval_id: str, status: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE approvals SET status = ?, updated_at = ? WHERE id = ?", (status, now_utc(), approval_id))

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return dict(row) if row else None

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            if status:
                rows = db.execute("SELECT * FROM approvals WHERE status = ? ORDER BY created_at DESC", (status,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM approvals ORDER BY created_at DESC").fetchall()
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

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        return dict(row) if row else None

    def insert_message(self, row: dict[str, Any]) -> None:
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
                "SELECT * FROM messages WHERE session_id = ? ORDER BY created_at ASC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

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
            db.execute("UPDATE kanban_cards SET lane = ?, updated_at = ? WHERE id = ?", (lane, now_utc(), card_id))

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
