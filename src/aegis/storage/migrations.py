"""Forward-only SQLite schema migrations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3

from aegis.storage.state import ensure_private_file
from aegis.security.taint import now_utc


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        name="initial_schema",
        sql="""
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
        """,
    ),
    Migration(
        version=2,
        name="task_session_links",
        sql="""
        ALTER TABLE tasks ADD COLUMN session_id TEXT;
        CREATE INDEX IF NOT EXISTS idx_tasks_session_id ON tasks(session_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_messages_session_id_created_at ON messages(session_id, created_at);
        """,
    ),
    Migration(
        version=3,
        name="improvement_proposals",
        sql="""
        CREATE TABLE IF NOT EXISTS improvement_proposals (
          id TEXT PRIMARY KEY,
          task_id TEXT,
          kind TEXT NOT NULL,
          summary TEXT NOT NULL,
          status TEXT NOT NULL,
          approval_required INTEGER NOT NULL,
          default_state TEXT NOT NULL,
          evidence_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          metadata_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_improvement_proposals_task_id ON improvement_proposals(task_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_improvement_proposals_status ON improvement_proposals(status, created_at);
        """,
    ),
    Migration(
        version=4,
        name="memory_embeddings",
        sql="""
        CREATE TABLE IF NOT EXISTS memory_embeddings (
          memory_id TEXT PRIMARY KEY,
          embedding_json TEXT NOT NULL,
          model TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_memory_embeddings_model ON memory_embeddings(model, updated_at);
        """,
    ),
    Migration(
        version=5,
        name="model_route_settings",
        sql="""
        CREATE TABLE IF NOT EXISTS model_route_settings (
          key TEXT PRIMARY KEY,
          value_json TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        """,
    ),
)


def apply_migrations(db: sqlite3.Connection) -> list[dict[str, object]]:
    """Apply unapplied migrations and return the migrations applied in this call."""
    ensure_migration_table(db)
    applied_rows = {int(row["version"]): row for row in db.execute("SELECT version, name, checksum FROM schema_migrations").fetchall()}
    applied: list[dict[str, object]] = []
    for migration in MIGRATIONS:
        existing = applied_rows.get(migration.version)
        if existing is not None:
            if existing["checksum"] != migration.checksum:
                raise RuntimeError(f"schema migration {migration.version} checksum mismatch")
            if existing["name"] != migration.name:
                raise RuntimeError(f"schema migration {migration.version} name mismatch")
            if migration.version == 1 and not _table_exists(db, "tasks"):
                db.executescript(migration.sql)
            continue
        if migration.version == 2 and _column_exists(db, "tasks", "session_id"):
            pass
        else:
            db.executescript(migration.sql)
        applied_at = now_utc()
        db.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
            (migration.version, migration.name, migration.checksum, applied_at),
        )
        applied.append({"version": migration.version, "name": migration.name, "checksum": migration.checksum, "applied_at": applied_at})
    return applied


def _table_exists(db: sqlite3.Connection, table_name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table_name,)).fetchone() is not None


def _column_exists(db: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    if not _table_exists(db, table_name):
        return False
    return any(row["name"] == column_name for row in db.execute(f"PRAGMA table_info({table_name})").fetchall())


def ensure_migration_table(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          checksum TEXT NOT NULL,
          applied_at TEXT NOT NULL
        )
        """
    )
    columns = {row["name"] for row in db.execute("PRAGMA table_info(schema_migrations)").fetchall()}
    if "checksum" not in columns:
        db.execute("ALTER TABLE schema_migrations ADD COLUMN checksum TEXT")
    for migration in MIGRATIONS:
        db.execute(
            "UPDATE schema_migrations SET checksum = ? WHERE version = ? AND (checksum IS NULL OR checksum = '')",
            (migration.checksum, migration.version),
        )


def migration_status(db: sqlite3.Connection) -> dict[str, object]:
    ensure_migration_table(db)
    rows = db.execute("SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version ASC").fetchall()
    applied = [{"version": int(row["version"]), "name": row["name"], "checksum": row["checksum"], "applied_at": row["applied_at"]} for row in rows]
    latest = max((migration.version for migration in MIGRATIONS), default=0)
    current = max((row["version"] for row in applied), default=0)
    pending = [{"version": migration.version, "name": migration.name} for migration in MIGRATIONS if migration.version > current]
    return {
        "current_version": int(current),
        "latest_version": int(latest),
        "applied": applied,
        "pending": pending,
    }


def migration_plan(db: sqlite3.Connection) -> dict[str, object]:
    status = migration_status(db)
    applied_versions = {int(row["version"]) for row in status["applied"]}
    plan = []
    for migration in MIGRATIONS:
        plan.append(
            {
                "version": migration.version,
                "name": migration.name,
                "checksum": migration.checksum,
                "status": "applied" if migration.version in applied_versions else "pending",
                "statements": _statement_count(migration.sql),
            }
        )
    return {
        **status,
        "operation": "dry_run",
        "requires_backup": bool(status["pending"]),
        "plan": plan,
    }


def external_migration_plan(target: str) -> dict[str, object]:
    normalized = target.strip().lower().replace("-", "_")
    if normalized in {"postgres", "postgresql"}:
        target_name = "postgresql"
    elif normalized in {"mysql", "mariadb"}:
        target_name = "mysql"
    else:
        raise ValueError("unsupported external migration target")
    plan = []
    for migration in MIGRATIONS:
        translated_sql = _translate_sql(migration.sql, target=target_name)
        plan.append(
            {
                "version": migration.version,
                "name": migration.name,
                "checksum": migration.checksum,
                "source_statements": _statement_count(migration.sql),
                "translated_statements": _statement_count(translated_sql),
                "sql": translated_sql,
            }
        )
    return {
        "operation": "dry_run_external_schema",
        "target": target_name,
        "connects_to_target": False,
        "writes": "none",
        "requires_operator_review": True,
        "latest_version": max((migration.version for migration in MIGRATIONS), default=0),
        "translation_notes": _translation_notes(target_name),
        "plan": plan,
    }


def external_migration_runner(
    target: str,
    *,
    output_dir: str | Path,
    force: bool = False,
) -> dict[str, object]:
    plan = external_migration_plan(target)
    target_name = str(plan["target"])
    destination = Path(output_dir).expanduser().resolve()
    if destination.exists() and any(destination.iterdir()) and not force:
        raise FileExistsError(f"external migration runner output directory is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    destination.chmod(0o700)
    migrations_dir = destination / "migrations"
    migrations_dir.mkdir(exist_ok=True)
    migrations_dir.chmod(0o700)
    files: list[dict[str, object]] = []
    for item in plan["plan"]:
        filename = f"{int(item['version']):04d}-{_safe_runner_name(str(item['name']))}.sql"
        path = migrations_dir / filename
        sql = _runner_sql_header(item, target=target_name) + str(item["sql"])
        path.write_text(sql, encoding="utf-8")
        path.chmod(0o600)
        files.append(
            {
                "version": item["version"],
                "name": item["name"],
                "checksum": item["checksum"],
                "path": str(path),
                "bytes": path.stat().st_size,
            }
        )
    manifest = {
        "ok": True,
        "operation": "external_migration_runner",
        "target": target_name,
        "created_at": now_utc(),
        "connects_to_target": False,
        "writes": "operator_executed_only",
        "requires_operator_review": True,
        "latest_version": plan["latest_version"],
        "translation_notes": plan["translation_notes"],
        "files": files,
    }
    manifest_path = destination / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)
    runner_path = destination / "run.sh"
    runner_path.write_text(_runner_script(target_name), encoding="utf-8")
    runner_path.chmod(0o700)
    return {
        **manifest,
        "output_dir": str(destination),
        "manifest_path": str(manifest_path),
        "runner_path": str(runner_path),
        "files": files,
    }


def backup_sqlite_database(source: str | Path, destination: str | Path | None = None) -> dict[str, object]:
    source_path = Path(source).expanduser().resolve()
    if not source_path.exists():
        raise FileNotFoundError(source_path)
    if destination is None:
        destination_path = source_path.with_name(f"{source_path.stem}.backup-{now_utc().replace(':', '-').replace('+', 'Z')}{source_path.suffix}")
    else:
        destination_path = Path(destination).expanduser().resolve()
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    ensure_private_file(destination_path)
    with sqlite3.connect(source_path) as src, sqlite3.connect(destination_path) as dst:
        src.backup(dst)
    ensure_private_file(destination_path)
    return {
        "ok": True,
        "source": str(source_path),
        "destination": str(destination_path),
        "bytes": destination_path.stat().st_size,
        "created_at": now_utc(),
    }


def _runner_sql_header(item: dict[str, object], *, target: str) -> str:
    return "\n".join(
        [
            f"-- Aegis external migration {item['version']}: {item['name']}",
            f"-- target: {target}",
            f"-- checksum: {item['checksum']}",
            "-- Review this file before executing it against a live database.",
            "",
        ]
    )


def _runner_script(target: str) -> str:
    if target == "postgresql":
        return """#!/usr/bin/env sh
set -eu

: "${DATABASE_URL:?Set DATABASE_URL to the target PostgreSQL connection URL.}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

for file in "$SCRIPT_DIR"/migrations/*.sql; do
  printf 'Applying %s\\n' "$file"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$file"
done
"""
    if target == "mysql":
        return """#!/usr/bin/env sh
set -eu

: "${MYSQL_DSN:?Set MYSQL_DSN to mysql client arguments, for example: --host=127.0.0.1 --user=aegis --database=aegis}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

for file in "$SCRIPT_DIR"/migrations/*.sql; do
  printf 'Applying %s\\n' "$file"
  # shellcheck disable=SC2086
  mysql $MYSQL_DSN < "$file"
done
"""
    raise ValueError("unsupported external migration target")


def _safe_runner_name(name: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in name).strip(".-") or "migration"


def _statement_count(sql: str) -> int:
    return sum(1 for statement in sql.split(";") if statement.strip())


def _translate_sql(sql: str, *, target: str) -> str:
    translated = sql.strip()
    if target == "postgresql":
        translated = translated.replace(" REAL ", " DOUBLE PRECISION ")
        translated = translated.replace("INTEGER NOT NULL DEFAULT 0", "INTEGER NOT NULL DEFAULT 0")
        return translated + "\n"
    if target == "mysql":
        translated = translated.replace("TEXT PRIMARY KEY", "VARCHAR(191) PRIMARY KEY")
        translated = translated.replace(" TEXT", " LONGTEXT")
        translated = translated.replace("REAL", "DOUBLE")
        translated = translated.replace("CREATE INDEX IF NOT EXISTS", "CREATE INDEX")
        return translated + "\n"
    raise ValueError("unsupported external migration target")


def _translation_notes(target: str) -> list[str]:
    if target == "postgresql":
        return [
            "Generated from checksum-verified SQLite forward migrations.",
            "PostgreSQL-compatible core types are preserved; review indexes and operational DDL before applying.",
            "This command never opens a database connection.",
        ]
    if target == "mysql":
        return [
            "Generated from checksum-verified SQLite forward migrations.",
            "MySQL text primary keys are narrowed to VARCHAR(191); review column lengths and index DDL before applying.",
            "This command never opens a database connection.",
        ]
    raise ValueError("unsupported external migration target")
