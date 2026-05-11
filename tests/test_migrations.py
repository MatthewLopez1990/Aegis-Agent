from __future__ import annotations

import sqlite3
import stat
import tempfile
import unittest
import json
from pathlib import Path

from aegis.memory.store import LocalStore
from aegis.storage.migrations import MIGRATIONS


class MigrationTests(unittest.TestCase):
    def test_schema_migrations_are_recorded_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "aegis.db"
            store = LocalStore(database)
            status = store.schema_status()

            self.assertEqual(status["current_version"], 5)
            self.assertEqual(status["latest_version"], 5)
            self.assertEqual(status["pending"], [])
            self.assertEqual(status["applied"][0]["name"], "initial_schema")
            self.assertEqual(status["applied"][0]["checksum"], MIGRATIONS[0].checksum)

            store.insert_task(
                task_id="task-1",
                user_request="Summarize project",
                interpretation="Read-only test",
                status="planned",
                plan=[],
                risk_level="low",
            )
            LocalStore(database)

            with sqlite3.connect(database) as db:
                migration_count = db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
                task_count = db.execute("SELECT COUNT(*) FROM tasks WHERE id = 'task-1'").fetchone()[0]
                task_columns = {row[1] for row in db.execute("PRAGMA table_info(tasks)").fetchall()}
                proposal_count = db.execute("SELECT COUNT(*) FROM improvement_proposals").fetchone()[0]
                embedding_count = db.execute("SELECT COUNT(*) FROM memory_embeddings").fetchone()[0]
                route_count = db.execute("SELECT COUNT(*) FROM model_route_settings").fetchone()[0]

            self.assertEqual(migration_count, 5)
            self.assertEqual(task_count, 1)
            self.assertIn("session_id", task_columns)
            self.assertEqual(proposal_count, 0)
            self.assertEqual(embedding_count, 0)
            self.assertEqual(route_count, 0)

    def test_migration_plan_and_private_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "aegis.db"
            store = LocalStore(database)
            store.insert_task(
                task_id="task-1",
                user_request="Summarize project",
                interpretation="Read-only test",
                status="planned",
                plan=[],
                risk_level="low",
            )

            plan = store.schema_plan()
            external = store.external_schema_plan("postgresql")
            backup = store.backup(Path(temp) / "backup.db")

            self.assertEqual(plan["operation"], "dry_run")
            self.assertFalse(plan["requires_backup"])
            self.assertEqual(plan["plan"][0]["checksum"], MIGRATIONS[0].checksum)
            self.assertEqual(plan["plan"][-1]["status"], "applied")
            self.assertEqual(external["operation"], "dry_run_external_schema")
            self.assertEqual(external["target"], "postgresql")
            self.assertFalse(external["connects_to_target"])
            self.assertTrue(external["requires_operator_review"])
            self.assertEqual(external["latest_version"], 5)
            self.assertEqual(external["plan"][0]["checksum"], MIGRATIONS[0].checksum)
            self.assertEqual(external["plan"][0]["source_statements"], external["plan"][0]["translated_statements"])
            self.assertIn("CREATE TABLE IF NOT EXISTS tasks", external["plan"][0]["sql"])
            self.assertTrue(backup["ok"])
            self.assertGreater(backup["bytes"], 0)
            self.assertEqual(stat.S_IMODE((Path(temp) / "backup.db").stat().st_mode), 0o600)
            with sqlite3.connect(Path(temp) / "backup.db") as db:
                task_count = db.execute("SELECT COUNT(*) FROM tasks WHERE id = 'task-1'").fetchone()[0]
            self.assertEqual(task_count, 1)

    def test_external_migration_plan_rejects_unknown_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = LocalStore(Path(temp) / "aegis.db")

            with self.assertRaisesRegex(ValueError, "unsupported external migration target"):
                store.external_schema_plan("oracle")

    def test_external_migration_runner_writes_private_reviewable_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = LocalStore(Path(temp) / "aegis.db")
            output_dir = Path(temp) / "pg-runner"

            runner = store.external_schema_runner("postgresql", output_dir=output_dir)

            self.assertEqual(runner["operation"], "external_migration_runner")
            self.assertEqual(runner["target"], "postgresql")
            self.assertFalse(runner["connects_to_target"])
            self.assertEqual(runner["writes"], "operator_executed_only")
            self.assertTrue(Path(runner["runner_path"]).exists())
            self.assertEqual(stat.S_IMODE(output_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(Path(runner["manifest_path"]).stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(Path(runner["runner_path"]).stat().st_mode), 0o700)
            first_file = Path(runner["files"][0]["path"])
            self.assertEqual(stat.S_IMODE(first_file.stat().st_mode), 0o600)
            self.assertIn("-- checksum:", first_file.read_text(encoding="utf-8"))
            self.assertIn("psql", Path(runner["runner_path"]).read_text(encoding="utf-8"))
            self.assertNotIn("password", Path(runner["runner_path"]).read_text(encoding="utf-8").lower())
            manifest = json.loads(Path(runner["manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["latest_version"], 5)

            with self.assertRaises(FileExistsError):
                store.external_schema_runner("postgresql", output_dir=output_dir)

    def test_current_database_without_marker_is_baselined_without_data_loss(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "aegis.db"
            store = LocalStore(database)
            store.insert_task(
                task_id="task-1",
                user_request="Summarize project",
                interpretation="Read-only test",
                status="planned",
                plan=[],
                risk_level="low",
            )
            with sqlite3.connect(database) as db:
                db.execute("DROP TABLE schema_migrations")

            store = LocalStore(database)
            status = store.schema_status()

            self.assertEqual(status["current_version"], 5)
            with sqlite3.connect(database) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], 5)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM tasks WHERE id = 'task-1'").fetchone()[0], 1)

    def test_checksum_drift_fails_fast(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "aegis.db"
            with sqlite3.connect(database) as db:
                db.execute(
                    """
                    CREATE TABLE schema_migrations (
                      version INTEGER PRIMARY KEY,
                      name TEXT NOT NULL,
                      checksum TEXT NOT NULL,
                      applied_at TEXT NOT NULL
                    )
                    """
                )
                db.execute(
                    "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                    (1, "initial_schema", "bad-checksum", "2026-05-10T00:00:00+00:00"),
                )

            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                LocalStore(database)

    def test_legacy_migration_table_without_checksum_is_backfilled(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "aegis.db"
            with sqlite3.connect(database) as db:
                db.execute(
                    """
                    CREATE TABLE schema_migrations (
                      version INTEGER PRIMARY KEY,
                      name TEXT NOT NULL,
                      applied_at TEXT NOT NULL
                    )
                    """
                )
                db.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (1, "initial_schema", "2026-05-10T00:00:00+00:00"),
                )

            status = LocalStore(database).schema_status()

            self.assertEqual(status["applied"][0]["checksum"], MIGRATIONS[0].checksum)


if __name__ == "__main__":
    unittest.main()
