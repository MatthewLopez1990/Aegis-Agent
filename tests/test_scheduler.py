from __future__ import annotations

from datetime import UTC, datetime, timedelta
import tempfile
import unittest
from pathlib import Path

from aegis.agent.orchestrator import build_orchestrator
from aegis.config.loader import load_config
from aegis.memory.models import MemoryType
from aegis.scheduler.worker import ScheduleWorker
from aegis.security.policy_profile import schedule_policy_bundle


class SchedulerTests(unittest.TestCase):
    def test_activate_due_and_run_due_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            schedule = orchestrator.schedules.create_schedule(
                name="Hourly",
                natural_language="Hourly project report",
                cron="@hourly",
                task_request="Summarize project",
                channel="terminal",
            )

            with self.assertRaises(PermissionError):
                orchestrator.schedules.activate(schedule["id"])
            approved = orchestrator.schedules.approve(schedule["id"], approved_by="tester")
            self.assertEqual(approved["status"], "paused_approved")
            self.assertTrue(approved["metadata"]["approved"])
            active = orchestrator.schedules.activate(schedule["id"])
            self.assertEqual(active["status"], "active")
            orchestrator.store.update_schedule(
                schedule["id"],
                {"next_run_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat()},
            )
            self.assertEqual(len(orchestrator.schedules.due()), 1)

            result = orchestrator.run_due_schedules()

            self.assertEqual(result["ran"], 1)
            self.assertEqual(result["results"][0]["schedule_id"], schedule["id"])
            updated = orchestrator.schedules.get(schedule["id"])
            self.assertEqual(updated["metadata"]["last_task_id"], result["results"][0]["task_id"])
            self.assertIsNotNone(updated["last_run_at"])
            self.assertGreater(datetime.fromisoformat(updated["next_run_at"]), datetime.now(UTC))
            event_types = {event["event_type"] for event in orchestrator.audit_logger.tail(50)}
            self.assertIn("schedule.claimed", event_types)
            self.assertIn("schedule.ran", event_types)
            self.assertIn("schedule.run_due_completed", event_types)

    def test_due_schedule_claim_prevents_duplicate_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            second = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            schedule = first.schedules.create_schedule(
                name="Hourly",
                natural_language="Hourly project report",
                cron="@hourly",
                task_request="Summarize project",
                channel="terminal",
            )
            first.schedules.approve(schedule["id"])
            first.schedules.activate(schedule["id"])
            due_at = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
            first.store.update_schedule(schedule["id"], {"next_run_at": due_at})

            self.assertTrue(first.schedules.claim_due(schedule["id"], expected_next_run_at=due_at))
            self.assertFalse(second.schedules.claim_due(schedule["id"], expected_next_run_at=due_at))
            self.assertEqual(second.schedules.due(), [])

    def test_background_worker_runs_due_schedules(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            schedule = orchestrator.schedules.create_schedule(
                name="Hourly",
                natural_language="Hourly project report",
                cron="@hourly",
                task_request="Summarize project",
                channel="terminal",
            )
            orchestrator.schedules.approve(schedule["id"])
            orchestrator.schedules.activate(schedule["id"])
            orchestrator.store.update_schedule(
                schedule["id"],
                {"next_run_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat()},
            )

            result = ScheduleWorker(orchestrator, interval_seconds=60).run_once()

            updated = orchestrator.schedules.get(schedule["id"])
            self.assertEqual(result["schedules"]["ran"], 1)
            self.assertEqual(updated["status"], "active")
            self.assertIn("last_task_id", updated["metadata"])
            self.assertIsNotNone(updated["last_run_at"])

    def test_background_worker_activates_due_policy_rollouts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            scheduled = schedule_policy_bundle(
                "strict-local",
                data_dir=root / ".aegis",
                activate_at="2000-01-01T00:00:00Z",
                approved=True,
            )

            result = ScheduleWorker(orchestrator, interval_seconds=60).run_once()
            loaded = load_config(root / ".aegis")

            self.assertEqual(result["policy_activations"]["activated"], 1)
            self.assertEqual(result["policy_activations"]["results"][0]["id"], scheduled["id"])
            self.assertEqual(loaded.policy_profile.message_send, "require_admin_approval")
            event_types = {event["event_type"] for event in orchestrator.audit_logger.tail(20)}
            self.assertIn("maintenance.completed", event_types)

    def test_background_worker_cleans_expired_memories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            expired = orchestrator.memory.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Ephemeral purge target should expire during maintenance.",
                source="test",
                provenance={"case": "worker_cleanup"},
                confidence=0.9,
            )
            active = orchestrator.memory.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Durable retain target remains retrievable after maintenance.",
                source="test",
                provenance={"case": "worker_cleanup"},
                confidence=0.9,
            )
            stale = orchestrator.memory.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Confirmed memory should be recertified during maintenance.",
                source="test",
                provenance={"case": "worker_cleanup"},
                confidence=0.9,
                confirmed=True,
            )
            orchestrator.store.update_memory(expired.id, {"expires_at": "2000-01-01T00:00:00+00:00"})
            orchestrator.store.update_memory(active.id, {"expires_at": "2999-01-01T00:00:00+00:00"})
            orchestrator.store.update_memory(stale.id, {"last_confirmed_at": "2000-01-01T00:00:00+00:00"})

            result = ScheduleWorker(orchestrator, interval_seconds=60).run_once()

            self.assertEqual(result["memory_cleanup"]["memory_ids"], [expired.id])
            self.assertEqual(result["memory_recertification"]["memory_ids"], [stale.id])
            self.assertEqual(orchestrator.store.get_memory(expired.id)["deleted"], 1)
            self.assertTrue(orchestrator.memory.retrieve_relevant("Durable retain target"))
            self.assertTrue(any(item.get("memory_id") == stale.id for item in orchestrator.memory.review_queue()["items"]))
            event_types = {event["event_type"] for event in orchestrator.audit_logger.tail(20)}
            self.assertIn("memory.cleanup_expired", event_types)
            self.assertIn("memory.recertification_marked", event_types)
            self.assertIn("maintenance.completed", event_types)

    def test_background_worker_uses_configured_recertification_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            data_dir.mkdir()
            (data_dir / "config.toml").write_text(
                "\n".join(
                    [
                        "[runtime]",
                        f'data_dir = "{data_dir}"',
                        "",
                        "[memory]",
                        "default_recertification_days = 180",
                        "",
                        "[memory.recertification_days]",
                        "episodic_memory = 7",
                        "procedural_memory = 0",
                    ]
                ),
                encoding="utf-8",
            )
            orchestrator = build_orchestrator(data_dir=data_dir, workspace=root)
            episodic = orchestrator.memory.create_memory(
                memory_type=MemoryType.EPISODIC,
                content="Configured episodic recertification target.",
                source="test",
                provenance={"case": "worker_recertification_policy"},
                confidence=0.9,
                confirmed=True,
            )
            project = orchestrator.memory.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Configured project recertification should wait for default threshold.",
                source="test",
                provenance={"case": "worker_recertification_policy"},
                confidence=0.9,
                confirmed=True,
            )
            procedural = orchestrator.memory.create_memory(
                memory_type=MemoryType.PROCEDURAL,
                content="Configured procedural recertification disabled.",
                source="test",
                provenance={"case": "worker_recertification_policy"},
                confidence=0.9,
                confirmed=True,
            )
            orchestrator.store.update_memory(episodic.id, {"last_confirmed_at": "2026-04-01T00:00:00+00:00"})
            orchestrator.store.update_memory(project.id, {"last_confirmed_at": "2026-04-01T00:00:00+00:00"})
            orchestrator.store.update_memory(procedural.id, {"last_confirmed_at": "2000-01-01T00:00:00+00:00"})

            result = ScheduleWorker(orchestrator, interval_seconds=60).run_once()

            self.assertEqual(result["memory_recertification"]["policy"], "configured")
            self.assertEqual(result["memory_recertification"]["memory_ids"], [episodic.id])
            self.assertNotIn(project.id, result["memory_recertification"]["memory_ids"])
            self.assertNotIn(procedural.id, result["memory_recertification"]["memory_ids"])

    def test_due_memory_review_digest_schedule_renders_pending_channel_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            memory = orchestrator.memory.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Scheduled digest should surface tentative memory review work.",
                source="test",
                provenance={"case": "scheduled_digest"},
                confidence=0.55,
            )
            schedule = orchestrator.schedules.create_memory_review_digest_schedule(
                name="Daily memory review",
                cron="@daily",
                channel="slack",
                limit=5,
            )
            orchestrator.schedules.approve(schedule["id"], approved_by="reviewer")
            orchestrator.schedules.activate(schedule["id"])
            orchestrator.store.update_schedule(schedule["id"], {"next_run_at": "2000-01-01T00:00:00+00:00"})

            result = orchestrator.run_due_schedules()

            self.assertEqual(result["ran"], 1)
            self.assertEqual(result["results"][0]["kind"], "memory_review_digest")
            self.assertEqual(result["results"][0]["review_total"], 1)
            self.assertIn("Memory review digest", result["results"][0]["rendered"]["text"])
            updated = orchestrator.schedules.get(schedule["id"])
            self.assertEqual(updated["metadata"]["last_delivery_kind"], "memory_review_digest")
            self.assertEqual(updated["metadata"]["last_review_total"], 1)
            events = orchestrator.channels.events(limit=5)
            self.assertTrue(any(event["channel"] == "slack" and event["status"] == "rendered_pending_approval" for event in events))
            self.assertTrue(any(memory.id[:8] in event["normalized"].get("text", "") for event in events))
            event_types = {event["event_type"] for event in orchestrator.audit_logger.tail(50)}
            self.assertIn("memory.review_digest_generated", event_types)
            self.assertIn("channel.outbound_rendered", event_types)
            self.assertIn("schedule.memory_review_digest_delivered", event_types)

    def test_due_memory_review_escalation_schedule_renders_pending_channel_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            memory = orchestrator.memory.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Scheduled escalation should surface overdue memory review work.",
                source="test",
                provenance={"case": "scheduled_escalation"},
                confidence=0.55,
            )
            with orchestrator.store.connect() as db:
                db.execute(
                    "UPDATE memories SET created_at = ?, updated_at = ? WHERE id = ?",
                    ("2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", memory.id),
                )
            schedule = orchestrator.schedules.create_memory_review_escalation_schedule(
                name="Daily memory escalation",
                cron="@daily",
                channel="slack",
                max_age_days=7,
                limit=5,
                route="memory-ops",
            )
            orchestrator.schedules.approve(schedule["id"], approved_by="reviewer")
            orchestrator.schedules.activate(schedule["id"])
            orchestrator.store.update_schedule(schedule["id"], {"next_run_at": "2000-01-01T00:00:00+00:00"})

            result = orchestrator.run_due_schedules()

            self.assertEqual(result["ran"], 1)
            self.assertEqual(result["results"][0]["kind"], "memory_review_escalation")
            self.assertEqual(result["results"][0]["review_overdue"], 1)
            self.assertIn("Memory review escalation", result["results"][0]["rendered"]["text"])
            updated = orchestrator.schedules.get(schedule["id"])
            self.assertEqual(updated["metadata"]["last_delivery_kind"], "memory_review_escalation")
            self.assertEqual(updated["metadata"]["last_review_overdue"], 1)
            events = orchestrator.channels.events(limit=5)
            self.assertTrue(any(event["channel"] == "slack" and event["status"] == "rendered_pending_approval" for event in events))
            self.assertTrue(any("memory-ops" in event["normalized"].get("text", "") for event in events))
            event_types = {event["event_type"] for event in orchestrator.audit_logger.tail(50)}
            self.assertIn("memory.review_escalation_generated", event_types)
            self.assertIn("channel.outbound_rendered", event_types)
            self.assertIn("schedule.memory_review_escalation_delivered", event_types)

    def test_due_evaluation_run_schedule_persists_report_and_renders_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            schedule = orchestrator.schedules.create_evaluation_run_schedule(
                name="Nightly evaluation",
                cron="@daily",
                scenario="policy regression",
                steps=("seed", "run gates", "review digest"),
                channel="slack",
            )
            orchestrator.schedules.approve(schedule["id"], approved_by="reviewer")
            orchestrator.schedules.activate(schedule["id"])
            orchestrator.store.update_schedule(schedule["id"], {"next_run_at": "2000-01-01T00:00:00+00:00"})

            result = orchestrator.run_due_schedules()

            self.assertEqual(result["ran"], 1)
            scheduled = result["results"][0]
            self.assertEqual(scheduled["kind"], "evaluation_run")
            self.assertEqual(scheduled["scenario"], "policy regression")
            self.assertEqual(scheduled["evaluation_trends"]["by_status"], {"scheduled": 1})
            self.assertTrue(Path(scheduled["report_path"]).exists())
            self.assertIn("Evaluation run digest", scheduled["rendered"]["text"])
            updated = orchestrator.schedules.get(schedule["id"])
            self.assertEqual(updated["metadata"]["last_delivery_kind"], "evaluation_run")
            self.assertEqual(updated["metadata"]["last_evaluation_report_id"], scheduled["report_id"])
            events = orchestrator.channels.events(limit=5)
            self.assertTrue(any(event["channel"] == "slack" and event["status"] == "rendered_pending_approval" for event in events))
            event_types = {event["event_type"] for event in orchestrator.audit_logger.tail(50)}
            self.assertIn("channel.outbound_rendered", event_types)
            self.assertIn("schedule.evaluation_run_delivered", event_types)

    def test_due_evaluation_suite_schedule_assigns_reviewer_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            schedule = orchestrator.schedules.create_evaluation_suite_schedule(
                name="Security suite",
                cron="@daily",
                suite="security",
                scenario_ids=("prompt_injection.file_content", "memory_poisoning.secret_storage"),
                channel="slack",
                reviewer="security-reviewer",
            )
            orchestrator.schedules.approve(schedule["id"], approved_by="reviewer")
            orchestrator.schedules.activate(schedule["id"])
            orchestrator.store.update_schedule(schedule["id"], {"next_run_at": "2000-01-01T00:00:00+00:00"})

            result = orchestrator.run_due_schedules()

            self.assertEqual(result["ran"], 1)
            scheduled = result["results"][0]
            self.assertEqual(scheduled["kind"], "evaluation_suite")
            self.assertEqual(scheduled["suite"], "security")
            self.assertEqual(scheduled["reviewer"], "security-reviewer")
            self.assertEqual(scheduled["report_count"], 2)
            self.assertEqual(scheduled["review_queue"]["total"], 2)
            self.assertIn("Evaluation suite digest", scheduled["rendered"]["text"])
            updated = orchestrator.schedules.get(schedule["id"])
            self.assertEqual(updated["metadata"]["last_delivery_kind"], "evaluation_suite")
            self.assertEqual(updated["metadata"]["last_evaluation_report_count"], 2)
            event_types = {event["event_type"] for event in orchestrator.audit_logger.tail(50)}
            self.assertIn("schedule.evaluation_suite_delivered", event_types)

    def test_pause_removes_schedule_from_due_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            schedule = orchestrator.schedules.create_schedule(
                name="Daily",
                natural_language="Daily report",
                cron="@daily",
                task_request="Summarize project",
            )

            orchestrator.schedules.approve(schedule["id"])
            orchestrator.schedules.activate(schedule["id"])
            paused = orchestrator.schedules.pause(schedule["id"])
            orchestrator.store.update_schedule(
                schedule["id"],
                {"next_run_at": (datetime.now(UTC) - timedelta(days=1)).isoformat()},
            )

            self.assertEqual(paused["status"], "paused")
            self.assertEqual(orchestrator.schedules.due(), [])


if __name__ == "__main__":
    unittest.main()
