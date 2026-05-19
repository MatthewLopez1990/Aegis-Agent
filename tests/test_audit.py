from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from aegis.agent.orchestrator import build_orchestrator
from aegis.audit.logger import AuditLogger
from aegis.memory.models import MemoryType
from aegis.skills.runtime import SkillRuntime


class AuditTests(unittest.TestCase):
    def test_audit_redacts_secrets_and_verifies_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            audit = AuditLogger(path)
            audit.append("test.event", {"api_key": "real-secret", "nested": {"password": "pw", "ok": "value"}})

            text = path.read_text(encoding="utf-8")
            self.assertNotIn("real-secret", text)
            self.assertNotIn('"pw"', text)
            self.assertIn("[REDACTED]", text)
            self.assertTrue(audit.verify_chain())

    def test_audit_redacts_secret_like_values_in_string_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            audit = AuditLogger(path)

            audit.append("task.created", {"user_request": "summarize token: abc123 and sk-1234567890abcdef"})

            text = path.read_text(encoding="utf-8")
            self.assertNotIn("abc123", text)
            self.assertNotIn("sk-1234567890abcdef", text)
            self.assertIn("[REDACTED_VALUE]", text)
            self.assertTrue(audit.verify_chain())

    def test_parallel_audit_appends_keep_hash_chain_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            start = threading.Barrier(6)

            def append_events(worker: int) -> None:
                audit = AuditLogger(path)
                start.wait()
                for index in range(25):
                    audit.append("parallel.event", {"worker": worker, "index": index})

            threads = [threading.Thread(target=append_events, args=(worker,)) for worker in range(5)]
            for thread in threads:
                thread.start()
            start.wait()
            for thread in threads:
                thread.join()

            audit = AuditLogger(path)
            self.assertTrue(audit.verify_chain())
            self.assertEqual(len(audit.events()), 125)

    def test_audit_can_query_full_task_history_beyond_recent_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            audit = AuditLogger(path)

            audit.append("task.created", {"step": 1}, task_id="task-1")
            for index in range(75):
                audit.append("runtime.noise", {"index": index})
            audit.append("task.completed", {"step": 2}, task_id="task-1")

            task_events = audit.for_task("task-1")

            self.assertEqual([event["event_type"] for event in task_events], ["task.created", "task.completed"])
            self.assertFalse(any(event.get("task_id") == "task-1" for event in audit.tail(50)[:-1]))

    def test_audit_exports_redacted_siem_jsonl_with_chain_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            audit = AuditLogger(path)

            audit.append("task.created", {"api_key": "real-secret", "note": "summarize token: abc123"}, task_id="task-1")
            audit.append("policy.decision", {"decision": "allow"}, task_id="task-1")
            audit.append("runtime.noise", {"ok": True}, task_id="task-2")

            exported = audit.export_siem(limit=10, task_id="task-1")
            jsonl = exported["jsonl"]

            self.assertEqual(exported["format"], "jsonl")
            self.assertEqual(exported["schema"], "aegis.audit.siem.v1")
            self.assertTrue(exported["chain_ok"])
            self.assertEqual(exported["count"], 2)
            self.assertNotIn("real-secret", jsonl)
            self.assertNotIn("abc123", jsonl)
            self.assertIn("[REDACTED]", jsonl)
            self.assertIn("[REDACTED_VALUE]", jsonl)
            self.assertEqual(exported["events"][0]["event"]["action"], "task.created")
            self.assertEqual(exported["events"][0]["event"]["category"], "process")
            self.assertEqual(exported["events"][0]["aegis"]["task_id"], "task-1")
            self.assertIn("prev_hash", exported["events"][0]["aegis"])
            self.assertIn("event_hash", path.read_text(encoding="utf-8"))

    def test_audit_events_cover_major_subsystems(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "README.md").write_text("Aegis Agent", encoding="utf-8")
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)

            orchestrator.submit_task("Summarize my project safely.", path=".")
            high_risk = orchestrator.submit_task("send message hello")
            orchestrator.approvals.approve(high_risk["checkpoint"]["approval_id"])
            orchestrator.resume_task(high_risk["id"])
            orchestrator.memory.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Audit integration test memory.",
                source="test",
                provenance={"test": "audit"},
                confidence=0.9,
            )
            runtime = SkillRuntime(orchestrator.skills, orchestrator.connectors, orchestrator.audit_logger)
            runtime.invoke(
                "aegis.project_summary",
                {"path": "."},
                requested_permissions={"connectors": ["filesystem"], "filesystem": {"read": True}},
            )

            event_types = {event["event_type"] for event in orchestrator.audit_logger.tail(100)}

            self.assertIn("task.created", event_types)
            self.assertIn("policy.decision", event_types)
            self.assertIn("connector.called", event_types)
            self.assertIn("receipt.generated", event_types)
            self.assertIn("approval.requested", event_types)
            self.assertIn("approval.approved", event_types)
            self.assertIn("memory.created", event_types)
            self.assertIn("skill.invoked", event_types)


if __name__ == "__main__":
    unittest.main()
