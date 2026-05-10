from __future__ import annotations

import tempfile
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
