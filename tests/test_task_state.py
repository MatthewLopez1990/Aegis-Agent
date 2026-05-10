from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegis.agent.orchestrator import build_orchestrator


class TaskStateTests(unittest.TestCase):
    def test_submit_task_creates_durable_record_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Agent.md").write_text("Aegis Agent", encoding="utf-8")
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)

            result = orchestrator.submit_task("Summarize my project safely.", path=".")
            task = orchestrator.store.get_task(result["id"])

            self.assertEqual(result["status"], "completed")
            self.assertIsNotNone(task)
            self.assertIsNotNone(result["receipt"])
            self.assertEqual(result["receipt"]["approval_status"], "not_required")
            self.assertTrue(orchestrator.audit_logger.verify_chain())

    def test_high_risk_message_requires_approval_then_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)

            result = orchestrator.submit_task("send message hello")
            self.assertEqual(result["status"], "waiting_approval")
            approval_id = result["checkpoint"]["approval_id"]

            orchestrator.approvals.approve(approval_id)
            resumed = orchestrator.resume_task(result["id"])

            self.assertEqual(resumed["status"], "completed")
            self.assertEqual(resumed["receipt"]["approval_status"], "approved")


if __name__ == "__main__":
    unittest.main()
