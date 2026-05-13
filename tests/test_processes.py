from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from aegis.agent.orchestrator import build_orchestrator


class ProcessRegistryTests(unittest.TestCase):
    def test_background_process_registry_gates_redacts_and_stops(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=workspace)

            gated = orchestrator.processes.start(["python3", "-c", "print('blocked')"])
            self.assertEqual(gated["status"], "approval_required")
            self.assertTrue(gated["approval_required"])
            self.assertFalse(gated["raw_command_included"])
            self.assertFalse(gated["raw_secret_values_included"])

            with self.assertRaisesRegex(ValueError, "secret-like"):
                orchestrator.processes.start(["python3", "-c", "print('blocked')", "api_key=abc123"], approved=True)

            started = orchestrator.processes.start(
                [
                    "python3",
                    "-c",
                    "import time; print('api_' + 'key=abc123', flush=True); time.sleep(30)",
                ],
                approved=True,
                actor="process-test",
                label="Redaction smoke",
            )
            process_id = started["process"]["id"]
            try:
                self.assertTrue(started["ok"])
                self.assertEqual(started["receipt"]["receipt_schema"], "aegis.process.v1")
                self.assertFalse(started["process"]["raw_command_included"])
                self.assertFalse(started["process"]["raw_secret_values_included"])
                self.assertFalse(started["process"]["pty_attached"])

                logs = _wait_for_log(orchestrator, process_id, "[REDACTED_VALUE]")
                self.assertIn("api_key=[REDACTED_VALUE]", logs["log"])
                self.assertNotIn("abc123", logs["log"])
                self.assertFalse(logs["raw_secret_values_included"])

                status = orchestrator.processes.status()
                self.assertEqual(status["status"], "process_registry_ready")
                self.assertIn("approval_required_start", status["implemented_controls"])
                self.assertIn("interactive_pty_attach", status["remaining_depth_work"])
                self.assertFalse(status["raw_command_included"])
                self.assertNotIn("api_key=abc123", json.dumps({"started": started, "status": status}, sort_keys=True))

                stopped = orchestrator.processes.stop(process_id, actor="process-test")
                self.assertTrue(stopped["ok"])
                self.assertEqual(stopped["receipt"]["receipt_schema"], "aegis.process.v1")
                self.assertFalse(stopped["receipt"]["raw_command_included"])
            finally:
                try:
                    orchestrator.processes.stop(process_id, actor="process-test-cleanup")
                except Exception:
                    pass


def _wait_for_log(orchestrator, process_id: str, expected: str) -> dict[str, object]:  # noqa: ANN001
    deadline = time.time() + 5
    latest: dict[str, object] = {}
    while time.time() < deadline:
        latest = orchestrator.processes.logs(process_id, max_bytes=4096)
        if expected in str(latest.get("log", "")):
            return latest
        time.sleep(0.05)
    return latest
