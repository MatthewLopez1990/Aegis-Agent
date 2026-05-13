from __future__ import annotations

import json
import os
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
                self.assertIn("interactive_pty_attach", status["implemented_controls"])
                self.assertIn("stdin_streaming", status["implemented_controls"])
                self.assertIn("terminal_resize_events", status["implemented_controls"])
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

    @unittest.skipIf(os.name != "posix", "PTY process controls require POSIX")
    def test_pty_process_accepts_guarded_stdin_and_resize_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=workspace)

            started = orchestrator.processes.start(
                [
                    "python3",
                    "-c",
                    "import sys, time; line=sys.stdin.readline().strip(); print('pty:' + line, flush=True); time.sleep(30)",
                ],
                approved=True,
                actor="process-test",
                label="PTY smoke",
                pty=True,
                rows=20,
                cols=60,
            )
            process_id = started["process"]["id"]
            try:
                self.assertTrue(started["ok"])
                self.assertTrue(started["process"]["pty_attached"])
                self.assertTrue(started["process"]["stdin_streaming"])
                self.assertEqual(started["process"]["terminal_rows"], 20)
                self.assertEqual(started["process"]["terminal_cols"], 60)

                resized = orchestrator.processes.resize(process_id, rows=32, cols=100, actor="process-test")
                sent = orchestrator.processes.send_input(process_id, "hello-pty", actor="process-test")
                logs = _wait_for_log(orchestrator, process_id, "pty:hello-pty")

                self.assertTrue(resized["ok"])
                self.assertEqual(resized["receipt"]["event_type"], "process.resized")
                self.assertEqual(resized["receipt"]["rows"], 32)
                self.assertEqual(resized["receipt"]["cols"], 100)
                self.assertTrue(sent["ok"])
                self.assertEqual(sent["receipt"]["event_type"], "process.stdin_sent")
                self.assertFalse(sent["receipt"]["raw_input_included"])
                self.assertNotIn("hello-pty", json.dumps({"resized": resized, "sent": sent}, sort_keys=True))
                self.assertIn("pty:hello-pty", logs["log"])
                status = orchestrator.processes.status()
                self.assertEqual(status["remaining_depth_work"], [])

                with self.assertRaisesRegex(ValueError, "secret-like"):
                    orchestrator.processes.send_input(process_id, "api_key=abc123", actor="process-test")
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
