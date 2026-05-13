from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from aegis.agent.orchestrator import build_orchestrator
from aegis.audit.logger import AuditLogger
from aegis.hooks.manager import HookManager


class HookManagerTests(unittest.TestCase):
    def test_hook_manager_runs_allowlisted_argv_hooks_with_redacted_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit = AuditLogger(root / "audit.jsonl")
            manager = HookManager(root / "hooks.json", audit, allowed_executables=("python3",), workspace=root)

            hook = manager.register_hook(
                event="manual",
                command=[
                    "python3",
                    "-c",
                    "import json, sys; data=json.load(sys.stdin); print(data['context']['message']); print('sk-1234567890abcdef')",
                    "token=abc123",
                ],
                hook_id="notify",
                enabled=True,
                approval_required=False,
            )
            result = manager.run_event("manual", context={"message": "hello"})

            self.assertEqual(hook["command"][-1], "token=[REDACTED_VALUE]")
            self.assertEqual(result["ran_count"], 1)
            self.assertEqual(result["results"][0]["status"], "completed")
            self.assertIn("hello", result["results"][0]["stdout"])
            self.assertNotIn("sk-1234567890abcdef", json.dumps(result, sort_keys=True))
            self.assertNotIn("sk-1234567890abcdef", (root / "audit.jsonl").read_text(encoding="utf-8"))

    def test_hook_manager_requires_approval_and_rejects_unallowlisted_executables(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = HookManager(root / "hooks.json", AuditLogger(root / "audit.jsonl"), allowed_executables=("python3",), workspace=root)

            manager.register_hook(event="manual", command=["python3", "-c", "print('blocked')"], hook_id="needs_review", enabled=True)
            skipped = manager.run_event("manual", context={})

            self.assertEqual(skipped["skipped_count"], 1)
            self.assertEqual(skipped["results"][0]["reason"], "approval_required")
            with self.assertRaises(PermissionError):
                manager.register_hook(event="manual", command=["bash", "-lc", "echo no"], hook_id="bad")

    @unittest.skipUnless(os.name == "posix", "POSIX mode assertions only apply on POSIX")
    def test_hook_store_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = HookManager(root / "hooks.json", AuditLogger(root / "audit.jsonl"), allowed_executables=("python3",), workspace=root)

            manager.register_hook(event="manual", command=["python3", "-c", "print('ok')"], hook_id="private")

            self.assertEqual(stat.S_IMODE((root / "hooks.json").stat().st_mode), 0o600)

    def test_task_lifecycle_hooks_run_without_breaking_task_submission(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            orchestrator.hooks.register_hook(
                event="task.completed",
                command=["python3", "-c", "import json, sys; data=json.load(sys.stdin); print(data['context']['task_id'])"],
                hook_id="task_done",
                enabled=True,
                approval_required=False,
            )

            result = orchestrator.submit_task("Summarize the hook lifecycle smoke.")
            events = orchestrator.audit_logger.events(task_id=result["id"], event_type="hook.run")

            self.assertEqual(result["status"], "completed")
            self.assertTrue(any(event["payload"]["hook_id"] == "task_done" for event in events))
            self.assertTrue(any(result["id"] in event["payload"]["stdout"] for event in events))


if __name__ == "__main__":
    unittest.main()
