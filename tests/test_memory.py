from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegis.audit.logger import AuditLogger
from aegis.memory.manager import MemoryManager, MemorySafetyError
from aegis.memory.models import MemoryType
from aegis.memory.store import LocalStore
from aegis.security.taint import Sensitivity


class MemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        base = Path(self.tempdir.name)
        self.store = LocalStore(base / "aegis.db")
        self.audit = AuditLogger(base / "audit.jsonl")
        self.manager = MemoryManager(self.store, self.audit)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_memory_crud_with_provenance_and_confidence(self) -> None:
        record = self.manager.create_memory(
            memory_type=MemoryType.PROJECT,
            content="The project uses a local-first SQLite store.",
            source="test",
            provenance={"file": "README.md"},
            confidence=0.9,
            tags=("sqlite",),
        )

        results = self.manager.retrieve_relevant("SQLite")
        self.assertEqual(results[0]["id"], record.id)
        self.assertEqual(results[0]["provenance"]["file"], "README.md")
        self.assertEqual(results[0]["confidence"], 0.9)

        updated = self.manager.update_memory(record.id, content="The project uses SQLite for durable task state.", confidence=0.95)
        self.assertEqual(updated["confidence"], 0.95)

        self.manager.delete_memory(record.id)
        self.assertEqual(self.manager.retrieve_relevant("SQLite"), [])

    def test_refuses_secret_like_memory(self) -> None:
        with self.assertRaises(MemorySafetyError):
            self.manager.create_memory(
                memory_type=MemoryType.PROFILE,
                content="My api key is abc123.",
                source="test",
                provenance={},
                confidence=0.9,
            )

    def test_sensitive_or_uncertain_memory_requires_confirmation(self) -> None:
        with self.assertRaises(MemorySafetyError):
            self.manager.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Confidential project detail.",
                source="test",
                provenance={},
                confidence=0.9,
                sensitivity=Sensitivity.CONFIDENTIAL,
            )
        with self.assertRaises(MemorySafetyError):
            self.manager.create_memory(
                memory_type=MemoryType.PROJECT,
                content="Maybe this is true.",
                source="test",
                provenance={},
                confidence=0.2,
            )

    def test_memory_conflict_merge_and_expire(self) -> None:
        first = self.manager.create_memory(
            memory_type=MemoryType.PREFERENCE,
            content="Prefer concise status updates for this workspace.",
            source="test",
            provenance={"turn": 1},
            confidence=0.8,
            scope="workspace",
            tags=("preference",),
        )
        second = self.manager.create_memory(
            memory_type=MemoryType.PREFERENCE,
            content="Prefer detailed status updates for this workspace.",
            source="test",
            provenance={"turn": 2},
            confidence=0.7,
            scope="workspace",
            tags=("preference", "conflict"),
        )

        conflicts = self.manager.detect_conflicts("Prefer detailed status updates for this workspace.", scope="workspace")
        self.assertTrue(any(memory["id"] == first.id for memory in conflicts))

        merged = self.manager.merge_duplicate(first.id, second.id)
        self.assertIn("conflict", merged["tags"])
        duplicate_row = self.store.get_memory(second.id)
        self.assertIsNotNone(duplicate_row)
        self.assertEqual(duplicate_row["deleted"], 1)

        expired = self.manager.expire_memory(first.id)
        self.assertTrue(expired["deleted"])


if __name__ == "__main__":
    unittest.main()
