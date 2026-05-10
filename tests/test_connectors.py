from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegis.connectors.base import ConnectorRequest
from aegis.connectors.filesystem import LocalFilesystemConnector
from aegis.connectors.mock_messaging import MockMessagingConnector
from aegis.connectors.github import GitHubConnectorStub
from aegis.connectors.shell import ShellConnector


class ConnectorTests(unittest.TestCase):
    def test_filesystem_read_scope_and_dry_run_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "note.txt").write_text("hello", encoding="utf-8")
            connector = LocalFilesystemConnector(root)

            result = connector.read(ConnectorRequest(operation="read", params={"path": "note.txt"}, scopes=("read",)))
            self.assertTrue(result.ok)
            self.assertEqual(result.data["content"], "hello")

            dry_run = connector.dry_run(ConnectorRequest(operation="dry_run_write", params={"path": "out.txt", "content": "x"}, scopes=("write",)))
            self.assertTrue(dry_run.ok)
            self.assertEqual(dry_run.data["bytes"], 1)

            denied = connector.write(ConnectorRequest(operation="write", params={"path": "out.txt", "content": "x"}, scopes=("write",), approved=True))
            self.assertFalse(denied.ok)

            with self.assertRaises(PermissionError):
                connector.read(ConnectorRequest(operation="read", params={"path": "../outside.txt"}, scopes=("read",)))

    def test_shell_rejects_unallowlisted_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            connector = ShellConnector(temp, allowed_commands=("pwd",))
            with self.assertRaises(PermissionError):
                connector.dry_run(ConnectorRequest(operation="execute", params={"command": "rm -rf ."}, scopes=("execute",)))

    def test_mock_messaging_write_requires_approval(self) -> None:
        connector = MockMessagingConnector()
        result = connector.write(ConnectorRequest(operation="send_message", params={"text": "hello"}, scopes=("write",)))
        self.assertFalse(result.ok)

    def test_github_stub_supports_mock_read_and_approval_gated_write(self) -> None:
        connector = GitHubConnectorStub()
        read = connector.read(ConnectorRequest(operation="read_repo", scopes=("read",)))
        write = connector.write(ConnectorRequest(operation="create_issue", params={"title": "x"}, scopes=("write",)))

        self.assertTrue(read.ok)
        self.assertEqual(read.connector, "github")
        self.assertFalse(write.ok)


if __name__ == "__main__":
    unittest.main()
