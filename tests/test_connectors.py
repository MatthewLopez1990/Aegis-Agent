from __future__ import annotations

from email.message import Message
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from aegis.agent.planner import PlanStep
from aegis.agent.tool_router import ToolRouter
from aegis.audit.logger import AuditLogger
from aegis.connectors.base import ConnectorRequest
from aegis.connectors.filesystem import LocalFilesystemConnector
from aegis.connectors.http import HttpConnector
from aegis.connectors.mock_messaging import MockMessagingConnector
from aegis.connectors.mock_graph import MockGraphConnector
from aegis.connectors.mock_servicenow import MockServiceNowConnector
from aegis.connectors.github import GitHubConnectorStub
from aegis.connectors.gitlab import GitLabConnectorStub
from aegis.connectors.registry import ConnectorRegistry
from aegis.connectors.rest import GenericRestConnector
from aegis.connectors.shell import ShellConnector
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.policy_engine import PolicyEngine, PolicyRequest
from aegis.security.taint import RiskLevel


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

            with self.assertRaisesRegex(PermissionError, "requires 'read' scope"):
                connector.read(ConnectorRequest(operation="read", params={"path": "note.txt"}, scopes=()))

            with self.assertRaisesRegex(PermissionError, "requires 'write' scope"):
                connector.dry_run(ConnectorRequest(operation="dry_run_write", params={"path": "out.txt", "content": "x"}, scopes=()))

    def test_tool_router_denies_missing_connector_scope_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "note.txt").write_text("secret-ish local content", encoding="utf-8")
            connector = LocalFilesystemConnector(root)
            audit = AuditLogger(root / "audit.jsonl")
            registry = ConnectorRegistry(audit)
            registry.register(connector)
            router = ToolRouter(registry, audit)

            result = router.route(
                PlanStep(
                    id="read-1",
                    description="read without scope",
                    connector="filesystem",
                    operation="read",
                    params={"path": "note.txt"},
                    scopes=(),
                    risk_level=RiskLevel.LOW,
                )
            )

            self.assertFalse(result.ok)
            self.assertIn("missing required connector scope", result.error)
            self.assertEqual(result.data, {})

    def test_tool_router_uses_connector_declared_operation_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit = AuditLogger(root / "audit.jsonl")
            registry = ConnectorRegistry(audit)
            registry.register(MockGraphConnector())
            registry.register(MockServiceNowConnector())
            router = ToolRouter(registry, audit)

            calendar = router.route(
                PlanStep(
                    id="calendar-1",
                    description="read calendar",
                    connector="mock_graph",
                    operation="read_calendar",
                    params={},
                    scopes=("read",),
                    risk_level=RiskLevel.LOW,
                )
            )
            self.assertTrue(calendar.ok)
            self.assertIn("events", calendar.data["data"])

            create_event_without_write = router.route(
                PlanStep(
                    id="event-1",
                    description="create event with read scope only",
                    connector="mock_graph",
                    operation="create_event",
                    params={"subject": "standup"},
                    scopes=("read",),
                    risk_level=RiskLevel.HIGH,
                )
            )
            self.assertFalse(create_event_without_write.ok)
            self.assertIn("write", create_event_without_write.error or "")

            create_event_dry_run = router.route(
                PlanStep(
                    id="event-2",
                    description="create event with write scope",
                    connector="mock_graph",
                    operation="create_event",
                    params={"subject": "standup"},
                    scopes=("write",),
                    risk_level=RiskLevel.HIGH,
                )
            )
            self.assertTrue(create_event_dry_run.ok)
            self.assertEqual(create_event_dry_run.operation, "dry_run")

            close_ticket_without_write = router.route(
                PlanStep(
                    id="ticket-1",
                    description="close ticket with read scope only",
                    connector="mock_servicenow",
                    operation="close_ticket",
                    params={"id": "INC000001"},
                    scopes=("read",),
                    risk_level=RiskLevel.HIGH,
                )
            )
            self.assertFalse(close_ticket_without_write.ok)
            self.assertIn("write", close_ticket_without_write.error or "")

    def test_connector_list_exposes_operation_policy_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            audit = AuditLogger(Path(temp) / "audit.jsonl")
            registry = ConnectorRegistry(audit)
            registry.register(MockGraphConnector())

            graph = registry.list()[0]

            self.assertEqual(graph["required_scopes"], ["read"])
            self.assertEqual(graph["optional_scopes"], ["write"])
            self.assertEqual(graph["operation_scopes"]["create_event"], ["write"])
            self.assertEqual(graph["operation_scopes"]["read_calendar"], ["read"])
            self.assertEqual(graph["risk_by_operation"]["create_event"], "high")
            self.assertEqual(graph["data_sensitivity"], "internal")
            self.assertEqual(graph["rate_limits"]["per_minute"], 60)

    def test_policy_treats_connector_specific_writes_as_writes(self) -> None:
        policy = PolicyEngine()

        decision = policy.evaluate(
            PolicyRequest(
                user_role="local-user",
                workspace=".",
                task_type="connector write",
                risk_level=RiskLevel.HIGH,
                connector="mock_servicenow",
                operation="close_ticket",
                requested_scopes=("read",),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertIn("write scope", " ".join(decision.reasons))

    def test_shell_rejects_unallowlisted_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            connector = ShellConnector(temp, allowed_commands=("pwd",))
            with self.assertRaises(PermissionError):
                connector.dry_run(ConnectorRequest(operation="execute", params={"command": "rm -rf ."}, scopes=("execute",)))
            with self.assertRaises(PermissionError):
                connector.dry_run(ConnectorRequest(operation="execute", params={"command": f"{temp}/pwd"}, scopes=("execute",)))
            with self.assertRaises(PermissionError):
                connector.dry_run(ConnectorRequest(operation="execute", params={"command": "./pwd"}, scopes=("execute",)))
            with self.assertRaisesRegex(PermissionError, "requires 'execute' scope"):
                connector.dry_run(ConnectorRequest(operation="execute", params={"command": "pwd"}, scopes=()))

    def test_shell_rejects_dangerous_args_for_allowlisted_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            connector = ShellConnector(temp, allowed_commands=("pwd", "ls", "find", "python", "python3"))

            self.assertTrue(connector.dry_run(ConnectorRequest(operation="execute", params={"command": "pwd"}, scopes=("execute",))).ok)
            self.assertEqual(
                connector.dry_run(ConnectorRequest(operation="execute", params={"command": "ls -la ."}, scopes=("execute",))).data["argv"],
                ["ls", "-la", "."],
            )
            self.assertTrue(connector.dry_run(ConnectorRequest(operation="execute", params={"command": "python3 --version"}, scopes=("execute",))).ok)

            for command in (
                "pwd .",
                "ls /",
                "ls ../outside",
                "ls --color=always",
                "find . -exec sh -c whoami ;",
                "find . -delete",
                "python3 -c 'print(1)'",
                "python3 -m http.server",
                "python3",
                "python script.py",
            ):
                with self.subTest(command=command):
                    with self.assertRaises(PermissionError):
                        connector.dry_run(ConnectorRequest(operation="execute", params={"command": command}, scopes=("execute",)))

    def test_mock_messaging_write_requires_approval(self) -> None:
        connector = MockMessagingConnector()
        result = connector.write(ConnectorRequest(operation="send_message", params={"text": "hello"}, scopes=("write",)))
        self.assertFalse(result.ok)
        unsupported_read = connector.read(ConnectorRequest(operation="delete_channel", params={}, scopes=("read",)))
        self.assertFalse(unsupported_read.ok)
        self.assertIn("unsupported", unsupported_read.error or "")
        unsupported_write = connector.write(ConnectorRequest(operation="unknown_write", params={}, scopes=("write",), approved=True))
        self.assertFalse(unsupported_write.ok)
        self.assertIn("unsupported", unsupported_write.error or "")
        with self.assertRaisesRegex(PermissionError, "requires 'write' scope"):
            connector.write(ConnectorRequest(operation="send_message", params={"text": "hello"}, scopes=()))

    def test_mock_messaging_live_write_requires_approval_secret_and_summarizes_payload(self) -> None:
        broker = SecretsBroker()
        disabled = MockMessagingConnector(allowlist=("example.com",), live_writes=False, secrets_broker=broker)
        connector = MockMessagingConnector(allowlist=("example.com",), live_writes=True, secrets_broker=broker)
        live_params = {
            "provider_url": "https://example.com/hooks/messages",
            "channel": "general",
            "text": "please post token=abc123",
        }
        unapproved = connector.write(ConnectorRequest(operation="send_message", params=live_params, scopes=("write",)))
        disabled_write = disabled.write(ConnectorRequest(operation="send_message", params=live_params, scopes=("write",), approved=True))
        missing_secret = connector.write(ConnectorRequest(operation="send_message", params=live_params, scopes=("write",), approved=True))
        non_https = connector.write(
            ConnectorRequest(
                operation="send_message",
                params={**live_params, "provider_url": "http://chat.example.com/hooks/messages"},
                scopes=("write",),
                approved=True,
            )
        )
        off_allowlist = connector.write(
            ConnectorRequest(
                operation="send_message",
                params={**live_params, "provider_url": "https://evil.test/hooks/messages"},
                scopes=("write",),
                approved=True,
            )
        )
        private_target = MockMessagingConnector(allowlist=("127.0.0.1",), live_writes=True, secrets_broker=broker).write(
            ConnectorRequest(
                operation="send_message",
                params={**live_params, "provider_url": "https://127.0.0.1/hooks/messages"},
                scopes=("write",),
                approved=True,
            )
        )
        broker.store_secret(name="MESSAGING_TOKEN", value="msg_raw_secret")

        class FakeResponse:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b'{"ok":true}'

        captured: dict[str, object] = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.headers.get("Authorization")
            captured["body"] = request.data.decode("utf-8")
            return FakeResponse()

        with patch("aegis.connectors.mock_messaging._open_without_redirects", side_effect=fake_open):
            live = connector.write(ConnectorRequest(operation="send_message", params=live_params, scopes=("write",), approved=True))

        rendered = json.dumps(live.data, sort_keys=True)
        self.assertFalse(unapproved.ok)
        self.assertIn("approval", unapproved.error)
        self.assertFalse(disabled_write.ok)
        self.assertIn("disabled", disabled_write.error)
        self.assertFalse(missing_secret.ok)
        self.assertIn("not configured", missing_secret.error)
        self.assertFalse(non_https.ok)
        self.assertIn("https", non_https.error)
        self.assertFalse(off_allowlist.ok)
        self.assertIn("not allowlisted", off_allowlist.error)
        self.assertFalse(private_target.ok)
        self.assertIn("private", private_target.error or "")
        self.assertTrue(live.ok)
        self.assertEqual(live.data["mode"], "live_write")
        self.assertEqual(live.data["status"], 202)
        self.assertEqual(captured["url"], "https://example.com/hooks/messages")
        self.assertEqual(captured["authorization"], "Bearer msg_raw_secret")
        self.assertIn('"channel": "general"', str(captured["body"]))
        self.assertNotIn("msg_raw_secret", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertNotIn("please post token", rendered)
        self.assertIn("param_sha256", live.data["accepted"])
        self.assertEqual(live.data["accepted"]["receipt_schema"], "redacted_param_summary_v1")
        self.assertFalse(live.data["accepted"]["raw_secret_values_included"])
        self.assertFalse(live.data["accepted"]["raw_response_body_included"])

    def test_mock_connector_results_summarize_and_redact_params(self) -> None:
        connector = MockMessagingConnector()
        params = {
            "text": "please send token=abc123",
            "authorization": "Bearer raw-secret",
            "nested": {"password": "pw123", "safe": "visible"},
        }

        dry_run = connector.dry_run(ConnectorRequest(operation="send_message", params=params, scopes=("write",)))
        written = connector.write(ConnectorRequest(operation="send_message", params=params, scopes=("write",), approved=True))
        rollback = connector.rollback(ConnectorRequest(operation="rollback", params=params, scopes=("write",), approved=True))

        for result, key in ((dry_run, "params"), (written, "accepted"), (rollback, "rolled_back")):
            with self.subTest(operation=result.operation):
                self.assertTrue(result.ok)
                summary = result.data[key]
                rendered = json.dumps(summary, sort_keys=True)
                self.assertEqual(summary["param_keys"], ["authorization", "nested", "text"])
                self.assertEqual(summary["receipt_schema"], "redacted_param_summary_v1")
                self.assertIn("param_sha256", summary)
                self.assertFalse(summary["raw_secret_values_included"])
                self.assertFalse(summary["raw_response_body_included"])
                self.assertIn("redacted_preview", summary)
                self.assertNotIn("abc123", rendered)
                self.assertNotIn("raw-secret", rendered)
                self.assertNotIn("pw123", rendered)
                self.assertNotIn("please send token", rendered)

    def test_github_stub_supports_mock_read_and_approval_gated_write(self) -> None:
        connector = GitHubConnectorStub()
        read = connector.read(ConnectorRequest(operation="read_repo", scopes=("read",)))
        pr_comments = connector.read(ConnectorRequest(operation="read_pull_request_comments", scopes=("read",)))
        write = connector.write(ConnectorRequest(operation="create_issue", params={"title": "x"}, scopes=("write",)))

        self.assertTrue(read.ok)
        self.assertEqual(read.connector, "github")
        self.assertTrue(pr_comments.ok)
        self.assertIn("pull_request_comments", pr_comments.data["data"])
        self.assertFalse(write.ok)
        with self.assertRaisesRegex(PermissionError, "requires 'read' scope"):
            connector.read(ConnectorRequest(operation="read_repo", scopes=()))

    def test_github_live_write_requires_approval_secret_and_summarizes_payload(self) -> None:
        broker = SecretsBroker()
        connector = GitHubConnectorStub(allowlist=("api.github.com",), live_writes=True, secrets_broker=broker)
        unapproved = connector.write(
            ConnectorRequest(
                operation="create_issue",
                params={"api_url": "https://api.github.com/repos/example/aegis/issues", "title": "Live issue"},
                scopes=("write",),
            )
        )
        missing_secret = connector.write(
            ConnectorRequest(
                operation="create_issue",
                params={"api_url": "https://api.github.com/repos/example/aegis/issues", "title": "Live issue"},
                scopes=("write",),
                approved=True,
            )
        )
        broker.store_secret(name="GITHUB_TOKEN", value="ghp_raw_secret")

        class FakeResponse:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b'{"number":1}'

        captured: dict[str, object] = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.headers.get("Authorization")
            captured["body"] = request.data.decode("utf-8")
            return FakeResponse()

        with patch("aegis.connectors.github._open_without_redirects", side_effect=fake_open):
            live = connector.write(
                ConnectorRequest(
                    operation="create_issue",
                    params={
                        "api_url": "https://api.github.com/repos/example/aegis/issues",
                        "title": "Live issue",
                        "body": "please fix token=abc123",
                    },
                    scopes=("write",),
                    approved=True,
                )
            )

        rendered = json.dumps(live.data, sort_keys=True)
        self.assertFalse(unapproved.ok)
        self.assertIn("approval", unapproved.error)
        self.assertFalse(missing_secret.ok)
        self.assertIn("not configured", missing_secret.error)
        self.assertTrue(live.ok)
        self.assertEqual(live.data["mode"], "live_write")
        self.assertEqual(live.data["status"], 201)
        self.assertEqual(captured["url"], "https://api.github.com/repos/example/aegis/issues")
        self.assertEqual(captured["authorization"], "Bearer ghp_raw_secret")
        self.assertIn('"title": "Live issue"', str(captured["body"]))
        self.assertNotIn("ghp_raw_secret", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertIn("param_sha256", live.data["accepted"])
        self.assertEqual(live.data["accepted"]["receipt_schema"], "redacted_param_summary_v1")
        self.assertFalse(live.data["accepted"]["raw_secret_values_included"])
        self.assertFalse(live.data["accepted"]["raw_response_body_included"])

    def test_gitlab_live_write_requires_approval_secret_and_summarizes_payload(self) -> None:
        broker = SecretsBroker()
        connector = GitLabConnectorStub(allowlist=("gitlab.com",), live_writes=True, secrets_broker=broker)
        unapproved = connector.write(
            ConnectorRequest(
                operation="create_issue",
                params={"api_url": "https://gitlab.com/api/v4/projects/1/issues", "title": "Live issue"},
                scopes=("write",),
            )
        )
        missing_secret = connector.write(
            ConnectorRequest(
                operation="create_issue",
                params={"api_url": "https://gitlab.com/api/v4/projects/1/issues", "title": "Live issue"},
                scopes=("write",),
                approved=True,
            )
        )
        broker.store_secret(name="GITLAB_TOKEN", value="glpat_raw_secret")

        class FakeResponse:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b'{"iid":1}'

        captured: dict[str, object] = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["private_token"] = request.headers.get("Private-token")
            captured["body"] = request.data.decode("utf-8")
            return FakeResponse()

        with patch("aegis.connectors.gitlab._open_without_redirects", side_effect=fake_open):
            live = connector.write(
                ConnectorRequest(
                    operation="create_issue",
                    params={
                        "api_url": "https://gitlab.com/api/v4/projects/1/issues",
                        "title": "Live issue",
                        "description": "please fix token=abc123",
                    },
                    scopes=("write",),
                    approved=True,
                )
            )

        rendered = json.dumps(live.data, sort_keys=True)
        self.assertFalse(unapproved.ok)
        self.assertIn("approval", unapproved.error)
        self.assertFalse(missing_secret.ok)
        self.assertIn("not configured", missing_secret.error)
        self.assertTrue(live.ok)
        self.assertEqual(live.data["mode"], "live_write")
        self.assertEqual(live.data["status"], 201)
        self.assertEqual(captured["url"], "https://gitlab.com/api/v4/projects/1/issues")
        self.assertEqual(captured["private_token"], "glpat_raw_secret")
        self.assertIn('"title": "Live issue"', str(captured["body"]))
        self.assertNotIn("glpat_raw_secret", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertIn("param_sha256", live.data["accepted"])
        self.assertEqual(live.data["accepted"]["receipt_schema"], "redacted_param_summary_v1")
        self.assertFalse(live.data["accepted"]["raw_secret_values_included"])
        self.assertFalse(live.data["accepted"]["raw_response_body_included"])

    def test_service_desk_live_write_requires_approval_secret_and_summarizes_payload(self) -> None:
        broker = SecretsBroker()
        connector = MockServiceNowConnector(allowlist=("example.com",), live_writes=True, secrets_broker=broker)
        unapproved = connector.write(
            ConnectorRequest(
                operation="close_ticket",
                params={"api_url": "https://example.com/api/now/table/incident/INC000001", "ticket": {"id": "INC000001"}},
                scopes=("write",),
            )
        )
        missing_secret = connector.write(
            ConnectorRequest(
                operation="close_ticket",
                params={"api_url": "https://example.com/api/now/table/incident/INC000001", "ticket": {"id": "INC000001"}},
                scopes=("write",),
                approved=True,
            )
        )
        broker.store_secret(name="SERVICE_DESK_TOKEN", value="svc_raw_secret")

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b'{"result":{"number":"INC000001"}}'

        captured: dict[str, object] = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["authorization"] = request.headers.get("Authorization")
            captured["body"] = request.data.decode("utf-8")
            return FakeResponse()

        with patch("aegis.connectors.mock_servicenow._open_without_redirects", side_effect=fake_open):
            live = connector.write(
                ConnectorRequest(
                    operation="close_ticket",
                    params={
                        "api_url": "https://example.com/api/now/table/incident/INC000001",
                        "ticket": {"id": "INC000001", "work_notes": "rotated token=abc123"},
                    },
                    scopes=("write",),
                    approved=True,
                )
            )

        rendered = json.dumps(live.data, sort_keys=True)
        self.assertFalse(unapproved.ok)
        self.assertIn("approval", unapproved.error)
        self.assertFalse(missing_secret.ok)
        self.assertIn("not configured", missing_secret.error)
        self.assertTrue(live.ok)
        self.assertEqual(live.data["mode"], "live_write")
        self.assertEqual(live.data["status"], 200)
        self.assertEqual(captured["url"], "https://example.com/api/now/table/incident/INC000001")
        self.assertEqual(captured["method"], "PATCH")
        self.assertEqual(captured["authorization"], "Bearer svc_raw_secret")
        self.assertIn('"state": "closed"', str(captured["body"]))
        self.assertNotIn("svc_raw_secret", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertIn("param_sha256", live.data["accepted"])
        self.assertEqual(live.data["accepted"]["receipt_schema"], "redacted_param_summary_v1")
        self.assertEqual(live.data["rate_limit"]["limit"], 60)
        self.assertTrue(live.data["rollback_receipt"]["rollback_available"])
        self.assertEqual(live.data["rollback_receipt"]["rollback_operation"], "rollback_close_ticket")
        self.assertFalse(live.data["accepted"]["raw_secret_values_included"])
        self.assertFalse(live.data["accepted"]["raw_response_body_included"])
        self.assertFalse(live.data["rollback_receipt"]["raw_secret_values_included"])
        self.assertFalse(live.data["rollback_receipt"]["raw_response_body_included"])

    def test_service_desk_live_write_rate_limit_and_close_rollback_receipt(self) -> None:
        broker = SecretsBroker()
        connector = MockServiceNowConnector(allowlist=("example.com",), live_writes=True, secrets_broker=broker, rate_limits={"per_minute": 1})
        broker.store_secret(name="SERVICE_DESK_TOKEN", value="svc_raw_secret")

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b'{"result":{"number":"INC000001"}}'

        captured: dict[str, list[dict[str, object]]] = {"requests": []}

        def fake_open(request, timeout):
            captured["requests"].append(
                {
                    "url": request.full_url,
                    "method": request.get_method(),
                    "authorization": request.headers.get("Authorization"),
                    "body": request.data.decode("utf-8"),
                }
            )
            return FakeResponse()

        close_request = ConnectorRequest(
            operation="close_ticket",
            params={"api_url": "https://example.com/api/now/table/incident/INC000001", "ticket": {"id": "INC000001", "work_notes": "rotated token=abc123"}},
            scopes=("write",),
            approved=True,
        )

        with patch("aegis.connectors.mock_servicenow._open_without_redirects", side_effect=fake_open):
            first_close = connector.write(close_request)
            limited_close = connector.write(close_request)
            unapproved_rollback = connector.rollback(
                ConnectorRequest(
                    operation="rollback_close_ticket",
                    params={"api_url": "https://example.com/api/now/table/incident/INC000001", "ticket": {"id": "INC000001"}, "target_state": "open"},
                    scopes=("write",),
                )
            )
            rollback = connector.rollback(
                ConnectorRequest(
                    operation="rollback_close_ticket",
                    params={
                        "api_url": "https://example.com/api/now/table/incident/INC000001",
                        "ticket": {"id": "INC000001"},
                        "target_state": "open",
                        "reason": "operator rollback token=abc123",
                    },
                    scopes=("write",),
                    approved=True,
                )
            )

        rendered_limited = json.dumps(limited_close.data, sort_keys=True)
        rendered_rollback = json.dumps(rollback.data, sort_keys=True)
        self.assertTrue(first_close.ok)
        self.assertFalse(limited_close.ok)
        self.assertIn("rate limit", limited_close.error or "")
        self.assertFalse(limited_close.data["rate_limit"]["allowed"])
        self.assertGreaterEqual(limited_close.data["rate_limit"]["retry_after_seconds"], 1)
        self.assertFalse(unapproved_rollback.ok)
        self.assertIn("approval", unapproved_rollback.error or "")
        self.assertTrue(rollback.ok)
        self.assertEqual(rollback.operation, "rollback_close_ticket")
        self.assertEqual(rollback.data["mode"], "live_rollback")
        self.assertEqual(rollback.data["rollback_receipt"]["receipt_schema"], "service_desk_rollback_receipt_v1")
        self.assertEqual(rollback.data["rollback_receipt"]["target_state"], "open")
        self.assertFalse(rollback.data["rollback_receipt"]["raw_secret_values_included"])
        self.assertFalse(rollback.data["rollback_receipt"]["raw_response_body_included"])
        self.assertEqual(len(captured["requests"]), 2)
        self.assertEqual(captured["requests"][0]["method"], "PATCH")
        self.assertEqual(captured["requests"][0]["authorization"], "Bearer svc_raw_secret")
        self.assertEqual(captured["requests"][1]["method"], "PATCH")
        self.assertEqual(captured["requests"][1]["authorization"], "Bearer svc_raw_secret")
        self.assertIn('"state": "open"', str(captured["requests"][1]["body"]))
        self.assertNotIn("svc_raw_secret", rendered_limited)
        self.assertNotIn("abc123", rendered_limited)
        self.assertNotIn("svc_raw_secret", rendered_rollback)
        self.assertNotIn("abc123", rendered_rollback)

    def test_calendar_live_write_requires_approval_secret_and_summarizes_payload(self) -> None:
        broker = SecretsBroker()
        connector = MockGraphConnector(allowlist=("example.com",), live_calendar_writes=True, secrets_broker=broker)
        unapproved = connector.write(
            ConnectorRequest(
                operation="create_event",
                params={"api_url": "https://example.com/v1.0/me/events", "event": {"subject": "Planning"}},
                scopes=("write",),
            )
        )
        missing_secret = connector.write(
            ConnectorRequest(
                operation="create_event",
                params={"api_url": "https://example.com/v1.0/me/events", "event": {"subject": "Planning"}},
                scopes=("write",),
                approved=True,
            )
        )
        broker.store_secret(name="GRAPH_TOKEN", value="graph_raw_secret")

        class FakeResponse:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b'{"id":"event-1"}'

        captured: dict[str, object] = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["authorization"] = request.headers.get("Authorization")
            captured["body"] = request.data.decode("utf-8")
            return FakeResponse()

        with patch("aegis.connectors.mock_graph._open_without_redirects", side_effect=fake_open):
            live = connector.write(
                ConnectorRequest(
                    operation="create_event",
                    params={
                        "api_url": "https://example.com/v1.0/me/events",
                        "event": {"subject": "Planning", "body": {"content": "join with token=abc123"}},
                    },
                    scopes=("write",),
                    approved=True,
                )
            )

        rendered = json.dumps(live.data, sort_keys=True)
        self.assertFalse(unapproved.ok)
        self.assertIn("approval", unapproved.error)
        self.assertFalse(missing_secret.ok)
        self.assertIn("not configured", missing_secret.error)
        self.assertTrue(live.ok)
        self.assertEqual(live.data["mode"], "live_write")
        self.assertEqual(live.data["status"], 201)
        self.assertEqual(captured["url"], "https://example.com/v1.0/me/events")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["authorization"], "Bearer graph_raw_secret")
        self.assertIn('"subject": "Planning"', str(captured["body"]))
        self.assertNotIn("graph_raw_secret", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertIn("param_sha256", live.data["accepted"])
        self.assertEqual(live.data["accepted"]["receipt_schema"], "redacted_param_summary_v1")
        self.assertFalse(live.data["accepted"]["raw_secret_values_included"])
        self.assertFalse(live.data["accepted"]["raw_response_body_included"])

    def test_graph_live_write_rate_limit_and_calendar_rollback_receipt(self) -> None:
        broker = SecretsBroker()
        broker.store_secret(name="GRAPH_TOKEN", value="graph_raw_secret")
        connector = MockGraphConnector(
            allowlist=("example.com",),
            live_calendar_writes=True,
            secrets_broker=broker,
            rate_limits={"per_minute": 1},
        )

        class FakeResponse:
            def __init__(self, status: int) -> None:
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b"{}"

        captured: dict[str, list[dict[str, object]]] = {"requests": []}

        def fake_open(request, timeout):
            method = request.get_method()
            captured["requests"].append(
                {
                    "url": request.full_url,
                    "method": method,
                    "authorization": request.headers.get("Authorization"),
                    "body": request.data.decode("utf-8") if request.data else "",
                }
            )
            return FakeResponse(204 if method == "DELETE" else 201)

        params = {
            "api_url": "https://example.com/v1.0/me/events/event-1",
            "event": {"id": "event-1", "subject": "Planning", "body": {"content": "token=abc123"}},
        }
        with patch("aegis.connectors.mock_graph._open_without_redirects", side_effect=fake_open):
            live = connector.write(ConnectorRequest(operation="create_event", params=params, scopes=("write",), approved=True))
            limited = connector.write(ConnectorRequest(operation="create_event", params=params, scopes=("write",), approved=True))
            unapproved_rollback = connector.rollback(ConnectorRequest(operation="create_event", params=params, scopes=("write",)))
            rollback = connector.rollback(ConnectorRequest(operation="create_event", params=params, scopes=("write",), approved=True))

        rendered_limited = json.dumps(limited.data, sort_keys=True)
        rendered_rollback = json.dumps(rollback.data, sort_keys=True)
        self.assertTrue(live.ok)
        self.assertEqual(live.data["rate_limit"]["limit"], 1)
        self.assertEqual(live.data["rollback_receipt"]["receipt_schema"], "graph_rollback_offer_v1")
        self.assertTrue(live.data["rollback_receipt"]["rollback_available"])
        self.assertEqual(live.data["rollback_receipt"]["rollback_operation"], "rollback_event")
        self.assertFalse(limited.ok)
        self.assertIn("rate limit", limited.error or "")
        self.assertFalse(limited.data["rate_limit"]["allowed"])
        self.assertFalse(unapproved_rollback.ok)
        self.assertIn("approval", unapproved_rollback.error or "")
        self.assertTrue(rollback.ok)
        self.assertEqual(rollback.operation, "rollback_event")
        self.assertEqual(rollback.data["mode"], "live_rollback")
        self.assertEqual(rollback.data["rollback_receipt"]["receipt_schema"], "graph_rollback_receipt_v1")
        self.assertEqual(rollback.data["rollback_receipt"]["resource_type"], "calendar_event")
        self.assertFalse(rollback.data["rollback_receipt"]["raw_secret_values_included"])
        self.assertFalse(rollback.data["rollback_receipt"]["raw_response_body_included"])
        self.assertEqual(len(captured["requests"]), 2)
        self.assertEqual(captured["requests"][0]["method"], "POST")
        self.assertEqual(captured["requests"][0]["authorization"], "Bearer graph_raw_secret")
        self.assertEqual(captured["requests"][1]["method"], "DELETE")
        self.assertEqual(captured["requests"][1]["authorization"], "Bearer graph_raw_secret")
        self.assertNotIn("graph_raw_secret", rendered_limited)
        self.assertNotIn("abc123", rendered_limited)
        self.assertNotIn("graph_raw_secret", rendered_rollback)
        self.assertNotIn("abc123", rendered_rollback)

    def test_graph_email_live_write_requires_approval_secret_and_summarizes_payload(self) -> None:
        broker = SecretsBroker()
        connector = MockGraphConnector(allowlist=("example.com",), live_email_writes=True, secrets_broker=broker)
        unapproved = connector.write(
            ConnectorRequest(
                operation="send_email",
                params={
                    "api_url": "https://example.com/v1.0/me/sendMail",
                    "message": {"subject": "Review", "to": ["local@example.test"]},
                },
                scopes=("write",),
            )
        )
        missing_secret = connector.write(
            ConnectorRequest(
                operation="send_email",
                params={
                    "api_url": "https://example.com/v1.0/me/sendMail",
                    "message": {"subject": "Review", "to": ["local@example.test"]},
                },
                scopes=("write",),
                approved=True,
            )
        )
        broker.store_secret(name="GRAPH_TOKEN", value="graph_mail_secret")

        class FakeResponse:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b"{}"

        captured: dict[str, object] = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["authorization"] = request.headers.get("Authorization")
            captured["body"] = request.data.decode("utf-8")
            return FakeResponse()

        with patch("aegis.connectors.mock_graph._open_without_redirects", side_effect=fake_open):
            live = connector.write(
                ConnectorRequest(
                    operation="send_email",
                    params={
                        "api_url": "https://example.com/v1.0/me/sendMail",
                        "message": {"subject": "Review", "to": ["local@example.test"], "body": "token=abc123"},
                    },
                    scopes=("write",),
                    approved=True,
                )
            )

        rendered = json.dumps(live.data, sort_keys=True)
        self.assertFalse(unapproved.ok)
        self.assertIn("approval", unapproved.error)
        self.assertFalse(missing_secret.ok)
        self.assertIn("not configured", missing_secret.error)
        self.assertTrue(live.ok)
        self.assertEqual(live.data["mode"], "live_write")
        self.assertEqual(live.data["status"], 202)
        self.assertEqual(captured["url"], "https://example.com/v1.0/me/sendMail")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["authorization"], "Bearer graph_mail_secret")
        self.assertIn('"subject": "Review"', str(captured["body"]))
        self.assertNotIn("graph_mail_secret", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertIn("param_sha256", live.data["accepted"])
        self.assertEqual(live.data["accepted"]["receipt_schema"], "redacted_param_summary_v1")
        self.assertFalse(live.data["accepted"]["raw_secret_values_included"])
        self.assertFalse(live.data["accepted"]["raw_response_body_included"])

    def test_graph_contact_live_write_requires_approval_secret_and_summarizes_payload(self) -> None:
        broker = SecretsBroker()
        connector = MockGraphConnector(allowlist=("example.com",), live_contact_writes=True, secrets_broker=broker)
        unapproved = connector.write(
            ConnectorRequest(
                operation="create_contact",
                params={
                    "api_url": "https://example.com/v1.0/me/contacts",
                    "contact": {"displayName": "Local Contact", "email": "local@example.test"},
                },
                scopes=("write",),
            )
        )
        missing_secret = connector.write(
            ConnectorRequest(
                operation="create_contact",
                params={
                    "api_url": "https://example.com/v1.0/me/contacts",
                    "contact": {"displayName": "Local Contact", "email": "local@example.test"},
                },
                scopes=("write",),
                approved=True,
            )
        )
        broker.store_secret(name="GRAPH_TOKEN", value="graph_contact_secret")

        class FakeResponse:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b'{"id":"contact-1"}'

        captured: dict[str, object] = {}

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["authorization"] = request.headers.get("Authorization")
            captured["body"] = request.data.decode("utf-8")
            return FakeResponse()

        with patch("aegis.connectors.mock_graph._open_without_redirects", side_effect=fake_open):
            live = connector.write(
                ConnectorRequest(
                    operation="create_contact",
                    params={
                        "api_url": "https://example.com/v1.0/me/contacts",
                        "contact": {"displayName": "Local Contact", "email": "local@example.test", "notes": "token=abc123"},
                    },
                    scopes=("write",),
                    approved=True,
                )
            )

        rendered = json.dumps(live.data, sort_keys=True)
        self.assertFalse(unapproved.ok)
        self.assertIn("approval", unapproved.error)
        self.assertFalse(missing_secret.ok)
        self.assertIn("not configured", missing_secret.error)
        self.assertTrue(live.ok)
        self.assertEqual(live.data["mode"], "live_write")
        self.assertEqual(live.data["status"], 201)
        self.assertEqual(captured["url"], "https://example.com/v1.0/me/contacts")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["authorization"], "Bearer graph_contact_secret")
        self.assertIn('"displayName": "Local Contact"', str(captured["body"]))
        self.assertNotIn("graph_contact_secret", rendered)
        self.assertNotIn("abc123", rendered)
        self.assertIn("param_sha256", live.data["accepted"])
        self.assertEqual(live.data["accepted"]["receipt_schema"], "redacted_param_summary_v1")
        self.assertFalse(live.data["accepted"]["raw_secret_values_included"])
        self.assertFalse(live.data["accepted"]["raw_response_body_included"])

    def test_http_live_read_is_allowlisted_and_blocks_unsafe_urls(self) -> None:
        connector = HttpConnector(allowlist=("example.com",), live_network=True)

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                self.limit = limit
                return b"live body"

        captured: dict[str, object] = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            return FakeResponse()

        with patch("aegis.connectors.http._open_without_redirects", fake_urlopen):
            result = connector.read(ConnectorRequest(operation="read", params={"url": "https://example.com/docs"}, scopes=("read",)))

        self.assertTrue(result.ok)
        self.assertEqual(result.data["content"], "live body")
        self.assertEqual(captured["url"], "https://example.com/docs")
        self.assertEqual(captured["timeout"], 10)

        unlisted = connector.read(ConnectorRequest(operation="read", params={"url": "https://evil.test"}, scopes=("read",)))
        self.assertFalse(unlisted.ok)
        self.assertIn("not allowlisted", unlisted.error)

        unsafe = connector.read(ConnectorRequest(operation="read", params={"url": "https://user:pass@example.com"}, scopes=("read",)))
        self.assertFalse(unsafe.ok)
        self.assertIn("credentials", unsafe.error)

        file_url = connector.dry_run(ConnectorRequest(operation="dry_run", params={"url": "file:///etc/passwd"}, scopes=("read",)))
        self.assertFalse(file_url.data["allowed"])
        self.assertIn("http and https", file_url.data["error"])

        with self.assertRaisesRegex(PermissionError, "requires 'read' scope"):
            connector.read(ConnectorRequest(operation="read", params={"url": "https://example.com/docs"}, scopes=()))

    def test_http_live_read_blocks_local_private_network_targets(self) -> None:
        connector = HttpConnector(allowlist=("localhost", "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"), live_network=True)

        for url in ("http://localhost:8000", "http://127.0.0.1:8000", "http://10.0.0.1", "http://169.254.169.254", "http://[::1]:8000"):
            result = connector.read(ConnectorRequest(operation="read", params={"url": url}, scopes=("read",)))
            self.assertFalse(result.ok)
            self.assertIn("local/private network", result.error or "")

        mock_connector = HttpConnector(allowlist=("localhost",), live_network=False)
        mock_result = mock_connector.read(ConnectorRequest(operation="read", params={"url": "http://localhost:8000"}, scopes=("read",)))
        self.assertTrue(mock_result.ok)

    def test_http_live_read_fails_closed_when_dns_cannot_be_verified(self) -> None:
        connector = HttpConnector(allowlist=("example.com",), live_network=True)

        with patch("socket.getaddrinfo", side_effect=OSError("dns unavailable")):
            result = connector.read(ConnectorRequest(operation="read", params={"url": "https://example.com/docs"}, scopes=("read",)))

        self.assertFalse(result.ok)
        self.assertIn("could not verify", result.error or "")

    def test_http_live_read_blocks_redirects_to_unallowlisted_domains(self) -> None:
        connector = HttpConnector(allowlist=("example.com",), live_network=True)
        headers = Message()
        headers["Location"] = "https://evil.test/secret"

        def redirect(request, timeout):
            raise HTTPError(request.full_url, 302, "Found", headers, None)

        with patch("aegis.connectors.http._open_without_redirects", redirect):
            result = connector.read(ConnectorRequest(operation="read", params={"url": "https://example.com/docs"}, scopes=("read",)))

        self.assertFalse(result.ok)
        self.assertIn("redirect target domain", result.error)

    def test_generic_rest_live_write_is_approval_gated_and_summarized(self) -> None:
        connector = GenericRestConnector(allowlist=("example.com",), live_writes=True)
        captured: dict[str, object] = {}

        class FakeResponse:
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit: int) -> bytes:
                return b""

        def fake_open(request, timeout):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["body"] = request.data.decode("utf-8")
            captured["timeout"] = timeout
            return FakeResponse()

        pending = connector.write(ConnectorRequest(operation="post", params={"url": "https://example.com/hook", "payload": {"token": "abc123"}}, scopes=("write",)))
        with patch("aegis.connectors.rest._private_network_error", return_value=None), patch("aegis.connectors.rest._open_without_redirects", fake_open):
            written = connector.write(ConnectorRequest(operation="post", params={"url": "https://example.com/hook", "payload": {"token": "abc123"}}, scopes=("write",), approved=True))

        self.assertFalse(pending.ok)
        self.assertTrue(written.ok)
        self.assertEqual(written.data["mode"], "live_write")
        self.assertEqual(written.data["status"], 204)
        self.assertEqual(written.data["accepted"]["payload_keys"], ["token"])
        self.assertEqual(written.data["accepted"]["receipt_schema"], "redacted_payload_summary_v1")
        self.assertFalse(written.data["accepted"]["raw_secret_values_included"])
        self.assertFalse(written.data["accepted"]["raw_response_body_included"])
        self.assertNotIn("abc123", json.dumps(written.data, sort_keys=True))
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["url"], "https://example.com/hook")
        self.assertIn("abc123", captured["body"])

    def test_generic_rest_live_write_blocks_unsafe_targets_before_network(self) -> None:
        connector = GenericRestConnector(allowlist=("example.com", "localhost"), live_writes=True)

        insecure = connector.write(ConnectorRequest(operation="post", params={"url": "http://example.com/hook", "payload": {}}, scopes=("write",), approved=True))
        private = connector.write(ConnectorRequest(operation="post", params={"url": "https://localhost/hook", "payload": {}}, scopes=("write",), approved=True))

        self.assertFalse(insecure.ok)
        self.assertIn("https", insecure.error or "")
        self.assertFalse(private.ok)
        self.assertIn("local/private", private.error or "")


if __name__ == "__main__":
    unittest.main()
