from __future__ import annotations

from email.message import Message
import os
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.models.client import LiveModelClient
from aegis.models.registry import ModelRegistry
from aegis.security.secrets_broker import SecretsBroker


class ModelAuthTests(unittest.TestCase):
    def test_model_usage_summary_groups_events_without_metadata_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"))

            first = registry.record_usage(
                identifier="openai/gpt-4o-mini",
                input_tokens=100,
                output_tokens=20,
                task_id="task-1",
                session_id="session-1",
                metadata={"prompt_hash": "sha256:abc", "raw_prompt": "secret-like usage context"},
            )
            registry.record_usage(identifier="ollama/llama3", input_tokens=10, output_tokens=5, session_id="session-1")

            summary = registry.usage_summary()
            serialized = json.dumps(summary, sort_keys=True)
            by_provider = {row["key"]: row for row in summary["by_provider"]}
            by_model = {row["key"]: row for row in summary["by_model"]}

            self.assertEqual(summary["events"], 2)
            self.assertEqual(summary["input_tokens"], 110)
            self.assertEqual(summary["output_tokens"], 25)
            self.assertEqual(by_provider["openai"]["events"], 1)
            self.assertEqual(by_provider["ollama"]["events"], 1)
            self.assertEqual(by_model["openai/gpt-4o-mini"]["input_tokens"], 100)
            recent = {row["id"]: row for row in summary["recent_events"]}
            self.assertEqual(recent[first["id"]]["task_id"], "task-1")
            self.assertEqual(recent[first["id"]]["metadata_keys"], ["prompt_hash", "raw_prompt"])
            self.assertNotIn("secret-like usage context", serialized)
            self.assertNotIn("sha256:abc", serialized)

    def test_cloud_provider_login_uses_brokered_local_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            self.assertFalse(registry.auth_status("openai")["auth_configured"])
            self.assertFalse(registry.auth_status("openrouter")["auth_configured"])
            self.assertFalse(registry.auth_status("anthropic")["auth_configured"])
            self.assertFalse(registry.auth_status("google")["auth_configured"])
            self.assertFalse(registry.auth_status("mistral")["auth_configured"])
            self.assertFalse(registry.auth_status("cohere")["auth_configured"])

            openai_status = registry.login_provider("openai", "sk-openai-test")
            openrouter_status = registry.login_provider("openrouter", "sk-openrouter-test")
            anthropic_status = registry.login_provider("anthropic", "sk-ant-test")
            google_status = registry.login_provider("google", "sk-google-test")
            mistral_status = registry.login_provider("mistral", "sk-mistral-test")
            cohere_status = registry.login_provider("cohere", "sk-cohere-test")

            self.assertEqual(openai_status["auth_source"], "local")
            self.assertEqual(openrouter_status["auth_source"], "local")
            self.assertEqual(anthropic_status["auth_source"], "local")
            self.assertEqual(google_status["auth_source"], "local")
            self.assertEqual(mistral_status["auth_source"], "local")
            self.assertEqual(cohere_status["auth_source"], "local")
            self.assertTrue(registry.auth_status("openai")["auth_configured"])
            self.assertTrue(registry.auth_status("openrouter")["auth_configured"])
            self.assertTrue(registry.auth_status("anthropic")["auth_configured"])
            self.assertTrue(registry.auth_status("google")["auth_configured"])
            self.assertTrue(registry.auth_status("mistral")["auth_configured"])
            self.assertTrue(registry.auth_status("cohere")["auth_configured"])
            self.assertTrue(registry.route("openai/gpt-4o").secret_handle_id)
            self.assertTrue(registry.route("openrouter/openai/gpt-4o").secret_handle_id)
            self.assertTrue(registry.route("anthropic/claude-sonnet-4.6").secret_handle_id)
            self.assertTrue(registry.route("google/gemini-pro").secret_handle_id)
            self.assertTrue(registry.route("mistral/mistral-large").secret_handle_id)
            self.assertTrue(registry.route("cohere/command-r-plus").secret_handle_id)

            openai_handle = broker.request_handle(
                name="OPENAI_API_KEY",
                requester="model:openai",
                reason="test resolve",
                scopes=("model.invoke",),
            )
            self.assertEqual(broker.resolve_for_authorized_tool(openai_handle, requester="model:openai"), "sk-openai-test")

            self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o600)
            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertNotIn("sk-openai-test", audit_text)
            self.assertNotIn("sk-openrouter-test", audit_text)
            self.assertNotIn("sk-ant-test", audit_text)
            self.assertNotIn("sk-google-test", audit_text)
            self.assertNotIn("sk-mistral-test", audit_text)
            self.assertNotIn("sk-cohere-test", audit_text)

            logout_status = registry.logout_provider("openrouter")
            self.assertFalse(logout_status["auth_configured"])

    def test_subscription_auth_surface_is_metadata_only_until_governed_bridge_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), SecretsBroker(secret_path))

            providers = {row["provider"]: row for row in registry.list_providers()}
            openai = providers["openai"]
            anthropic = providers["anthropic"]
            openrouter = providers["openrouter"]
            aws_bedrock = providers["aws-bedrock"]

            self.assertEqual(openai["auth_methods"], ["api_key", "subscription"])
            self.assertTrue(openai["subscription_auth_supported"])
            self.assertFalse(openai["subscription_auth_configured"])
            self.assertEqual(openai["subscription_auth"]["external_command"], "codex login")
            self.assertEqual(openai["subscription_auth"]["aegis_bridge_status"], "official_cli_handoff_only")
            self.assertEqual(anthropic["auth_methods"], ["api_key", "subscription"])
            self.assertEqual(anthropic["subscription_auth"]["external_command"], "claude auth login")
            self.assertEqual(anthropic["subscription_auth"]["external_login_instruction"], "/login")
            self.assertFalse(openrouter["subscription_auth_supported"])
            self.assertIsNone(openrouter["subscription_auth"])
            self.assertTrue(aws_bedrock["auth_required"])
            self.assertEqual(aws_bedrock["auth_methods"], ["cloud_identity"])
            self.assertFalse(aws_bedrock["auth_configured"])
            all_auth_status = {row["provider"]: row for row in registry.auth_status()}
            self.assertIn("aws-bedrock", all_auth_status)

            status = registry.login_provider_subscription("openai")
            self.assertEqual(status["status"], "external_login_required")
            self.assertEqual(status["external_command"], "codex login")
            self.assertFalse(status["token_captured"])
            self.assertFalse(status["token_capture_supported"])
            self.assertFalse(registry.auth_status("openai")["auth_configured"])
            self.assertFalse(secret_path.exists())

            with self.assertRaises(ValueError):
                registry.login_provider_subscription("openrouter")

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_subscription_login_requested", audit_text)
            self.assertNotIn("sk-", audit_text)
            self.assertNotIn("session_cookie", audit_text)

    def test_subscription_auth_can_launch_official_cli_without_token_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), SecretsBroker(secret_path))

            login_completed = subprocess.CompletedProcess(("codex", "login"), 0)
            status_completed = subprocess.CompletedProcess(("codex", "login", "status"), 0, stdout="Logged in using ChatGPT\n", stderr="")
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/codex"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)) as run,
            ):
                status = registry.login_provider_subscription("openai", run_external=True)

            self.assertEqual(run.call_args_list[0].args[0], ("codex", "login"))
            self.assertEqual(run.call_args_list[1].args[0], ("codex", "login", "status"))
            self.assertEqual(status["status"], "external_login_verified")
            self.assertTrue(status["external_login_attempted"])
            self.assertTrue(status["external_status_verified"])
            self.assertEqual(status["external_login_exit_code"], 0)
            self.assertEqual(status["external_command_argv"], ["codex", "login"])
            self.assertTrue(status["auth_configured"])
            self.assertTrue(status["subscription_auth_configured"])
            self.assertFalse(status["token_captured"])
            self.assertFalse(secret_path.exists())

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_subscription_login_requested", audit_text)
            self.assertIn("external_login_verified", audit_text)
            self.assertNotIn("CODEX_ACCESS_TOKEN", audit_text)
            self.assertNotIn("session_cookie", audit_text)

    def test_verified_codex_subscription_can_invoke_without_api_key_or_token_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            login_completed = subprocess.CompletedProcess(("codex", "login"), 0)
            status_completed = subprocess.CompletedProcess(("codex", "login", "status"), 0, stdout="Logged in using ChatGPT\n", stderr="")
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/codex"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)),
            ):
                login = registry.login_provider_subscription("openai", run_external=True)

            self.assertEqual(login["status"], "external_login_verified")
            self.assertFalse(secret_path.exists())
            self.assertTrue(registry.auth_status("openai")["auth_configured"])
            self.assertTrue(registry.auth_status("openai")["subscription_auth_configured"])
            self.assertEqual(registry.auth_status("openai")["auth_source"], "subscription_cli")
            target_rows = {row["target"]: row for row in registry.auth_targets()["targets"]}
            self.assertEqual(target_rows["OpenAI Codex / ChatGPT subscription"]["status"], "subscription_cli_ready")

            reloaded = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)
            route = reloaded.route("openai/gpt-4o-mini")
            self.assertEqual(route.auth_method, "subscription_cli")
            self.assertIsNone(route.secret_handle_id)

            def fake_codex_exec(command, **kwargs):
                self.assertEqual(command[1], "exec")
                self.assertIn("--skip-git-repo-check", command)
                self.assertIn("--ephemeral", command)
                self.assertIn("--ignore-rules", command)
                self.assertIn("read-only", command)
                self.assertIn("never", command)
                self.assertEqual(command[command.index("-m") + 1], "gpt-4o-mini")
                self.assertIn("[USER]\nhello from aegis", kwargs["input"])
                output_path = Path(command[command.index("--output-last-message") + 1])
                output_path.write_text("subscription backed response\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with (
                patch("aegis.models.client.shutil.which", return_value="/usr/bin/codex"),
                patch("aegis.models.client.subprocess.run", side_effect=fake_codex_exec) as run,
            ):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "subscription backed response")
            self.assertEqual(result.raw_usage["source"], "subscription_cli")
            self.assertEqual(result.raw_usage["bridge"], "codex_exec")
            run.assert_called_once()

            logout = reloaded.logout_provider("openai")
            self.assertEqual(logout["removed_external_auth_links"], 1)
            self.assertFalse(logout["auth_configured"])
            self.assertFalse(logout["subscription_auth_configured"])
            self.assertEqual(reloaded.route("openai/gpt-4o-mini").auth_method, "none")

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_subscription_login_requested", audit_text)
            self.assertNotIn("CODEX_ACCESS_TOKEN", audit_text)
            self.assertNotIn("session_cookie", audit_text)

    def test_verified_claude_subscription_can_invoke_without_api_key_or_token_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            login_completed = subprocess.CompletedProcess(("claude", "auth", "login"), 0)
            status_completed = subprocess.CompletedProcess(("claude", "auth", "status"), 0, stdout="Logged in with Claude subscription\n", stderr="")
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/claude"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)),
            ):
                login = registry.login_provider_subscription("anthropic", run_external=True)

            self.assertEqual(login["status"], "external_login_verified")
            self.assertEqual(login["invocation_bridge"], "claude_print")
            self.assertFalse(secret_path.exists())
            self.assertTrue(registry.auth_status("anthropic")["auth_configured"])
            self.assertTrue(registry.auth_status("anthropic")["subscription_auth_configured"])
            self.assertEqual(registry.auth_status("anthropic")["auth_source"], "subscription_cli")
            target_rows = {row["target"]: row for row in registry.auth_targets()["targets"]}
            self.assertEqual(target_rows["Claude Code subscription"]["status"], "subscription_cli_ready")

            route = registry.route("anthropic/claude-sonnet-4.6")
            self.assertEqual(route.auth_method, "subscription_cli")
            self.assertIsNone(route.secret_handle_id)

            def fake_claude_print(command, **kwargs):
                self.assertEqual(command[1], "-p")
                self.assertIn("--output-format", command)
                self.assertIn("text", command)
                self.assertIn("--max-turns", command)
                self.assertIn("1", command)
                self.assertIn("--permission-mode", command)
                self.assertIn("plan", command)
                self.assertEqual(command[command.index("--model") + 1], "sonnet")
                self.assertIn("[USER]\nhello from aegis", command[-1])
                self.assertNotIn("input", kwargs)
                return subprocess.CompletedProcess(command, 0, stdout="claude subscription response\n", stderr="")

            with (
                patch("aegis.models.client.shutil.which", return_value="/usr/bin/claude"),
                patch("aegis.models.client.subprocess.run", side_effect=fake_claude_print) as run,
            ):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "claude subscription response")
            self.assertEqual(result.raw_usage["source"], "subscription_cli")
            self.assertEqual(result.raw_usage["bridge"], "claude_print")
            run.assert_called_once()

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_subscription_login_requested", audit_text)
            self.assertNotIn("ANTHROPIC_AUTH_TOKEN", audit_text)
            self.assertNotIn("session_cookie", audit_text)

    def test_subscription_auth_reports_missing_official_cli_without_token_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), SecretsBroker(secret_path))

            with (
                patch("aegis.models.registry.shutil.which", return_value=None),
                patch("aegis.models.registry.subprocess.run") as run,
            ):
                status = registry.login_provider_subscription("anthropic", run_external=True)

            run.assert_not_called()
            self.assertEqual(status["status"], "external_command_unavailable")
            self.assertFalse(status["external_command_available"])
            self.assertFalse(status["external_login_attempted"])
            self.assertIn("claude", status["external_login_error"])
            self.assertFalse(status["token_captured"])
            self.assertFalse(secret_path.exists())

    def test_provider_native_auth_handoff_runs_official_cli_without_token_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), SecretsBroker(secret_path))

            login_completed = subprocess.CompletedProcess(("gh", "auth", "login"), 0)
            status_completed = subprocess.CompletedProcess(("gh", "auth", "status"), 0, stdout="Logged in to github.com\n", stderr="")
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/gh"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)) as run,
            ):
                status = registry.login_provider_external("github-copilot", method="oauth-device", run_external=True)

            self.assertEqual(run.call_args_list[0].args[0], ("gh", "auth", "login"))
            self.assertEqual(run.call_args_list[1].args[0], ("gh", "auth", "status"))
            self.assertEqual(status["provider"], "github-copilot")
            self.assertEqual(status["target"], "GitHub Copilot")
            self.assertEqual(status["method"], "oauth_device")
            self.assertEqual(status["status"], "external_login_verified")
            self.assertTrue(status["external_login_attempted"])
            self.assertTrue(status["external_status_verified"])
            self.assertEqual(status["external_command_argv"], ["gh", "auth", "login"])
            self.assertTrue(status["auth_configured"])
            self.assertFalse(status["token_captured"])
            self.assertFalse(secret_path.exists())

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_external_login_requested", audit_text)
            self.assertNotIn("GH_TOKEN", audit_text)

    def test_aws_cloud_identity_handoff_verifies_official_cli_without_token_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), SecretsBroker(secret_path))

            login_completed = subprocess.CompletedProcess(("aws", "sso", "login"), 0)
            status_completed = subprocess.CompletedProcess(
                ("aws", "sts", "get-caller-identity"),
                0,
                stdout='{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/Test/User"}\n',
                stderr="",
            )
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/aws"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)) as run,
            ):
                status = registry.login_provider_external("aws-bedrock", method="cloud-identity", run_external=True)

            self.assertEqual(run.call_args_list[0].args[0], ("aws", "sso", "login"))
            self.assertEqual(run.call_args_list[1].args[0], ("aws", "sts", "get-caller-identity"))
            self.assertEqual(status["provider"], "aws-bedrock")
            self.assertEqual(status["target"], "AWS Bedrock")
            self.assertEqual(status["method"], "cloud_identity")
            self.assertEqual(status["status"], "external_login_verified")
            self.assertTrue(status["external_status_verified"])
            self.assertEqual(status["external_status_command_argv"], ["aws", "sts", "get-caller-identity"])
            self.assertTrue(status["auth_configured"])
            self.assertFalse(status["token_captured"])
            self.assertFalse(secret_path.exists())

            target_rows = {row["target"]: row for row in registry.auth_targets()["targets"]}
            self.assertEqual(target_rows["AWS Bedrock"]["status"], "external_login_verified")
            self.assertEqual(target_rows["AWS Bedrock"]["bridge_status"], "official_cli_link_verified")
            self.assertTrue(target_rows["AWS Bedrock"]["external_auth_configured"])
            self.assertNotIn("123456789012", audit_path.read_text(encoding="utf-8"))

    def test_verified_aws_bedrock_cloud_identity_can_invoke_without_token_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            login_completed = subprocess.CompletedProcess(("aws", "sso", "login"), 0)
            status_completed = subprocess.CompletedProcess(
                ("aws", "sts", "get-caller-identity"),
                0,
                stdout='{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/Test/User"}\n',
                stderr="",
            )
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/aws"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)),
            ):
                login = registry.login_provider_external("aws-bedrock", method="cloud-identity", run_external=True)

            self.assertEqual(login["status"], "external_login_verified")
            self.assertFalse(secret_path.exists())
            self.assertTrue(registry.auth_status("aws-bedrock")["auth_configured"])
            self.assertEqual(registry.auth_status("aws-bedrock")["auth_source"], "official_cli")

            route = registry.route("aws-bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0")
            self.assertEqual(route.auth_method, "cloud_identity_cli")
            self.assertIsNone(route.secret_handle_id)
            self.assertEqual(route.provider.external_auth_method, "cloud_identity")

            def fake_bedrock_converse(command, **kwargs):
                self.assertEqual(command[0], "/usr/bin/aws")
                self.assertEqual(command[1:3], ("bedrock-runtime", "converse"))
                self.assertEqual(command[command.index("--model-id") + 1], "anthropic.claude-3-5-sonnet-20240620-v1:0")
                messages = json.loads(command[command.index("--messages") + 1])
                self.assertEqual(messages[0]["role"], "user")
                self.assertEqual(messages[0]["content"][0]["text"], "hello from aegis")
                inference_config = json.loads(command[command.index("--inference-config") + 1])
                self.assertEqual(inference_config["temperature"], 0.2)
                self.assertEqual(kwargs["cwd"].name.startswith("aegis-bedrock-model-"), True)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"output":{"message":{"role":"assistant","content":[{"text":"bedrock response"}]}},"usage":{"inputTokens":12,"outputTokens":5,"totalTokens":17}}\n',
                    stderr="",
                )

            with (
                patch("aegis.models.client.shutil.which", return_value="/usr/bin/aws"),
                patch("aegis.models.client.subprocess.run", side_effect=fake_bedrock_converse) as run,
            ):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "bedrock response")
            self.assertEqual(result.input_tokens, 12)
            self.assertEqual(result.output_tokens, 5)
            self.assertEqual(result.raw_usage["source"], "official_cli")
            self.assertEqual(result.raw_usage["bridge"], "aws_bedrock_runtime_converse")
            run.assert_called_once()

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_external_login_requested", audit_text)
            self.assertNotIn("AWS_ACCESS_KEY_ID", audit_text)
            self.assertNotIn("123456789012", audit_text)

    def test_aws_bedrock_requires_verified_cloud_identity_before_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)

            route = registry.route("aws-bedrock/amazon.titan-text-express-v1")

            self.assertEqual(route.auth_method, "none")
            with self.assertRaises(ValueError):
                LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

    def test_google_cloud_identity_handoff_verifies_official_cli_without_token_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), SecretsBroker(secret_path))

            login_completed = subprocess.CompletedProcess(("gcloud", "auth", "login", "--update-adc"), 0)
            status_completed = subprocess.CompletedProcess(
                ("gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"),
                0,
                stdout="operator@example.com\n",
                stderr="",
            )
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/gcloud"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)) as run,
            ):
                status = registry.login_provider_external("google", method="cloud-identity", run_external=True)

            self.assertEqual(run.call_args_list[0].args[0], ("gcloud", "auth", "login", "--update-adc"))
            self.assertEqual(run.call_args_list[1].args[0], ("gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"))
            self.assertEqual(status["provider"], "google")
            self.assertEqual(status["target"], "Google Vertex AI / Gemini cloud identity")
            self.assertEqual(status["method"], "cloud_identity")
            self.assertEqual(status["status"], "external_login_verified")
            self.assertTrue(status["external_status_verified"])
            self.assertEqual(status["external_status_command_argv"], ["gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"])
            self.assertTrue(status["auth_configured"])
            self.assertFalse(status["token_captured"])
            self.assertFalse(secret_path.exists())

            target_rows = {row["target"]: row for row in registry.auth_targets()["targets"]}
            self.assertEqual(target_rows["Google Vertex AI / Gemini cloud identity"]["status"], "external_login_verified")
            self.assertEqual(target_rows["Google Vertex AI / Gemini cloud identity"]["bridge_status"], "official_cli_link_verified")
            self.assertTrue(target_rows["Google Vertex AI / Gemini cloud identity"]["external_auth_configured"])
            self.assertNotIn("operator@example.com", audit_path.read_text(encoding="utf-8"))

    def test_manual_provider_native_auth_handoff_never_captures_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), SecretsBroker(secret_path))

            with (
                patch("aegis.models.registry.shutil.which", return_value=None),
                patch("aegis.models.registry.subprocess.run") as run,
            ):
                status = registry.login_provider_external("minimax", method="oauth", run_external=True)

            run.assert_not_called()
            self.assertEqual(status["target"], "MiniMax OAuth")
            self.assertEqual(status["status"], "external_login_manual_required")
            self.assertFalse(status["external_command_available"])
            self.assertFalse(status["external_login_attempted"])
            self.assertFalse(status["token_captured"])
            self.assertFalse(secret_path.exists())

    def test_verified_provider_native_auth_links_update_targets_and_logout(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"))
            login_completed = subprocess.CompletedProcess(("gh", "auth", "login"), 0)
            status_completed = subprocess.CompletedProcess(("gh", "auth", "status"), 0, stdout="Logged in to github.com\n", stderr="")

            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/gh"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)) as run,
            ):
                login = registry.login_provider_external("github-copilot", method="oauth-device", run_external=True)
            status = registry.auth_status("github-copilot")
            qwen_status = registry.auth_status("qwen")
            targets = registry.auth_targets()
            by_target = {row["target"]: row for row in targets["targets"]}

            self.assertEqual(run.call_args_list[0].args[0], ("gh", "auth", "login"))
            self.assertEqual(run.call_args_list[1].args[0], ("gh", "auth", "status"))
            self.assertEqual(login["status"], "external_login_verified")
            self.assertFalse(login["token_captured"])
            self.assertEqual(status["status"], "external_login_verified")
            self.assertTrue(status["external_auth_configured"])
            self.assertEqual(status["bridge_status"], "official_cli_link_verified")
            self.assertIn("oauth", qwen_status["auth_methods"])
            self.assertEqual(qwen_status["provider_native_auth"][0]["status"], "official_cli_handoff_only")
            self.assertEqual(by_target["GitHub Copilot"]["status"], "external_login_verified")
            self.assertEqual(by_target["GitHub Copilot"]["bridge_status"], "official_cli_link_verified")
            self.assertTrue(by_target["GitHub Copilot"]["external_auth_configured"])
            self.assertIn("GitHub Copilot", targets["verified_external_auth_targets"])
            self.assertNotIn("GitHub Copilot", targets["subscription_bridge_targets"])
            self.assertFalse(any(row["raw_tokens_captured"] for row in targets["targets"]))

            logout = registry.logout_provider("github-copilot")
            targets_after = registry.auth_targets()
            by_target_after = {row["target"]: row for row in targets_after["targets"]}

            self.assertEqual(logout["removed_external_auth_links"], 1)
            self.assertFalse(logout["external_auth_configured"])
            self.assertEqual(logout["status"], "official_cli_handoff_only")
            self.assertEqual(by_target_after["GitHub Copilot"]["status"], "official_cli_handoff_only")

    def test_provider_auth_targets_track_hermes_and_claude_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"))

            targets = registry.auth_targets()
            by_target = {row["target"]: row for row in targets["targets"]}

            self.assertEqual(targets["status"], "auth_parity_gap_tracked")
            self.assertGreaterEqual(targets["target_provider_count"], 26)
            self.assertIn("api_key", targets["implemented_auth_methods"])
            self.assertIn("subscription", targets["implemented_auth_methods"])
            self.assertIn("oauth", targets["implemented_auth_methods"])
            self.assertIn("oauth_device", targets["implemented_auth_methods"])
            self.assertIn("cloud_identity", targets["implemented_auth_methods"])
            self.assertEqual(by_target["OpenAI API"]["status"], "api_key_ready")
            self.assertEqual(by_target["OpenAI Codex / ChatGPT subscription"]["status"], "official_cli_handoff_only")
            self.assertEqual(by_target["OpenAI Codex / ChatGPT subscription"]["external_command"], "codex login")
            self.assertEqual(by_target["Claude Code subscription"]["status"], "official_cli_handoff_only")
            self.assertEqual(by_target["Claude Code subscription"]["external_command"], "claude auth login")
            self.assertEqual(by_target["Claude Code subscription"]["external_login_instruction"], "/login")
            self.assertEqual(by_target["Nous Portal API key"]["status"], "api_key_ready")
            self.assertEqual(by_target["Nous Portal OAuth subscription"]["status"], "manual_provider_handoff_only")
            self.assertEqual(by_target["GitHub Copilot"]["status"], "official_cli_handoff_only")
            self.assertEqual(by_target["GitHub Copilot"]["external_command"], "gh auth login")
            self.assertEqual(by_target["Google Gemini"]["status"], "api_key_ready")
            self.assertEqual(by_target["Google Vertex AI / Gemini cloud identity"]["status"], "official_cli_handoff_only")
            self.assertEqual(by_target["Google Vertex AI / Gemini cloud identity"]["external_command"], "gcloud auth login --update-adc")
            self.assertEqual(by_target["Google Vertex AI / Gemini cloud identity"]["external_status_command"], "gcloud auth list --filter=status:ACTIVE --format=value(account)")
            self.assertEqual(by_target["DeepSeek"]["status"], "api_key_ready")
            self.assertEqual(by_target["MiniMax"]["status"], "api_key_ready")
            self.assertEqual(by_target["MiniMax OAuth"]["status"], "manual_provider_handoff_only")
            self.assertEqual(by_target["AWS Bedrock"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["Azure Foundry API key"]["status"], "api_key_ready")
            self.assertEqual(by_target["Azure Foundry"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["Qwen DashScope API"]["status"], "api_key_ready")
            self.assertEqual(by_target["Qwen OAuth"]["required_auth"], ["oauth"])
            self.assertEqual(by_target["Qwen OAuth"]["status"], "official_cli_handoff_only")
            self.assertEqual(by_target["Qwen OAuth"]["external_command"], "qwen auth")
            self.assertEqual(by_target["Ollama"]["status"], "local_ready")
            self.assertFalse(any(row["raw_tokens_captured"] for row in targets["targets"]))
            self.assertIn("raw_token_capture_rejection", targets["verification_gates"])

    def test_azure_foundry_api_key_provider_uses_configured_v1_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(
                LocalStore(root / ".aegis" / "aegis.db"),
                AuditLogger(root / ".aegis" / "audit.jsonl"),
                broker,
                azure_foundry_base_url="https://aoai.example.openai.azure.com/openai/v1",
            )
            client = LiveModelClient(broker)

            login = registry.login_provider("azure-foundry", "sk-azure-test")
            route = registry.route("azure-foundry/prod-gpt-4o")

            self.assertTrue(login["auth_configured"])
            self.assertEqual(login["auth_secret"], "AZURE_OPENAI_API_KEY")
            self.assertEqual(route.provider.base_url, "https://aoai.example.openai.azure.com/openai/v1")
            self.assertEqual(route.provider.models, ("*",))
            self.assertEqual(route.provider.auth_secret, "AZURE_OPENAI_API_KEY")
            self.assertTrue(route.secret_handle_id)

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return b'{"choices":[{"message":{"content":"azure response"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}'

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("sk-azure-test", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = client.chat(route, [{"role": "user", "content": "hello"}])

            headers = {str(key).lower(): value for key, value in dict(captured["headers"]).items()}
            self.assertEqual(captured["url"], "https://aoai.example.openai.azure.com/openai/v1/chat/completions")
            self.assertEqual(headers["api-key"], "sk-azure-test")
            self.assertEqual(captured["payload"]["model"], "prod-gpt-4o")
            self.assertEqual(result.content, "azure response")
            self.assertEqual(result.input_tokens, 7)
            self.assertEqual(result.output_tokens, 3)

    def test_verified_azure_foundry_cloud_identity_can_invoke_without_token_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(
                LocalStore(root / ".aegis" / "aegis.db"),
                AuditLogger(audit_path),
                broker,
                azure_foundry_base_url="https://aoai.example.openai.azure.com/openai/v1",
            )

            login_completed = subprocess.CompletedProcess(("az", "login"), 0)
            status_completed = subprocess.CompletedProcess(
                ("az", "account", "show"),
                0,
                stdout='{"id":"00000000-0000-0000-0000-000000000000","user":{"name":"operator@example.com"}}\n',
                stderr="",
            )
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/az"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)),
            ):
                login = registry.login_provider_external("azure-foundry", method="cloud-identity", run_external=True)

            self.assertEqual(login["status"], "external_login_verified")
            self.assertFalse(secret_path.exists())
            self.assertTrue(registry.auth_status("azure-foundry")["auth_configured"])
            self.assertEqual(registry.auth_status("azure-foundry")["auth_source"], "official_cli")

            route = registry.route("azure-foundry/prod-gpt-4o")
            self.assertEqual(route.auth_method, "cloud_identity_cli")
            self.assertIsNone(route.secret_handle_id)

            def fake_az_rest(command, **kwargs):
                self.assertEqual(command[0], "/usr/bin/az")
                self.assertEqual(command[1], "rest")
                self.assertEqual(command[command.index("--method") + 1], "post")
                self.assertEqual(command[command.index("--resource") + 1], "https://ai.azure.com")
                self.assertEqual(command[command.index("--url") + 1], "https://aoai.example.openai.azure.com/openai/v1/chat/completions")
                payload = json.loads(command[command.index("--body") + 1])
                self.assertEqual(payload["model"], "prod-gpt-4o")
                self.assertEqual(payload["messages"][0]["content"], "hello from aegis")
                self.assertTrue(kwargs["cwd"].name.startswith("aegis-azure-model-"))
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"choices":[{"message":{"content":"azure identity response"}}],"usage":{"prompt_tokens":9,"completion_tokens":4}}\n',
                    stderr="",
                )

            with (
                patch("aegis.models.client.shutil.which", return_value="/usr/bin/az"),
                patch("aegis.models.client.subprocess.run", side_effect=fake_az_rest) as run,
            ):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "azure identity response")
            self.assertEqual(result.input_tokens, 9)
            self.assertEqual(result.output_tokens, 4)
            self.assertEqual(result.raw_usage["source"], "official_cli")
            self.assertEqual(result.raw_usage["bridge"], "az_rest")
            run.assert_called_once()

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_external_login_requested", audit_text)
            self.assertNotIn("operator@example.com", audit_text)
            self.assertNotIn("00000000-0000-0000-0000-000000000000", audit_text)

    def test_azure_foundry_rejects_unsafe_base_urls_before_auth_resolution(self) -> None:
        for base_url in (
            "http://aoai.example.openai.azure.com/openai/v1",
            "https://user:pass@aoai.example.openai.azure.com/openai/v1",
            "https://models.example.com/openai/v1",
            "https://aoai.example.openai.azure.com",
        ):
            with self.subTest(base_url=base_url), tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
                root = Path(temp)
                broker = SecretsBroker(root / ".aegis" / "secrets.json")
                registry = ModelRegistry(
                    LocalStore(root / ".aegis" / "aegis.db"),
                    AuditLogger(root / ".aegis" / "audit.jsonl"),
                    broker,
                    azure_foundry_base_url=base_url,
                )
                registry.login_provider("azure-foundry", "sk-azure-test")
                route = registry.route("azure-foundry/prod-gpt-4o")

                with self.assertRaises(ValueError):
                    LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

    def test_expanded_openai_compatible_providers_use_shared_guarded_client(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            client = LiveModelClient(broker)
            cases = (
                ("nous", "Hermes-4-70B", "https://inference-api.nousresearch.com/v1/chat/completions", "NOUS_API_KEY"),
                ("deepseek", "deepseek-v4-flash", "https://api.deepseek.com/chat/completions", "DEEPSEEK_API_KEY"),
                ("xai", "grok-4", "https://api.x.ai/v1/chat/completions", "XAI_API_KEY"),
                ("kimi", "kimi-k2.5", "https://api.moonshot.ai/v1/chat/completions", "KIMI_API_KEY"),
                ("minimax", "MiniMax-M2.7", "https://api.minimax.io/v1/chat/completions", "MINIMAX_API_KEY"),
                ("zai", "glm-5.1", "https://api.z.ai/api/paas/v4/chat/completions", "GLM_API_KEY"),
                ("qwen", "qwen-plus", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions", "DASHSCOPE_API_KEY"),
            )

            for provider, model, expected_url, secret_name in cases:
                with self.subTest(provider=provider):
                    api_key = f"sk-{provider}-test"
                    registry.login_provider(provider, api_key)
                    route = registry.route(f"{provider}/{model}")
                    self.assertEqual(route.provider.auth_secret, secret_name)
                    self.assertTrue(route.secret_handle_id)

                    class FakeResponse:
                        def __enter__(self):
                            return self

                        def __exit__(self, exc_type, exc, traceback):
                            return False

                        def read(self) -> bytes:
                            return b'{"choices":[{"message":{"content":"provider response"}}],"usage":{"prompt_tokens":5,"completion_tokens":2}}'

                    captured: dict[str, object] = {}

                    def fake_urlopen(request, timeout):
                        captured["url"] = request.full_url
                        captured["headers"] = dict(request.header_items())
                        captured["payload"] = json.loads(request.data.decode("utf-8"))
                        self.assertNotIn(api_key, request.data.decode("utf-8"))
                        return FakeResponse()

                    with patch("aegis.models.client._open_model_request", fake_urlopen):
                        result = client.chat(route, [{"role": "user", "content": "hello"}])

                    self.assertEqual(captured["url"], expected_url)
                    self.assertIn(f"Bearer {api_key}", captured["headers"]["Authorization"])
                    self.assertEqual(captured["payload"]["model"], model)
                    self.assertEqual(result.provider, provider)
                    self.assertEqual(result.content, "provider response")

    def test_openrouter_live_client_uses_brokered_secret_and_records_usage(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("openrouter", "sk-openrouter-test")
            route = registry.route("openrouter/anthropic/claude-sonnet-4.6")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return (
                        b'{"choices":[{"message":{"content":"live response"}}],'
                        b'"usage":{"prompt_tokens":12,"completion_tokens":3}}'
                    )

            captured_headers: dict[str, str] = {}

            def fake_urlopen(request, timeout):
                self.assertEqual(timeout, 60.0)
                captured_headers.update(dict(request.header_items()))
                self.assertNotIn("sk-openrouter-test", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(result.content, "live response")
            self.assertEqual(result.input_tokens, 12)
            self.assertEqual(result.output_tokens, 3)
            self.assertIn("Bearer sk-openrouter-test", captured_headers["Authorization"])

    def test_openai_live_client_uses_brokered_secret_and_chat_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("openai", "sk-openai-test")
            route = registry.route("openai/gpt-4o-mini")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return (
                        b'{"choices":[{"message":{"content":"openai response"}}],'
                        b'"usage":{"prompt_tokens":9,"completion_tokens":4}}'
                    )

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured["url"], "https://api.openai.com/v1/chat/completions")
            self.assertEqual(captured["payload"]["model"], "gpt-4o-mini")
            self.assertIn("Bearer sk-openai-test", captured["headers"]["Authorization"])
            self.assertEqual(result.content, "openai response")
            self.assertEqual(result.input_tokens, 9)
            self.assertEqual(result.output_tokens, 4)

    def test_anthropic_live_client_uses_brokered_secret_and_messages_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("anthropic", "sk-ant-test")
            route = registry.route("anthropic/claude-sonnet-4.6")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return (
                        b'{"content":[{"type":"text","text":"anthropic response"}],'
                        b'"usage":{"input_tokens":11,"output_tokens":5}}'
                    )

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("sk-ant-test", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(
                    route,
                    [
                        {"role": "system", "content": "system policy"},
                        {"role": "user", "content": "hello"},
                    ],
                )

            self.assertEqual(captured["url"], "https://api.anthropic.com/v1/messages")
            self.assertEqual(captured["payload"]["model"], "claude-sonnet-4.6")
            self.assertEqual(captured["payload"]["system"], "system policy")
            self.assertEqual(captured["payload"]["messages"], [{"role": "user", "content": "hello"}])
            self.assertEqual(captured["headers"]["X-api-key"], "sk-ant-test")
            self.assertEqual(captured["headers"]["Anthropic-version"], "2023-06-01")
            self.assertEqual(result.content, "anthropic response")
            self.assertEqual(result.input_tokens, 11)
            self.assertEqual(result.output_tokens, 5)

    def test_mistral_live_client_uses_openai_compatible_chat_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("mistral", "sk-mistral-test")
            route = registry.route("mistral/mistral-large")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return (
                        b'{"choices":[{"message":{"content":"mistral response"}}],'
                        b'"usage":{"prompt_tokens":13,"completion_tokens":6}}'
                    )

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("sk-mistral-test", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured["url"], "https://api.mistral.ai/v1/chat/completions")
            self.assertEqual(captured["payload"]["model"], "mistral-large")
            self.assertIn("Bearer sk-mistral-test", captured["headers"]["Authorization"])
            self.assertEqual(result.content, "mistral response")
            self.assertEqual(result.input_tokens, 13)
            self.assertEqual(result.output_tokens, 6)

    def test_cohere_live_client_uses_v2_chat_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("cohere", "sk-cohere-test")
            route = registry.route("cohere/command-r-plus")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return (
                        b'{"message":{"role":"assistant","content":[{"type":"text","text":"cohere response"}]},'
                        b'"usage":{"tokens":{"input_tokens":17,"output_tokens":8},'
                        b'"billed_units":{"input_tokens":2,"output_tokens":8}}}'
                    )

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("sk-cohere-test", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured["url"], "https://api.cohere.com/v2/chat")
            self.assertEqual(captured["payload"]["model"], "command-r-plus")
            self.assertEqual(captured["payload"]["stream"], False)
            self.assertIn("Bearer sk-cohere-test", captured["headers"]["Authorization"])
            self.assertEqual(result.content, "cohere response")
            self.assertEqual(result.input_tokens, 17)
            self.assertEqual(result.output_tokens, 8)

    def test_google_live_client_uses_gemini_generate_content_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("google", "sk-google-test")
            route = registry.route("google/gemini-pro")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return (
                        b'{"candidates":[{"content":{"parts":[{"text":"google response"}]}}],'
                        b'"usageMetadata":{"promptTokenCount":19,"candidatesTokenCount":7}}'
                    )

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("sk-google-test", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(
                    route,
                    [
                        {"role": "system", "content": "system policy"},
                        {"role": "user", "content": "hello"},
                    ],
                )

            headers = {key.lower(): value for key, value in captured["headers"].items()}
            self.assertEqual(captured["url"], "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent")
            self.assertEqual(captured["payload"]["contents"], [{"role": "user", "parts": [{"text": "hello"}]}])
            self.assertEqual(captured["payload"]["systemInstruction"], {"parts": [{"text": "system policy"}]})
            self.assertEqual(headers["X-goog-api-key".lower()], "sk-google-test")
            self.assertEqual(result.content, "google response")
            self.assertEqual(result.input_tokens, 19)
            self.assertEqual(result.output_tokens, 7)

    def test_custom_openai_compatible_client_uses_configured_base_url(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(
                LocalStore(root / ".aegis" / "aegis.db"),
                AuditLogger(root / ".aegis" / "audit.jsonl"),
                broker,
                custom_base_url="http://localhost:8000/v1",
            )
            registry.login_provider("custom", "sk-custom-test")
            route = registry.route("custom/vendor-model")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return (
                        b'{"choices":[{"message":{"content":"custom response"}}],'
                        b'"usage":{"prompt_tokens":3,"completion_tokens":2}}'
                    )

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("sk-custom-test", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured["url"], "http://localhost:8000/v1/chat/completions")
            self.assertEqual(captured["payload"]["model"], "vendor-model")
            self.assertIn("Bearer sk-custom-test", captured["headers"]["Authorization"])
            self.assertEqual(result.content, "custom response")
            self.assertEqual(result.input_tokens, 3)
            self.assertEqual(result.output_tokens, 2)

    def test_lmstudio_allows_arbitrary_local_model_ids_without_auth_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            route = registry.route("lmstudio/qwen2.5-coder-7b-instruct")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return (
                        b'{"choices":[{"message":{"content":"lm studio response"}}],'
                        b'"usage":{"prompt_tokens":5,"completion_tokens":4}}'
                    )

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured["url"], "http://localhost:1234/v1/chat/completions")
            self.assertEqual(captured["payload"]["model"], "qwen2.5-coder-7b-instruct")
            self.assertNotIn("Authorization", captured["headers"])
            self.assertEqual(result.content, "lm studio response")
            self.assertEqual(result.input_tokens, 5)
            self.assertEqual(result.output_tokens, 4)

    def test_custom_openai_compatible_client_rejects_unsafe_base_urls_before_auth(self) -> None:
        for base_url in ("http://example.com/v1", "https://user:pass@example.com/v1"):
            with self.subTest(base_url=base_url), tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
                root = Path(temp)
                broker = SecretsBroker(root / ".aegis" / "secrets.json")
                registry = ModelRegistry(
                    LocalStore(root / ".aegis" / "aegis.db"),
                    AuditLogger(root / ".aegis" / "audit.jsonl"),
                    broker,
                    custom_base_url=base_url,
                )
                registry.login_provider("custom", "sk-custom-test")
                route = registry.route("custom/vendor-model")

                def fail_open(request, timeout):
                    raise AssertionError("unsafe custom URL should be rejected before network open")

                with patch("aegis.models.client._open_model_request", fail_open):
                    with self.assertRaisesRegex(ValueError, "custom model base URL"):
                        LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

    def test_model_client_blocks_redirects(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("openai", "sk-openai-test")
            route = registry.route("openai/gpt-4o-mini")
            headers = Message()
            headers["Location"] = "https://evil.test/v1/chat/completions"

            def redirect(request, timeout):
                raise HTTPError(request.full_url, 302, "Found", headers, None)

            with patch("aegis.models.client._open_model_request", redirect):
                with self.assertRaisesRegex(RuntimeError, "redirect blocked"):
                    LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

    def test_ollama_live_client_uses_local_chat_without_auth_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            route = registry.route("ollama/llama3")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return b'{"message":{"content":"local response"},"prompt_eval_count":7,"eval_count":2}'

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured["url"], "http://localhost:11434/api/chat")
            self.assertEqual(captured["payload"]["model"], "llama3")
            self.assertFalse(any(key.lower() == "authorization" for key in captured["headers"]))
            self.assertEqual(result.content, "local response")
            self.assertEqual(result.input_tokens, 7)
            self.assertEqual(result.output_tokens, 2)


if __name__ == "__main__":
    unittest.main()
