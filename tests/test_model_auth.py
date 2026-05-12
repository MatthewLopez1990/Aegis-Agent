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

            insights = registry.usage_insights(days=30)
            insight_text = json.dumps(insights, sort_keys=True)
            self.assertEqual(insights["status"], "usage_insights")
            self.assertEqual(insights["events"], 2)
            self.assertEqual(insights["total_tokens"], 135)
            self.assertEqual(insights["top_provider"]["key"], "openai")
            self.assertEqual(insights["top_model"]["key"], "openai/gpt-4o-mini")
            self.assertFalse(insights["raw_metadata_values_included"])
            self.assertNotIn("secret-like usage context", insight_text)
            self.assertNotIn("sha256:abc", insight_text)

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
            self.assertFalse(registry.auth_status("huggingface")["auth_configured"])

            openai_status = registry.login_provider("openai", "sk-openai-test")
            openrouter_status = registry.login_provider("openrouter", "sk-openrouter-test")
            anthropic_status = registry.login_provider("anthropic", "sk-ant-test")
            google_status = registry.login_provider("google", "sk-google-test")
            mistral_status = registry.login_provider("mistral", "sk-mistral-test")
            cohere_status = registry.login_provider("cohere", "sk-cohere-test")
            hf_status = registry.login_provider("huggingface", "hf-test-token")

            self.assertEqual(openai_status["auth_source"], "local")
            self.assertEqual(openrouter_status["auth_source"], "local")
            self.assertEqual(anthropic_status["auth_source"], "local")
            self.assertEqual(google_status["auth_source"], "local")
            self.assertEqual(mistral_status["auth_source"], "local")
            self.assertEqual(cohere_status["auth_source"], "local")
            self.assertEqual(hf_status["auth_source"], "local")
            self.assertTrue(registry.auth_status("openai")["auth_configured"])
            self.assertTrue(registry.auth_status("openrouter")["auth_configured"])
            self.assertTrue(registry.auth_status("anthropic")["auth_configured"])
            self.assertTrue(registry.auth_status("google")["auth_configured"])
            self.assertTrue(registry.auth_status("mistral")["auth_configured"])
            self.assertTrue(registry.auth_status("cohere")["auth_configured"])
            self.assertTrue(registry.auth_status("huggingface")["auth_configured"])
            self.assertTrue(registry.route("openai/gpt-4o").secret_handle_id)
            self.assertTrue(registry.route("openrouter/openai/gpt-4o").secret_handle_id)
            self.assertTrue(registry.route("anthropic/claude-sonnet-4.6").secret_handle_id)
            self.assertTrue(registry.route("google/gemini-pro").secret_handle_id)
            self.assertTrue(registry.route("mistral/mistral-large").secret_handle_id)
            self.assertTrue(registry.route("cohere/command-r-plus").secret_handle_id)
            self.assertTrue(registry.route("huggingface/Qwen/Qwen3-235B-A22B-Instruct-2507").secret_handle_id)

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
            self.assertNotIn("hf-test-token", audit_text)

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
            qwen = providers["qwen"]
            google = providers["google"]
            aws_bedrock = providers["aws-bedrock"]

            self.assertEqual(openai["auth_methods"], ["api_key", "subscription"])
            self.assertTrue(openai["subscription_auth_supported"])
            self.assertFalse(openai["subscription_auth_configured"])
            self.assertEqual(openai["subscription_auth"]["external_command"], "codex login")
            self.assertEqual(openai["subscription_auth"]["aegis_bridge_status"], "official_cli_bridge_available")
            self.assertEqual(anthropic["auth_methods"], ["api_key", "subscription"])
            self.assertEqual(anthropic["subscription_auth"]["external_command"], "claude auth login")
            self.assertEqual(anthropic["subscription_auth"]["external_login_instruction"], "/login")
            self.assertFalse(openrouter["subscription_auth_supported"])
            self.assertIsNone(openrouter["subscription_auth"])
            self.assertEqual(qwen["auth_methods"], ["api_key", "subscription", "oauth"])
            self.assertEqual(qwen["subscription_auth"]["external_command"], "qwen auth coding-plan")
            self.assertEqual(qwen["subscription_auth"]["external_status_command"], "qwen auth status")
            self.assertIn("cloud_identity", google["auth_methods"])
            self.assertIn("subscription", google["auth_methods"])
            self.assertEqual(google["subscription_auth"]["external_command"], "gemini")
            self.assertEqual(google["subscription_auth"]["external_login_instruction"], "/auth")
            self.assertEqual(google["subscription_auth"]["invocation_bridge"], "gemini_prompt_json")
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

    def test_verified_qwen_coding_plan_subscription_can_invoke_without_token_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            login_completed = subprocess.CompletedProcess(("qwen", "auth", "coding-plan"), 0)
            status_completed = subprocess.CompletedProcess(("qwen", "auth", "status"), 0, stdout="Authenticated with Alibaba Cloud Coding Plan\n", stderr="")
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/qwen"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)),
            ):
                login = registry.login_provider_subscription("qwen", run_external=True)

            self.assertEqual(login["status"], "external_login_verified")
            self.assertEqual(login["invocation_bridge"], "qwen_headless_json")
            self.assertFalse(secret_path.exists())
            self.assertTrue(registry.auth_status("qwen")["auth_configured"])
            self.assertTrue(registry.auth_status("qwen")["subscription_auth_configured"])
            self.assertEqual(registry.auth_status("qwen")["auth_source"], "subscription_cli")
            target_rows = {row["target"]: row for row in registry.auth_targets()["targets"]}
            self.assertEqual(target_rows["Qwen Code Coding Plan subscription"]["status"], "subscription_cli_ready")

            route = registry.route("qwen/qwen3-coder-plus")
            self.assertEqual(route.auth_method, "subscription_cli")
            self.assertIsNone(route.secret_handle_id)

            def fake_qwen_headless(command, **kwargs):
                self.assertEqual(command[0], "/usr/bin/qwen")
                self.assertIn("--output-format", command)
                self.assertEqual(command[command.index("--output-format") + 1], "json")
                self.assertIn("--approval-mode", command)
                self.assertEqual(command[command.index("--approval-mode") + 1], "plan")
                self.assertEqual(command[command.index("--model") + 1], "qwen3-coder-plus")
                self.assertIn("[USER]\nhello from aegis", kwargs["input"])
                self.assertTrue(kwargs["cwd"].name.startswith("aegis-qwen-model-"))
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='[{"type":"assistant","message":{"content":[{"type":"text","text":"ignored assistant event"}]}},{"type":"result","subtype":"success","result":"qwen coding plan response","usage":{"input_tokens":9,"output_tokens":5}}]\n',
                    stderr="",
                )

            with (
                patch("aegis.models.client.shutil.which", return_value="/usr/bin/qwen"),
                patch("aegis.models.client.subprocess.run", side_effect=fake_qwen_headless) as run,
            ):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "qwen coding plan response")
            self.assertEqual(result.raw_usage["source"], "subscription_cli")
            self.assertEqual(result.raw_usage["bridge"], "qwen_headless_json")
            run.assert_called_once()

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_subscription_login_requested", audit_text)
            self.assertNotIn("sk-sp-", audit_text)
            self.assertNotIn("qwen_refresh_token", audit_text)

    def test_verified_gemini_cli_subscription_can_invoke_without_token_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            login_completed = subprocess.CompletedProcess(("gemini",), 0)
            status_command = (
                "gemini",
                "-p",
                "Respond with OK only.",
                "--output-format=json",
                "--approval-mode=plan",
                "--sandbox",
                "--skip-trust",
            )
            status_completed = subprocess.CompletedProcess(
                status_command,
                0,
                stdout='{"response":"OK","stats":{"models":{"gemini-2.5-flash":{"tokens":{"prompt":4,"response":1}}}}}\n',
                stderr="",
            )
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/gemini"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)) as auth_run,
            ):
                login = registry.login_provider_subscription("google", run_external=True)

            self.assertEqual(auth_run.call_args_list[0].args[0], ("gemini",))
            self.assertEqual(auth_run.call_args_list[1].args[0], status_command)
            self.assertTrue(Path(auth_run.call_args_list[1].kwargs["cwd"]).name.startswith("aegis-gemini-auth-status-"))
            self.assertEqual(login["status"], "external_login_verified")
            self.assertEqual(login["invocation_bridge"], "gemini_prompt_json")
            self.assertFalse(secret_path.exists())
            self.assertTrue(registry.auth_status("google")["auth_configured"])
            self.assertTrue(registry.auth_status("google")["subscription_auth_configured"])
            self.assertEqual(registry.auth_status("google")["auth_source"], "subscription_cli")
            target_rows = {row["target"]: row for row in registry.auth_targets()["targets"]}
            self.assertEqual(target_rows["Google Gemini CLI subscription"]["status"], "subscription_cli_ready")

            route = registry.route("google/gemini-2.5-flash")
            self.assertEqual(route.auth_method, "subscription_cli")
            self.assertIsNone(route.secret_handle_id)

            def fake_gemini_prompt(command, **kwargs):
                self.assertEqual(command[0], "/usr/bin/gemini")
                self.assertEqual(command[1], "-p")
                self.assertIn("[USER]\nhello from aegis", command[2])
                self.assertIn("--output-format=json", command)
                self.assertIn("--approval-mode=plan", command)
                self.assertIn("--sandbox", command)
                self.assertIn("--skip-trust", command)
                self.assertIn("--model=gemini-2.5-flash", command)
                self.assertTrue(kwargs["cwd"].name.startswith("aegis-gemini-model-"))
                self.assertNotIn("input", kwargs)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"response":"gemini cli response","stats":{"models":{"gemini-2.5-flash":{"tokens":{"prompt":9,"response":5}}}}}\n',
                    stderr="",
                )

            with (
                patch("aegis.models.client.shutil.which", return_value="/usr/bin/gemini"),
                patch("aegis.models.client.subprocess.run", side_effect=fake_gemini_prompt) as run,
            ):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "gemini cli response")
            self.assertEqual(result.raw_usage["source"], "subscription_cli")
            self.assertEqual(result.raw_usage["bridge"], "gemini_prompt_json")
            run.assert_called_once()

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_subscription_login_requested", audit_text)
            self.assertNotIn("GOOGLE_REFRESH_TOKEN", audit_text)
            self.assertNotIn("ya29.", audit_text)
            self.assertNotIn("session_cookie", audit_text)

    def test_verified_github_copilot_oauth_can_invoke_without_raw_token_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            class FakeResponse:
                def __init__(self, payload: dict[str, object], status: int = 200) -> None:
                    self.payload = payload
                    self.status = status

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            captured_auth: list[tuple[str, str]] = []

            def fake_auth_open(request, timeout):
                body = request.data.decode("utf-8")
                captured_auth.append((request.full_url, body))
                if request.full_url.endswith("/login/device/code"):
                    return FakeResponse(
                        {
                            "device_code": "device-123",
                            "user_code": "GHUB-1234",
                            "verification_uri": "https://github.com/login/device",
                            "expires_in": 60,
                            "interval": 1,
                        }
                    )
                return FakeResponse({"access_token": "gho_copilot_secret", "token_type": "bearer", "scope": "read:user"})

            with patch("aegis.models.registry._open_auth_request", fake_auth_open):
                login = registry.login_provider_external("github-copilot", method="oauth-device", run_external=True, timeout_seconds=5)

            self.assertEqual(login["status"], "external_login_verified")
            self.assertEqual(login["auth_source"], "oauth_device_flow")
            self.assertTrue(login["oauth_token_brokered"])
            self.assertNotIn("gho_copilot_secret", json.dumps(login))
            self.assertTrue(secret_path.exists())
            self.assertEqual(broker.resolve_stored_secret("GITHUB_COPILOT_OAUTH_TOKEN"), "gho_copilot_secret")
            self.assertIn("client_id=Ov23li8tweQw6odWQebz", captured_auth[0][1])
            self.assertIn("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code", captured_auth[1][1])
            self.assertTrue(registry.auth_status("github-copilot")["auth_configured"])
            self.assertEqual(registry.auth_status("github-copilot")["auth_source"], "oauth_device_flow")

            route = registry.route("github-copilot/gpt-5.1-codex")
            self.assertEqual(route.auth_method, "oauth_token")
            self.assertIsNone(route.secret_handle_id)

            captured_model: list[tuple[str, dict[str, str], dict[str, object] | None]] = []

            def fake_model_open(request, timeout):
                headers = {key.lower(): value for key, value in request.header_items()}
                payload = json.loads(request.data.decode("utf-8")) if request.data else None
                captured_model.append((request.full_url, headers, payload))
                if request.full_url == "https://api.github.com/copilot_internal/v2/token":
                    self.assertEqual(headers["authorization"], "token gho_copilot_secret")
                    return FakeResponse({"token": "copilot-api-secret", "expires_at": 9999999999})
                self.assertEqual(request.full_url, "https://api.githubcopilot.com/chat/completions")
                self.assertEqual(headers["authorization"], "Bearer copilot-api-secret")
                self.assertEqual(payload["model"], "gpt-5.1-codex")
                self.assertEqual(payload["messages"][0]["content"], "hello from aegis")
                return FakeResponse({"choices": [{"message": {"content": "copilot response"}}], "usage": {"prompt_tokens": 4, "completion_tokens": 2}})

            with patch("aegis.models.client._open_model_request", fake_model_open):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "copilot response")
            self.assertEqual(result.raw_usage["source"], "oauth_device_flow")
            self.assertEqual(result.raw_usage["bridge"], "copilot_oauth_chat_completions")
            self.assertEqual([entry[0] for entry in captured_model], ["https://api.github.com/copilot_internal/v2/token", "https://api.githubcopilot.com/chat/completions"])

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_external_login_requested", audit_text)
            self.assertNotIn("COPILOT_GITHUB_TOKEN", audit_text)
            self.assertNotIn("gho_copilot_secret", audit_text)
            self.assertNotIn("copilot-api-secret", audit_text)

    def test_google_gemini_oauth_login_brokers_tokens_and_invokes_cloudcode(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"AEGIS_GOOGLE_GEMINI_OAUTH_CLIENT_ID": "test-google-client-id", "AEGIS_GOOGLE_GEMINI_OAUTH_CLIENT_SECRET": "test-google-client-secret"}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            class FakeResponse:
                def __init__(self, payload: dict[str, object]) -> None:
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            captured_auth: list[tuple[str, str]] = []

            def fake_auth_open(request, timeout):
                body = request.data.decode("utf-8")
                captured_auth.append((request.full_url, body))
                self.assertEqual(request.full_url, "https://oauth2.googleapis.com/token")
                return FakeResponse(
                    {
                        "access_token": "google-access-secret",
                        "refresh_token": "google-refresh-secret",
                        "expires_in": 3600,
                        "token_type": "Bearer",
                        "scope": "https://www.googleapis.com/auth/cloud-platform",
                    }
                )

            with (
                patch("aegis.models.registry._oauth_pkce_pair", return_value=("verifier-123", "challenge-123")),
                patch("aegis.models.registry._google_gemini_collect_authorization_code", return_value=("code-123", "http://127.0.0.1:8085/oauth2callback")),
                patch("aegis.models.registry._open_auth_request", fake_auth_open),
            ):
                login = registry.login_provider_external("google-gemini-oauth", method="oauth", run_external=True, timeout_seconds=5)

            self.assertEqual(login["target"], "Google Gemini OAuth / Code Assist")
            self.assertEqual(login["status"], "external_login_verified")
            self.assertEqual(login["auth_source"], "oauth_device_flow")
            self.assertTrue(login["oauth_token_brokered"])
            self.assertFalse(login["token_captured"])
            self.assertNotIn("google-access-secret", json.dumps(login))
            self.assertNotIn("google-refresh-secret", json.dumps(login))
            self.assertEqual(broker.resolve_stored_secret("GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN"), "google-access-secret")
            self.assertEqual(broker.resolve_stored_secret("GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN"), "google-refresh-secret")
            self.assertIn("grant_type=authorization_code", captured_auth[0][1])
            self.assertIn("code=code-123", captured_auth[0][1])
            self.assertIn("code_verifier=verifier-123", captured_auth[0][1])
            self.assertIn("client_id=test-google-client-id", captured_auth[0][1])

            status = registry.auth_status("google-gemini-oauth")
            self.assertTrue(status["auth_configured"])
            self.assertEqual(status["auth_source"], "oauth_device_flow")
            targets = registry.auth_targets()
            by_target = {row["target"]: row for row in targets["targets"]}
            self.assertEqual(by_target["Google Gemini OAuth / Code Assist"]["status"], "external_login_verified")
            self.assertEqual(by_target["Google Gemini OAuth / Code Assist"]["bridge_status"], "oauth_device_flow_ready")
            self.assertTrue(by_target["Google Gemini OAuth / Code Assist"]["oauth_token_brokered"])
            self.assertNotIn("Google Gemini OAuth / Code Assist", targets["subscription_bridge_targets"])

            route = registry.route("google-gemini-oauth/gemini-2.5-flash")
            self.assertEqual(route.auth_method, "oauth_token")
            route.auth_metadata["expires_at"] = "2000-01-01T00:00:00+00:00"
            captured_model: list[tuple[str, dict[str, str], dict[str, object] | str]] = []

            def fake_model_open(request, timeout):
                headers = {key.lower(): value for key, value in request.header_items()}
                payload: dict[str, object] | str
                if request.data and headers.get("content-type") == "application/x-www-form-urlencoded":
                    payload = request.data.decode("utf-8")
                else:
                    payload = json.loads(request.data.decode("utf-8")) if request.data else {}
                captured_model.append((request.full_url, headers, payload))
                if request.full_url == "https://oauth2.googleapis.com/token":
                    self.assertIn("grant_type=refresh_token", str(payload))
                    self.assertIn("refresh_token=google-refresh-secret", str(payload))
                    return FakeResponse({"access_token": "google-access-refreshed", "refresh_token": "google-refresh-rotated", "expires_in": 3600})
                self.assertEqual(headers["authorization"], "Bearer google-access-refreshed")
                if request.full_url.endswith("/v1internal:loadCodeAssist"):
                    return FakeResponse({"response": {"currentTier": {"id": "free-tier"}, "cloudaicompanionProject": "cloud-project-123"}})
                self.assertEqual(request.full_url, "https://cloudcode-pa.googleapis.com/v1internal:generateContent")
                self.assertIsInstance(payload, dict)
                self.assertEqual(payload["project"], "cloud-project-123")
                self.assertEqual(payload["model"], "gemini-2.5-flash")
                self.assertEqual(payload["request"]["contents"][0]["parts"][0]["text"], "hello from aegis")
                return FakeResponse(
                    {
                        "response": {
                            "candidates": [{"content": {"parts": [{"text": "gemini oauth response"}]}}],
                            "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 3},
                        }
                    }
                )

            with patch("aegis.models.client._open_model_request", fake_model_open):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "gemini oauth response")
            self.assertEqual(result.input_tokens, 5)
            self.assertEqual(result.output_tokens, 3)
            self.assertEqual(result.raw_usage["source"], "oauth_device_flow")
            self.assertEqual(result.raw_usage["bridge"], "google_gemini_cloudcode_generate_content")
            self.assertEqual(result.raw_usage["project_source"], "discovered")
            self.assertEqual(broker.resolve_stored_secret("GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN"), "google-access-refreshed")
            self.assertEqual(broker.resolve_stored_secret("GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN"), "google-refresh-rotated")
            self.assertEqual([entry[0] for entry in captured_model], ["https://oauth2.googleapis.com/token", "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist", "https://cloudcode-pa.googleapis.com/v1internal:generateContent"])

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_external_login_requested", audit_text)
            self.assertNotIn("google-access-secret", audit_text)
            self.assertNotIn("google-refresh-secret", audit_text)
            self.assertNotIn("google-access-refreshed", audit_text)
            self.assertNotIn("google-refresh-rotated", audit_text)

    def test_google_gemini_oauth_quota_uses_brokered_token_without_secret_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"AEGIS_GOOGLE_GEMINI_OAUTH_CLIENT_ID": "test-google-client-id", "AEGIS_GOOGLE_GEMINI_OAUTH_CLIENT_SECRET": "test-google-client-secret"}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            broker.store_secret(name="GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN", value="quota-access-secret")
            broker.store_secret(name="GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN", value="quota-refresh-secret")
            registry._remember_external_auth_link(
                "google-gemini-oauth",
                "oauth",
                {
                    "target": "Google Gemini OAuth / Code Assist",
                    "status": "external_login_verified",
                    "auth_source": "oauth_device_flow",
                    "aegis_bridge_status": "oauth_device_flow_ready",
                    "invocation_bridge": "google_gemini_cloudcode_generate_content",
                    "inference_base_url": "https://cloudcode-pa.googleapis.com",
                    "access_token_secret": "GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN",
                    "refresh_token_secret": "GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                    "oauth_token_brokered": True,
                },
            )
            route = registry.route("google-gemini-oauth/gemini-2.5-flash")

            class FakeResponse:
                def __init__(self, payload: dict[str, object]) -> None:
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            captured_model: list[tuple[str, dict[str, str], dict[str, object]]] = []

            def fake_model_open(request, timeout):
                headers = {key.lower(): value for key, value in request.header_items()}
                payload = json.loads(request.data.decode("utf-8")) if request.data else {}
                captured_model.append((request.full_url, headers, payload))
                self.assertEqual(headers["authorization"], "Bearer quota-access-secret")
                if request.full_url.endswith("/v1internal:loadCodeAssist"):
                    return FakeResponse({"response": {"currentTier": {"id": "free-tier"}, "cloudaicompanionProject": "quota-project-123"}})
                self.assertEqual(request.full_url, "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota")
                self.assertEqual(payload["project"], "quota-project-123")
                return FakeResponse(
                    {
                        "buckets": [
                            {"modelId": "gemini-2.5-flash", "tokenType": "RPM", "remainingFraction": 0.75, "resetTime": "2026-05-13T00:00:00Z"},
                            {"modelId": "gemini-2.5-pro", "tokenType": "RPD", "remainingFraction": 1.2, "resetTime": ""},
                        ]
                    }
                )

            with patch("aegis.models.client._open_model_request", fake_model_open):
                result = LiveModelClient(broker).google_gemini_oauth_quota(route)

            self.assertEqual(result["status"], "quota_available")
            self.assertEqual(result["provider"], "google-gemini-oauth")
            self.assertEqual(result["model"], "gemini-2.5-flash")
            self.assertEqual(result["project_id"], "quota-project-123")
            self.assertEqual(result["project_source"], "discovered")
            self.assertEqual(result["bucket_count"], 2)
            self.assertEqual(result["buckets"][0]["remaining_percent"], 75.0)
            self.assertEqual(result["buckets"][1]["remaining_percent"], 100.0)
            serialized = json.dumps(result, sort_keys=True)
            self.assertNotIn("quota-access-secret", serialized)
            self.assertNotIn("quota-refresh-secret", serialized)
            self.assertEqual([entry[0] for entry in captured_model], ["https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist", "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota"])

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

    def test_provider_native_auth_handoff_runs_github_oauth_without_raw_token_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), SecretsBroker(secret_path))

            class FakeResponse:
                def __init__(self, payload: dict[str, object], status: int = 200) -> None:
                    self.payload = payload
                    self.status = status

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            def fake_open(request, timeout):
                if request.full_url.endswith("/login/device/code"):
                    return FakeResponse({"device_code": "device-123", "user_code": "GHUB-1234", "verification_uri": "https://github.com/login/device", "expires_in": 60, "interval": 1})
                return FakeResponse({"access_token": "gho_copilot_secret", "token_type": "bearer", "scope": "read:user"})

            with patch("aegis.models.registry._open_auth_request", fake_open):
                status = registry.login_provider_external("github-copilot", method="oauth-device", run_external=True, timeout_seconds=5)

            self.assertEqual(status["provider"], "github-copilot")
            self.assertEqual(status["target"], "GitHub Copilot")
            self.assertEqual(status["method"], "oauth_device")
            self.assertEqual(status["status"], "external_login_verified")
            self.assertTrue(status["external_login_attempted"])
            self.assertTrue(status["external_status_verified"])
            self.assertEqual(status["auth_source"], "oauth_device_flow")
            self.assertEqual(status["external_command_argv"], [])
            self.assertTrue(status["oauth_token_brokered"])
            self.assertTrue(status["auth_configured"])
            self.assertFalse(status["token_captured"])
            self.assertTrue(secret_path.exists())

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_external_login_requested", audit_text)
            self.assertNotIn("GH_TOKEN", audit_text)
            self.assertNotIn("COPILOT_GITHUB_TOKEN", audit_text)
            self.assertNotIn("gho_copilot_secret", audit_text)

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

    def test_verified_google_vertex_cloud_identity_can_invoke_without_token_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(
                LocalStore(root / ".aegis" / "aegis.db"),
                AuditLogger(audit_path),
                broker,
                google_vertex_project="aegis-test-project",
                google_vertex_location="us-central1",
            )

            login_completed = subprocess.CompletedProcess(("gcloud", "auth", "login", "--update-adc"), 0)
            status_completed = subprocess.CompletedProcess(
                ("gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"),
                0,
                stdout="operator@example.com\n",
                stderr="",
            )
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/gcloud"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)),
            ):
                login = registry.login_provider_external("google", method="cloud-identity", run_external=True)

            self.assertEqual(login["status"], "external_login_verified")
            self.assertFalse(secret_path.exists())
            self.assertTrue(registry.auth_status("google")["auth_configured"])
            self.assertEqual(registry.auth_status("google")["auth_source"], "official_cli")

            route = registry.route("google/gemini-2.5-flash")
            self.assertEqual(route.auth_method, "cloud_identity_cli")
            self.assertIsNone(route.secret_handle_id)
            self.assertEqual(route.provider.external_auth_method, "cloud_identity")

            def fake_vertex_request(command, **kwargs):
                self.assertEqual(command[0], "/usr/bin/bash")
                self.assertEqual(command[1], "-lc")
                self.assertNotIn("ya29.", command[2])
                self.assertEqual(command[3], "aegis-google-vertex")
                self.assertEqual(command[5], "https://us-central1-aiplatform.googleapis.com/v1/projects/aegis-test-project/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent")
                self.assertEqual(command[6], "/usr/bin/gcloud")
                self.assertEqual(command[7], "/usr/bin/curl")
                payload = json.loads(Path(command[4]).read_text(encoding="utf-8"))
                self.assertEqual(payload["contents"][0]["role"], "user")
                self.assertEqual(payload["contents"][0]["parts"][0]["text"], "hello from aegis")
                self.assertEqual(payload["generationConfig"]["temperature"], 0.2)
                self.assertTrue(kwargs["cwd"].name.startswith("aegis-google-vertex-model-"))
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"candidates":[{"content":{"parts":[{"text":"vertex response"}]}}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":6}}\n',
                    stderr="",
                )

            with (
                patch("aegis.models.client.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"),
                patch("aegis.models.client.subprocess.run", side_effect=fake_vertex_request) as run,
            ):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello from aegis"}])

            self.assertEqual(result.content, "vertex response")
            self.assertEqual(result.input_tokens, 11)
            self.assertEqual(result.output_tokens, 6)
            self.assertEqual(result.raw_usage["source"], "official_cli")
            self.assertEqual(result.raw_usage["bridge"], "gcloud_vertex_rest")
            run.assert_called_once()

            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertIn("model.auth_external_login_requested", audit_text)
            self.assertNotIn("operator@example.com", audit_text)
            self.assertNotIn("ya29.", audit_text)

    def test_google_vertex_requires_project_and_location_before_cloud_identity_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)

            login_completed = subprocess.CompletedProcess(("gcloud", "auth", "login", "--update-adc"), 0)
            status_completed = subprocess.CompletedProcess(
                ("gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"),
                0,
                stdout="operator@example.com\n",
                stderr="",
            )
            with (
                patch("aegis.models.registry.shutil.which", return_value="/usr/bin/gcloud"),
                patch("aegis.models.registry.subprocess.run", side_effect=(login_completed, status_completed)),
            ):
                registry.login_provider_external("google", method="cloud-identity", run_external=True)
            route = registry.route("google/gemini-2.5-flash")

            self.assertEqual(route.auth_method, "cloud_identity_cli")
            with self.assertRaises(ValueError):
                LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

    def test_nous_oauth_login_brokers_tokens_and_agent_key_without_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), SecretsBroker(secret_path))

            class FakeResponse:
                def __init__(self, payload: dict[str, object]) -> None:
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            captured: list[tuple[str, dict[str, str], str]] = []

            def fake_open(request, timeout):
                body = request.data.decode("utf-8")
                headers = dict(request.header_items())
                captured.append((request.full_url, headers, body))
                if request.full_url.endswith("/api/oauth/device/code"):
                    return FakeResponse(
                        {
                            "device_code": "device-123",
                            "user_code": "NOUS-1234",
                            "verification_uri": "https://portal.nousresearch.com/device",
                            "verification_uri_complete": "https://portal.nousresearch.com/device?user_code=NOUS-1234",
                            "expires_in": 60,
                            "interval": 1,
                        }
                    )
                if request.full_url.endswith("/api/oauth/token"):
                    return FakeResponse(
                        {
                            "access_token": "nous-access-secret",
                            "refresh_token": "nous-refresh-secret",
                            "expires_in": 3600,
                            "token_type": "Bearer",
                            "scope": "inference:mint_agent_key",
                        }
                    )
                return FakeResponse({"api_key": "nous-agent-key-secret", "key_id": "key-123", "expires_at": "2999-01-01T00:00:00+00:00", "expires_in": 86400})

            with patch("aegis.models.registry._open_auth_request", fake_open):
                status = registry.login_provider_external("nous", method="oauth", run_external=True, timeout_seconds=5)

            self.assertEqual(status["target"], "Nous Portal OAuth subscription")
            self.assertEqual(status["status"], "external_login_verified")
            self.assertEqual(status["auth_source"], "oauth_device_flow")
            self.assertTrue(status["oauth_token_brokered"])
            self.assertTrue(status["agent_key_brokered"])
            self.assertFalse(status["token_captured"])
            self.assertNotIn("nous-access-secret", json.dumps(status))
            self.assertNotIn("nous-refresh-secret", json.dumps(status))
            self.assertNotIn("nous-agent-key-secret", json.dumps(status))
            self.assertTrue(secret_path.exists())
            self.assertEqual(registry.secrets_broker.resolve_stored_secret("NOUS_OAUTH_ACCESS_TOKEN"), "nous-access-secret")
            self.assertEqual(registry.secrets_broker.resolve_stored_secret("NOUS_OAUTH_REFRESH_TOKEN"), "nous-refresh-secret")
            self.assertEqual(registry.secrets_broker.resolve_stored_secret("NOUS_OAUTH_AGENT_KEY"), "nous-agent-key-secret")
            self.assertIn("client_id=hermes-cli", captured[0][2])
            self.assertIn("scope=inference%3Amint_agent_key", captured[0][2])
            self.assertIn("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code", captured[1][2])
            self.assertEqual(captured[2][0], "https://portal.nousresearch.com/api/oauth/agent-key")
            self.assertEqual(captured[2][1]["Authorization"], "Bearer nous-access-secret")
            targets = registry.auth_targets()
            by_target = {row["target"]: row for row in targets["targets"]}
            self.assertEqual(by_target["Nous Portal OAuth subscription"]["status"], "external_login_verified")
            self.assertEqual(by_target["Nous Portal OAuth subscription"]["bridge_status"], "oauth_device_flow_ready")
            self.assertTrue(by_target["Nous Portal OAuth subscription"]["agent_key_brokered"])
            self.assertNotIn("Nous Portal OAuth subscription", targets["subscription_bridge_targets"])

    def test_minimax_oauth_login_brokers_tokens_without_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), SecretsBroker(secret_path))

            class FakeResponse:
                def __init__(self, payload: dict[str, object]) -> None:
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            captured: list[tuple[str, str]] = []

            def fake_open(request, timeout):
                body = request.data.decode("utf-8")
                captured.append((request.full_url, body))
                if request.full_url.endswith("/oauth/code"):
                    return FakeResponse({"user_code": "ABCD-EFGH", "verification_uri": "https://api.minimax.io/oauth/verify", "expired_in": 60, "interval": 1, "state": "state-123"})
                return FakeResponse({"status": "success", "access_token": "mx-access-secret", "refresh_token": "mx-refresh-secret", "expired_in": 3600, "token_type": "Bearer"})

            with patch("aegis.models.registry._minimax_pkce_pair", return_value=("verifier", "challenge", "state-123")), patch("aegis.models.registry._open_auth_request", fake_open):
                status = registry.login_provider_external("minimax-oauth", method="oauth", run_external=True, timeout_seconds=5)

            self.assertEqual(status["target"], "MiniMax OAuth")
            self.assertEqual(status["status"], "external_login_verified")
            self.assertEqual(status["auth_source"], "oauth_device_flow")
            self.assertTrue(status["oauth_token_brokered"])
            self.assertFalse(status["token_captured"])
            self.assertNotIn("mx-access-secret", json.dumps(status))
            self.assertNotIn("mx-refresh-secret", json.dumps(status))
            self.assertTrue(secret_path.exists())
            self.assertEqual(registry.secrets_broker.resolve_stored_secret("MINIMAX_OAUTH_ACCESS_TOKEN"), "mx-access-secret")
            self.assertEqual(registry.secrets_broker.resolve_stored_secret("MINIMAX_OAUTH_REFRESH_TOKEN"), "mx-refresh-secret")
            self.assertIn("code_challenge=challenge", captured[0][1])
            self.assertIn("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auser_code", captured[1][1])
            targets = registry.auth_targets()
            by_target = {row["target"]: row for row in targets["targets"]}
            self.assertEqual(by_target["MiniMax OAuth"]["status"], "external_login_verified")
            self.assertEqual(by_target["MiniMax OAuth"]["bridge_status"], "oauth_device_flow_ready")
            self.assertTrue(by_target["MiniMax OAuth"]["oauth_token_brokered"])
            self.assertNotIn("MiniMax OAuth", targets["subscription_bridge_targets"])

    def test_verified_provider_native_auth_links_update_targets_and_logout(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)

            class FakeResponse:
                def __init__(self, payload: dict[str, object], status: int = 200) -> None:
                    self.payload = payload
                    self.status = status

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            def fake_open(request, timeout):
                if request.full_url.endswith("/login/device/code"):
                    return FakeResponse({"device_code": "device-123", "user_code": "GHUB-1234", "verification_uri": "https://github.com/login/device", "expires_in": 60, "interval": 1})
                return FakeResponse({"access_token": "gho_copilot_secret", "token_type": "bearer", "scope": "read:user"})

            with patch("aegis.models.registry._open_auth_request", fake_open):
                login = registry.login_provider_external("github-copilot", method="oauth-device", run_external=True, timeout_seconds=5)
            status = registry.auth_status("github-copilot")
            qwen_status = registry.auth_status("qwen")
            targets = registry.auth_targets()
            by_target = {row["target"]: row for row in targets["targets"]}

            self.assertEqual(login["status"], "external_login_verified")
            self.assertFalse(login["token_captured"])
            self.assertTrue(login["oauth_token_brokered"])
            self.assertEqual(broker.resolve_stored_secret("GITHUB_COPILOT_OAUTH_TOKEN"), "gho_copilot_secret")
            self.assertTrue(status["auth_configured"])
            self.assertTrue(status["external_auth_configured"])
            self.assertEqual(status["auth_source"], "oauth_device_flow")
            self.assertEqual(status["provider_native_auth"][0]["status"], "external_login_verified")
            self.assertEqual(status["provider_native_auth"][0]["bridge_status"], "oauth_device_flow_ready")
            self.assertIn("oauth", qwen_status["auth_methods"])
            self.assertIn("subscription", qwen_status["auth_methods"])
            self.assertEqual(qwen_status["subscription_auth"]["aegis_bridge_status"], "official_cli_bridge_available")
            self.assertEqual(qwen_status["provider_native_auth"][0]["status"], "provider_discontinued")
            self.assertEqual(by_target["GitHub Copilot"]["status"], "external_login_verified")
            self.assertEqual(by_target["GitHub Copilot"]["bridge_status"], "oauth_device_flow_ready")
            self.assertTrue(by_target["GitHub Copilot"]["oauth_token_brokered"])
            self.assertTrue(by_target["GitHub Copilot"]["external_auth_configured"])
            self.assertIn("GitHub Copilot", targets["verified_external_auth_targets"])
            self.assertNotIn("GitHub Copilot", targets["subscription_bridge_targets"])
            self.assertFalse(any(row["raw_tokens_captured"] for row in targets["targets"]))

            logout = registry.logout_provider("github-copilot")
            targets_after = registry.auth_targets()
            by_target_after = {row["target"]: row for row in targets_after["targets"]}

            self.assertEqual(logout["removed_external_auth_links"], 1)
            self.assertFalse(logout["external_auth_configured"])
            self.assertEqual(logout["provider_native_auth"][0]["status"], "oauth_device_flow_available")
            self.assertEqual(by_target_after["GitHub Copilot"]["status"], "oauth_device_flow_available")

    def test_provider_auth_targets_track_hermes_and_claude_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"))

            targets = registry.auth_targets()
            by_target = {row["target"]: row for row in targets["targets"]}

            self.assertEqual(targets["status"], "auth_parity_gap_tracked")
            self.assertGreaterEqual(targets["target_provider_count"], 40)
            self.assertIn("api_key", targets["implemented_auth_methods"])
            self.assertIn("subscription", targets["implemented_auth_methods"])
            self.assertIn("oauth", targets["implemented_auth_methods"])
            self.assertIn("oauth_device", targets["implemented_auth_methods"])
            self.assertIn("cloud_identity", targets["implemented_auth_methods"])
            self.assertEqual(by_target["OpenAI API"]["status"], "api_key_ready")
            self.assertEqual(by_target["OpenAI Codex / ChatGPT subscription"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["OpenAI Codex / ChatGPT subscription"]["external_command"], "codex login")
            self.assertEqual(by_target["Claude Code subscription"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["Claude Code subscription"]["external_command"], "claude auth login")
            self.assertEqual(by_target["Claude Code subscription"]["external_login_instruction"], "/login")
            self.assertEqual(by_target["Nous Portal API key"]["status"], "api_key_ready")
            self.assertEqual(by_target["Nous Portal OAuth subscription"]["status"], "oauth_device_flow_available")
            self.assertEqual(by_target["Nous Portal OAuth subscription"]["provider_token_source"], "official Nous Portal OAuth device-code flow")
            self.assertEqual(by_target["Nous Portal OAuth subscription"]["invocation_bridge"], "nous_oauth_agent_key")
            self.assertEqual(by_target["GitHub Copilot"]["status"], "oauth_device_flow_available")
            self.assertEqual(by_target["GitHub Copilot"]["external_command"], "GitHub browser OAuth device-code login")
            self.assertEqual(by_target["GitHub Copilot"]["invocation_bridge"], "copilot_oauth_chat_completions")
            self.assertEqual(by_target["Google Gemini"]["status"], "api_key_ready")
            self.assertEqual(by_target["Google Gemini OAuth / Code Assist"]["status"], "oauth_device_flow_available")
            self.assertEqual(by_target["Google Gemini OAuth / Code Assist"]["external_command"], "Google browser OAuth PKCE login")
            self.assertEqual(by_target["Google Gemini OAuth / Code Assist"]["invocation_bridge"], "google_gemini_cloudcode_generate_content")
            self.assertEqual(by_target["Google Vertex AI / Gemini cloud identity"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["Google Vertex AI / Gemini cloud identity"]["external_command"], "gcloud auth login --update-adc")
            self.assertEqual(by_target["Google Vertex AI / Gemini cloud identity"]["external_status_command"], "gcloud auth list --filter=status:ACTIVE --format=value(account)")
            self.assertEqual(by_target["Google Gemini CLI subscription"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["Google Gemini CLI subscription"]["external_command"], "gemini")
            self.assertEqual(by_target["Google Gemini CLI subscription"]["external_status_command"], 'gemini -p "Respond with OK only." --output-format=json --approval-mode=plan --sandbox --skip-trust')
            self.assertEqual(by_target["Google Gemini CLI subscription"]["external_login_instruction"], "/auth")
            self.assertEqual(by_target["DeepSeek"]["status"], "api_key_ready")
            self.assertEqual(by_target["Kimi China"]["status"], "api_key_ready")
            self.assertEqual(by_target["Arcee AI"]["status"], "api_key_ready")
            self.assertEqual(by_target["GMI Cloud"]["status"], "api_key_ready")
            self.assertEqual(by_target["MiniMax"]["status"], "api_key_ready")
            self.assertEqual(by_target["MiniMax China"]["status"], "api_key_ready")
            self.assertEqual(by_target["MiniMax Token Plan"]["status"], "api_key_ready")
            self.assertEqual(by_target["MiniMax Token Plan"]["required_auth"], ["api_key"])
            self.assertEqual(by_target["MiniMax Token Plan"]["account_surface"], "MiniMax Token Plan")
            self.assertEqual(by_target["MiniMax OAuth"]["status"], "oauth_device_flow_available")
            self.assertEqual(by_target["MiniMax OAuth"]["provider_token_source"], "official MiniMax OAuth device-code flow")
            self.assertEqual(by_target["MiniMax OAuth"]["invocation_bridge"], "minimax_oauth_anthropic_compatible")
            self.assertEqual(by_target["AWS Bedrock"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["Azure Foundry API key"]["status"], "api_key_ready")
            self.assertEqual(by_target["Azure Foundry"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["Qwen DashScope API"]["status"], "api_key_ready")
            self.assertEqual(by_target["Alibaba Cloud Coding Plan API"]["status"], "api_key_ready")
            self.assertEqual(by_target["Qwen Code Coding Plan subscription"]["required_auth"], ["subscription"])
            self.assertEqual(by_target["Qwen Code Coding Plan subscription"]["status"], "official_cli_bridge_available")
            self.assertEqual(by_target["Qwen Code Coding Plan subscription"]["external_command"], "qwen auth coding-plan")
            self.assertEqual(by_target["Qwen Code Coding Plan subscription"]["external_login_instruction"], "/auth")
            self.assertEqual(by_target["StepFun Step Plan"]["status"], "api_key_ready")
            self.assertEqual(by_target["Hugging Face"]["status"], "api_key_ready")
            self.assertEqual(by_target["NVIDIA NIM"]["status"], "api_key_ready")
            self.assertEqual(by_target["Vercel AI Gateway"]["status"], "api_key_ready")
            self.assertEqual(by_target["OpenCode Zen"]["status"], "api_key_ready")
            self.assertEqual(by_target["OpenCode Go"]["status"], "api_key_ready")
            self.assertEqual(by_target["Kilo Code"]["status"], "api_key_ready")
            self.assertEqual(by_target["Xiaomi MiMo"]["status"], "api_key_ready")
            self.assertEqual(by_target["Tencent TokenHub"]["status"], "api_key_ready")
            self.assertEqual(by_target["Ollama Cloud"]["status"], "api_key_ready")
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
                ("kimi-cn", "kimi-k2.5", "https://api.moonshot.cn/v1/chat/completions", "KIMI_CN_API_KEY"),
                ("arcee", "auto", "https://api.arcee.ai/api/v1/chat/completions", "ARCEEAI_API_KEY"),
                ("gmi", "provider-model", "https://api.gmi-serving.com/v1/chat/completions", "GMI_API_KEY"),
                ("minimax", "MiniMax-M2.7", "https://api.minimax.io/v1/chat/completions", "MINIMAX_API_KEY"),
                ("zai", "glm-5.1", "https://api.z.ai/api/paas/v4/chat/completions", "GLM_API_KEY"),
                ("qwen", "qwen-plus", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions", "DASHSCOPE_API_KEY"),
                ("alibaba-coding-plan", "qwen3-coder-plus", "https://coding-intl.dashscope.aliyuncs.com/v1/chat/completions", "ALIBABA_CODING_PLAN_API_KEY"),
                ("stepfun", "step-3", "https://api.stepfun.ai/step_plan/v1/chat/completions", "STEPFUN_API_KEY"),
                ("huggingface", "Qwen/Qwen3-235B-A22B-Instruct-2507", "https://router.huggingface.co/v1/chat/completions", "HF_TOKEN"),
                ("nvidia", "nvidia/llama-3.1-nemotron-70b-instruct", "https://integrate.api.nvidia.com/v1/chat/completions", "NVIDIA_API_KEY"),
                ("ai-gateway", "gateway-model", "https://ai-gateway.vercel.sh/v1/chat/completions", "AI_GATEWAY_API_KEY"),
                ("opencode-zen", "zen-model", "https://opencode.ai/zen/v1/chat/completions", "OPENCODE_ZEN_API_KEY"),
                ("opencode-go", "go-model", "https://opencode.ai/zen/go/v1/chat/completions", "OPENCODE_GO_API_KEY"),
                ("kilocode", "kilo-model", "https://api.kilo.ai/api/gateway/chat/completions", "KILOCODE_API_KEY"),
                ("xiaomi", "mimo-vl-7b-rl", "https://api.xiaomimimo.com/v1/chat/completions", "XIAOMI_API_KEY"),
                ("tencent-tokenhub", "tokenhub-model", "https://tokenhub.tencentmaas.com/v1/chat/completions", "TOKENHUB_API_KEY"),
                ("ollama-cloud", "llama3.3", "https://ollama.com/v1/chat/completions", "OLLAMA_API_KEY"),
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

    def test_minimax_token_plan_uses_anthropic_compatible_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("minimax-token-plan", "sk-minimax-token-plan")
            route = registry.route("minimax-token-plan/MiniMax-M2.7-highspeed")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return b'{"content":[{"type":"text","text":"token plan response"}],"usage":{"input_tokens":11,"output_tokens":4}}'

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("sk-minimax-token-plan", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(
                    route,
                    [
                        {"role": "system", "content": "system policy"},
                        {"role": "user", "content": "hello"},
                    ],
                )

            self.assertEqual(captured["url"], "https://api.minimax.io/anthropic/v1/messages")
            self.assertEqual(captured["headers"]["X-api-key"], "sk-minimax-token-plan")
            self.assertEqual(captured["headers"]["Anthropic-version"], "2023-06-01")
            self.assertEqual(captured["payload"]["model"], "MiniMax-M2.7-highspeed")
            self.assertEqual(captured["payload"]["system"], "system policy")
            self.assertEqual(result.provider, "minimax-token-plan")
            self.assertEqual(result.content, "token plan response")
            self.assertEqual(result.input_tokens, 11)
            self.assertEqual(result.output_tokens, 4)
            self.assertEqual(result.raw_usage["bridge"], "minimax_anthropic_compatible")

    def test_minimax_china_uses_anthropic_compatible_api_key_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            registry.login_provider("minimax-cn", "sk-minimax-cn")
            route = registry.route("minimax-cn/MiniMax-M2.7")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return b'{"content":[{"type":"text","text":"minimax cn response"}],"usage":{"input_tokens":7,"output_tokens":3}}'

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("sk-minimax-cn", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured["url"], "https://api.minimaxi.com/anthropic/messages")
            self.assertEqual(captured["headers"]["X-api-key"], "sk-minimax-cn")
            self.assertEqual(captured["headers"]["Anthropic-version"], "2023-06-01")
            self.assertEqual(captured["payload"]["model"], "MiniMax-M2.7")
            self.assertEqual(result.provider, "minimax-cn")
            self.assertEqual(result.content, "minimax cn response")
            self.assertEqual(result.raw_usage["bridge"], "minimax_cn_anthropic_compatible")

    def test_minimax_oauth_live_client_uses_brokered_oauth_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            broker.store_secret(name="MINIMAX_OAUTH_ACCESS_TOKEN", value="mx-access-secret")
            broker.store_secret(name="MINIMAX_OAUTH_REFRESH_TOKEN", value="mx-refresh-secret")
            registry._remember_external_auth_link(  # noqa: SLF001 - test seeds verified external auth metadata.
                "minimax-oauth",
                "oauth",
                {
                    "target": "MiniMax OAuth",
                    "auth_source": "oauth_device_flow",
                    "aegis_bridge_status": "oauth_device_flow_ready",
                    "oauth_token_brokered": True,
                    "access_token_secret": "MINIMAX_OAUTH_ACCESS_TOKEN",
                    "refresh_token_secret": "MINIMAX_OAUTH_REFRESH_TOKEN",
                    "portal_base_url": "https://api.minimax.io",
                    "inference_base_url": "https://api.minimax.io/anthropic/v1",
                    "client_id": "78257093-7e40-4613-99e0-527b14b39113",
                    "scope": "group_id profile model.completion",
                    "token_type": "Bearer",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                    "expires_in": 3600,
                    "refresh_skew_seconds": 60,
                    "invocation_bridge": "minimax_oauth_anthropic_compatible",
                },
            )
            route = registry.route("minimax-oauth/MiniMax-M2.7")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return b'{"content":[{"type":"text","text":"oauth response"}],"usage":{"input_tokens":7,"output_tokens":3}}'

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("mx-access-secret", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(route.auth_method, "oauth_token")
            self.assertEqual(captured["url"], "https://api.minimax.io/anthropic/v1/messages")
            self.assertEqual(captured["headers"]["X-api-key"], "mx-access-secret")
            self.assertEqual(captured["headers"]["Anthropic-version"], "2023-06-01")
            self.assertEqual(captured["payload"]["model"], "MiniMax-M2.7")
            self.assertEqual(result.provider, "minimax-oauth")
            self.assertEqual(result.content, "oauth response")
            self.assertEqual(result.raw_usage["source"], "oauth_device_flow")
            self.assertEqual(result.raw_usage["bridge"], "minimax_oauth_anthropic_compatible")

    def test_nous_oauth_live_client_uses_brokered_agent_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            broker.store_secret(name="NOUS_OAUTH_ACCESS_TOKEN", value="nous-access-secret")
            broker.store_secret(name="NOUS_OAUTH_REFRESH_TOKEN", value="nous-refresh-secret")
            broker.store_secret(name="NOUS_OAUTH_AGENT_KEY", value="nous-agent-key-secret")
            registry._remember_external_auth_link(  # noqa: SLF001 - test seeds verified external auth metadata.
                "nous",
                "oauth",
                {
                    "target": "Nous Portal OAuth subscription",
                    "auth_source": "oauth_device_flow",
                    "aegis_bridge_status": "oauth_device_flow_ready",
                    "oauth_token_brokered": True,
                    "agent_key_brokered": True,
                    "access_token_secret": "NOUS_OAUTH_ACCESS_TOKEN",
                    "refresh_token_secret": "NOUS_OAUTH_REFRESH_TOKEN",
                    "agent_key_secret": "NOUS_OAUTH_AGENT_KEY",
                    "portal_base_url": "https://portal.nousresearch.com",
                    "inference_base_url": "https://inference-api.nousresearch.com/v1",
                    "client_id": "hermes-cli",
                    "scope": "inference:mint_agent_key",
                    "token_type": "Bearer",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                    "agent_key_expires_at": "2999-01-01T00:00:00+00:00",
                    "refresh_skew_seconds": 120,
                    "agent_key_min_ttl_seconds": 1800,
                    "invocation_bridge": "nous_oauth_agent_key",
                },
            )
            route = registry.route("nous/Hermes-4-405B")

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return b'{"choices":[{"message":{"content":"nous oauth response"}}],"usage":{"prompt_tokens":9,"completion_tokens":4}}'

            captured: dict[str, object] = {}

            def fake_urlopen(request, timeout):
                captured["url"] = request.full_url
                captured["headers"] = dict(request.header_items())
                captured["payload"] = json.loads(request.data.decode("utf-8"))
                self.assertNotIn("nous-access-secret", request.data.decode("utf-8"))
                self.assertNotIn("nous-agent-key-secret", request.data.decode("utf-8"))
                return FakeResponse()

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(route.auth_method, "oauth_token")
            self.assertEqual(captured["url"], "https://inference-api.nousresearch.com/v1/chat/completions")
            self.assertEqual(captured["headers"]["Authorization"], "Bearer nous-agent-key-secret")
            self.assertEqual(captured["payload"]["model"], "Hermes-4-405B")
            self.assertEqual(result.provider, "nous")
            self.assertEqual(result.content, "nous oauth response")
            self.assertEqual(result.raw_usage["source"], "oauth_device_flow")
            self.assertEqual(result.raw_usage["bridge"], "nous_oauth_agent_key")

    def test_nous_oauth_live_client_refreshes_and_mints_agent_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            broker.store_secret(name="NOUS_OAUTH_ACCESS_TOKEN", value="nous-old-access")
            broker.store_secret(name="NOUS_OAUTH_REFRESH_TOKEN", value="nous-refresh-secret")
            broker.store_secret(name="NOUS_OAUTH_AGENT_KEY", value="nous-old-agent-key")
            registry._remember_external_auth_link(  # noqa: SLF001 - test seeds verified external auth metadata.
                "nous",
                "oauth",
                {
                    "target": "Nous Portal OAuth subscription",
                    "auth_source": "oauth_device_flow",
                    "aegis_bridge_status": "oauth_device_flow_ready",
                    "oauth_token_brokered": True,
                    "agent_key_brokered": True,
                    "access_token_secret": "NOUS_OAUTH_ACCESS_TOKEN",
                    "refresh_token_secret": "NOUS_OAUTH_REFRESH_TOKEN",
                    "agent_key_secret": "NOUS_OAUTH_AGENT_KEY",
                    "portal_base_url": "https://portal.nousresearch.com",
                    "inference_base_url": "https://inference-api.nousresearch.com/v1",
                    "client_id": "hermes-cli",
                    "expires_at": "2000-01-01T00:00:00+00:00",
                    "agent_key_expires_at": "2000-01-01T00:00:00+00:00",
                    "refresh_skew_seconds": 120,
                    "agent_key_min_ttl_seconds": 1800,
                },
            )
            route = registry.route("nous/Hermes-4-405B")

            class FakeResponse:
                def __init__(self, payload: dict[str, object]) -> None:
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            captured: list[tuple[str, dict[str, str], str]] = []

            def fake_urlopen(request, timeout):
                body = request.data.decode("utf-8")
                headers = dict(request.header_items())
                captured.append((request.full_url, headers, body))
                if request.full_url.endswith("/api/oauth/token"):
                    return FakeResponse({"access_token": "nous-new-access", "refresh_token": "nous-new-refresh", "expires_in": 3600})
                if request.full_url.endswith("/api/oauth/agent-key"):
                    self.assertEqual(headers["Authorization"], "Bearer nous-new-access")
                    return FakeResponse({"api_key": "nous-new-agent-key", "expires_at": "2999-01-01T00:00:00+00:00", "expires_in": 86400})
                self.assertEqual(headers["Authorization"], "Bearer nous-new-agent-key")
                return FakeResponse({"choices": [{"message": {"content": "refreshed nous response"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured[0][0], "https://portal.nousresearch.com/api/oauth/token")
            self.assertIn("grant_type=refresh_token", captured[0][2])
            self.assertEqual(captured[0][1]["X-nous-refresh-token"], "nous-refresh-secret")
            self.assertEqual(captured[1][0], "https://portal.nousresearch.com/api/oauth/agent-key")
            self.assertEqual(captured[2][0], "https://inference-api.nousresearch.com/v1/chat/completions")
            self.assertEqual(broker.resolve_stored_secret("NOUS_OAUTH_ACCESS_TOKEN"), "nous-new-access")
            self.assertEqual(broker.resolve_stored_secret("NOUS_OAUTH_REFRESH_TOKEN"), "nous-new-refresh")
            self.assertEqual(broker.resolve_stored_secret("NOUS_OAUTH_AGENT_KEY"), "nous-new-agent-key")
            self.assertEqual(result.content, "refreshed nous response")

    def test_minimax_oauth_live_client_refreshes_expired_brokered_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            broker = SecretsBroker(root / ".aegis" / "secrets.json")
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(root / ".aegis" / "audit.jsonl"), broker)
            broker.store_secret(name="MINIMAX_OAUTH_ACCESS_TOKEN", value="mx-old-access")
            broker.store_secret(name="MINIMAX_OAUTH_REFRESH_TOKEN", value="mx-refresh-secret")
            registry._remember_external_auth_link(  # noqa: SLF001 - test seeds verified external auth metadata.
                "minimax-oauth",
                "oauth",
                {
                    "target": "MiniMax OAuth",
                    "auth_source": "oauth_device_flow",
                    "aegis_bridge_status": "oauth_device_flow_ready",
                    "oauth_token_brokered": True,
                    "access_token_secret": "MINIMAX_OAUTH_ACCESS_TOKEN",
                    "refresh_token_secret": "MINIMAX_OAUTH_REFRESH_TOKEN",
                    "portal_base_url": "https://api.minimax.io",
                    "inference_base_url": "https://api.minimax.io/anthropic/v1",
                    "client_id": "78257093-7e40-4613-99e0-527b14b39113",
                    "expires_at": "2000-01-01T00:00:00+00:00",
                    "refresh_skew_seconds": 60,
                },
            )
            route = registry.route("minimax-oauth/MiniMax-M2.7")

            class FakeResponse:
                def __init__(self, payload: dict[str, object]) -> None:
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            captured: list[tuple[str, dict[str, str], str]] = []

            def fake_urlopen(request, timeout):
                body = request.data.decode("utf-8")
                headers = dict(request.header_items())
                captured.append((request.full_url, headers, body))
                if request.full_url.endswith("/oauth/token"):
                    return FakeResponse({"status": "success", "access_token": "mx-new-access", "refresh_token": "mx-new-refresh"})
                self.assertEqual(headers["X-api-key"], "mx-new-access")
                return FakeResponse({"content": [{"type": "text", "text": "refreshed response"}], "usage": {"input_tokens": 1, "output_tokens": 1}})

            with patch("aegis.models.client._open_model_request", fake_urlopen):
                result = LiveModelClient(broker).chat(route, [{"role": "user", "content": "hello"}])

            self.assertEqual(captured[0][0], "https://api.minimax.io/oauth/token")
            self.assertIn("refresh_token=mx-refresh-secret", captured[0][2])
            self.assertEqual(broker.resolve_stored_secret("MINIMAX_OAUTH_ACCESS_TOKEN"), "mx-new-access")
            self.assertEqual(broker.resolve_stored_secret("MINIMAX_OAUTH_REFRESH_TOKEN"), "mx-new-refresh")
            self.assertEqual(result.content, "refreshed response")

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
