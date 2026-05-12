"""Minimal live model client for OpenAI-compatible providers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aegis.models.registry import (
    GITHUB_COPILOT_OAUTH_TOKEN_SECRET,
    ModelRoute,
    NOUS_OAUTH_ACCESS_TOKEN_SECRET,
    NOUS_OAUTH_AGENT_KEY_MIN_TTL_SECONDS,
    NOUS_OAUTH_AGENT_KEY_SECRET,
    NOUS_OAUTH_CLIENT_ID,
    NOUS_OAUTH_PORTAL_BASE_URL,
    NOUS_OAUTH_REFRESH_SKEW_SECONDS,
    NOUS_OAUTH_REFRESH_TOKEN_SECRET,
)
from aegis.security.secrets_broker import SecretsBroker


@dataclass(frozen=True)
class ModelInvocationResult:
    provider: str
    model: str
    content: str
    input_tokens: int
    output_tokens: int
    raw_usage: dict[str, Any]


OPENAI_COMPATIBLE_PROVIDERS = {
    "openai",
    "openrouter",
    "mistral",
    "lmstudio",
    "custom",
    "nous",
    "deepseek",
    "xai",
    "kimi",
    "kimi-cn",
    "arcee",
    "gmi",
    "minimax",
    "zai",
    "qwen",
    "alibaba-coding-plan",
    "stepfun",
    "huggingface",
    "nvidia",
    "ai-gateway",
    "opencode-zen",
    "opencode-go",
    "kilocode",
    "xiaomi",
    "tencent-tokenhub",
    "ollama-cloud",
}


COPILOT_DENIED_TOOLS = (
    "bash",
    "powershell",
    "list_bash",
    "list_powershell",
    "read_bash",
    "read_powershell",
    "stop_bash",
    "stop_powershell",
    "write_bash",
    "write_powershell",
    "apply_patch",
    "create",
    "edit",
    "view",
    "list_agents",
    "read_agent",
    "task",
    "ask_user",
    "glob",
    "grep",
    "skill",
    "web_fetch",
)


class LiveModelClient:
    """Invokes configured live providers without exposing raw secrets to callers."""

    def __init__(self, secrets_broker: SecretsBroker, *, timeout_seconds: float = 60.0) -> None:
        self.secrets_broker = secrets_broker
        self.timeout_seconds = timeout_seconds

    def chat(self, route: ModelRoute, messages: list[dict[str, str]], *, temperature: float = 0.2) -> ModelInvocationResult:
        if route.auth_method == "subscription_cli":
            return self._chat_subscription_cli(route, messages, temperature=temperature)
        if route.provider.provider == "aws-bedrock":
            return self._chat_aws_bedrock_cli(route, messages, temperature=temperature)
        if route.provider.provider == "azure-foundry":
            return self._chat_azure_foundry(route, messages, temperature=temperature)
        if route.provider.provider == "github-copilot":
            if route.auth_method == "oauth_token":
                return self._chat_github_copilot_oauth(route, messages, temperature=temperature)
            return self._chat_github_copilot_cli(route, messages, temperature=temperature)
        if route.provider.provider == "minimax-oauth":
            return self._chat_minimax_oauth(route, messages, temperature=temperature)
        if route.provider.provider == "minimax-token-plan":
            return self._chat_minimax_token_plan(route, messages, temperature=temperature)
        if route.provider.metadata.get("compatibility") == "anthropic_messages":
            return self._chat_anthropic_compatible_api_key(route, messages, temperature=temperature)
        if route.provider.provider in OPENAI_COMPATIBLE_PROVIDERS:
            return self._chat_openai_compatible(route, messages, temperature=temperature)
        if route.provider.provider == "anthropic":
            return self._chat_anthropic(route, messages, temperature=temperature)
        if route.provider.provider == "cohere":
            return self._chat_cohere(route, messages, temperature=temperature)
        if route.provider.provider == "google":
            return self._chat_google(route, messages, temperature=temperature)
        if route.provider.provider == "ollama":
            return self._chat_ollama(route, messages, temperature=temperature)
        raise ValueError(f"live invocation is not implemented for provider {route.provider.provider!r}")

    def _chat_subscription_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.provider.provider == "openai":
            return self._chat_codex_subscription_cli(route, messages, temperature=temperature)
        if route.provider.provider == "anthropic":
            return self._chat_claude_subscription_cli(route, messages, temperature=temperature)
        if route.provider.provider == "qwen":
            return self._chat_qwen_subscription_cli(route, messages, temperature=temperature)
        if route.provider.provider == "google":
            return self._chat_gemini_subscription_cli(route, messages, temperature=temperature)
        raise ValueError(f"subscription CLI invocation is not implemented for provider {route.provider.provider!r}")

    def _chat_codex_subscription_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        executable_path = shutil.which("codex")
        if executable_path is None:
            raise RuntimeError("official Codex CLI is not installed")
        prompt = _subscription_cli_prompt(messages, provider="codex", temperature=temperature)
        with tempfile.TemporaryDirectory(prefix="aegis-codex-model-") as temp:
            temp_dir = Path(temp)
            output_path = temp_dir / "last-message.txt"
            command = (
                executable_path,
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "--ignore-rules",
                "--sandbox",
                "read-only",
                "--ask-for-approval",
                "never",
                "-m",
                route.model,
                "--output-last-message",
                str(output_path),
                "-",
            )
            try:
                completed = subprocess.run(
                    command,
                    input=prompt,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    cwd=temp_dir,
                )  # noqa: S603 - argv is a fixed official provider CLI bridge.
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("official Codex CLI model invocation timed out") from exc
            except OSError as exc:
                raise RuntimeError(f"official Codex CLI model invocation failed: {exc}") from exc
            if completed.returncode != 0:
                raise RuntimeError(f"official Codex CLI model invocation exited with {completed.returncode}")
            content = output_path.read_text(encoding="utf-8").strip() if output_path.exists() else completed.stdout.strip()
        if not content:
            raise RuntimeError("official Codex CLI model invocation returned no final message")
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=max(1, len(prompt) // 4),
            output_tokens=max(1, len(content) // 4),
            raw_usage={"source": "subscription_cli", "bridge": "codex_exec", "token_counts": "estimated"},
        )

    def _chat_claude_subscription_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        executable_path = shutil.which("claude")
        if executable_path is None:
            raise RuntimeError("official Claude Code CLI is not installed")
        prompt = _subscription_cli_prompt(messages, provider="claude", temperature=temperature)
        with tempfile.TemporaryDirectory(prefix="aegis-claude-model-") as temp:
            temp_dir = Path(temp)
            command = (
                executable_path,
                "-p",
                "--output-format",
                "text",
                "--max-turns",
                "1",
                "--permission-mode",
                "plan",
                "--model",
                _claude_cli_model(route.model),
                prompt,
            )
            try:
                completed = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    cwd=temp_dir,
                )  # noqa: S603 - argv is a fixed official provider CLI bridge.
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("official Claude Code CLI model invocation timed out") from exc
            except OSError as exc:
                raise RuntimeError(f"official Claude Code CLI model invocation failed: {exc}") from exc
            if completed.returncode != 0:
                raise RuntimeError(f"official Claude Code CLI model invocation exited with {completed.returncode}")
            content = completed.stdout.strip()
        if not content:
            raise RuntimeError("official Claude Code CLI model invocation returned no final message")
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=max(1, len(prompt) // 4),
            output_tokens=max(1, len(content) // 4),
            raw_usage={"source": "subscription_cli", "bridge": "claude_print", "token_counts": "estimated"},
        )

    def _chat_qwen_subscription_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        executable_path = shutil.which("qwen")
        if executable_path is None:
            raise RuntimeError("official Qwen Code CLI is not installed")
        prompt = _subscription_cli_prompt(messages, provider="qwen", temperature=temperature)
        with tempfile.TemporaryDirectory(prefix="aegis-qwen-model-") as temp:
            temp_dir = Path(temp)
            command = (
                executable_path,
                "--output-format",
                "json",
                "--approval-mode",
                "plan",
                "--model",
                route.model,
            )
            try:
                completed = subprocess.run(
                    command,
                    input=prompt,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    cwd=temp_dir,
                )  # noqa: S603 - argv is a fixed official provider CLI bridge.
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("official Qwen Code CLI model invocation timed out") from exc
            except OSError as exc:
                raise RuntimeError(f"official Qwen Code CLI model invocation failed: {exc}") from exc
            if completed.returncode != 0:
                raise RuntimeError(f"official Qwen Code CLI model invocation exited with {completed.returncode}")
            content = _qwen_json_result_text(completed.stdout)
        if not content:
            raise RuntimeError("official Qwen Code CLI model invocation returned no final message")
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=max(1, len(prompt) // 4),
            output_tokens=max(1, len(content) // 4),
            raw_usage={"source": "subscription_cli", "bridge": "qwen_headless_json", "token_counts": "estimated"},
        )

    def _chat_gemini_subscription_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        executable_path = shutil.which("gemini")
        if executable_path is None:
            raise RuntimeError("official Gemini CLI is not installed")
        prompt = _subscription_cli_prompt(messages, provider="gemini", temperature=temperature)
        with tempfile.TemporaryDirectory(prefix="aegis-gemini-model-") as temp:
            temp_dir = Path(temp)
            command = (
                executable_path,
                "-p",
                prompt,
                "--output-format=json",
                "--approval-mode=plan",
                "--sandbox",
                "--skip-trust",
                f"--model={_gemini_cli_model(route.model)}",
            )
            try:
                completed = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    cwd=temp_dir,
                )  # noqa: S603 - argv is a fixed official provider CLI bridge.
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("official Gemini CLI model invocation timed out") from exc
            except OSError as exc:
                raise RuntimeError(f"official Gemini CLI model invocation failed: {exc}") from exc
        if completed.returncode != 0:
            raise RuntimeError(f"official Gemini CLI model invocation exited with {completed.returncode}")
        content, usage = _gemini_json_result(completed.stdout)
        if not content:
            raise RuntimeError("official Gemini CLI model invocation returned no final message")
        raw_usage = dict(usage)
        raw_usage.update({"source": "subscription_cli", "bridge": "gemini_prompt_json", "token_counts": "estimated"})
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=max(1, len(prompt) // 4),
            output_tokens=max(1, len(content) // 4),
            raw_usage=raw_usage,
        )

    def _chat_github_copilot_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.auth_method != "oauth_device_cli":
            raise ValueError("github-copilot provider requires verified Copilot CLI login")
        executable_path = shutil.which("copilot")
        if executable_path is None:
            raise RuntimeError("official GitHub Copilot CLI is not installed")
        prompt = _subscription_cli_prompt(messages, provider="github-copilot", temperature=temperature)
        with tempfile.TemporaryDirectory(prefix="aegis-copilot-model-") as temp:
            temp_dir = Path(temp)
            command = _copilot_prompt_command(executable_path, prompt=prompt, model=route.model)
            try:
                completed = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    cwd=temp_dir,
                    env=_copilot_safe_env(),
                )  # noqa: S603 - argv is a fixed official provider CLI bridge.
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("official GitHub Copilot CLI model invocation timed out") from exc
            except OSError as exc:
                raise RuntimeError(f"official GitHub Copilot CLI model invocation failed: {exc}") from exc
        if completed.returncode != 0:
            raise RuntimeError(f"official GitHub Copilot CLI model invocation exited with {completed.returncode}")
        content = _copilot_jsonl_result_text(completed.stdout)
        if not content:
            raise RuntimeError("official GitHub Copilot CLI model invocation returned no final message")
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=max(1, len(prompt) // 4),
            output_tokens=max(1, len(content) // 4),
            raw_usage={"source": "official_cli", "bridge": "copilot_prompt_json", "token_counts": "estimated"},
        )

    def _chat_github_copilot_oauth(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        raw_token = self._resolve_github_copilot_oauth_token(route)
        api_token = self._exchange_github_copilot_token(raw_token)
        response = self._post_json(
            "https://api.githubcopilot.com/chat/completions",
            payload={
                "model": route.model,
                "messages": messages,
                "stream": False,
                "temperature": temperature,
            },
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Editor-Version": "vscode/1.104.1",
                "Copilot-Integration-Id": "vscode-chat",
                "Openai-Intent": "conversation-panel",
                "User-Agent": "GitHubCopilotChat/0.26.7",
                "x-initiator": "user",
            },
        )
        choices = response.get("choices", [])
        if not choices:
            raise RuntimeError("github-copilot provider returned no choices")
        message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
        content = str(message.get("content", "")).strip()
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        raw_usage = dict(usage)
        raw_usage.update({"source": "oauth_device_flow", "bridge": "copilot_oauth_chat_completions"})
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            raw_usage=raw_usage,
        )

    def _chat_aws_bedrock_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.auth_method != "cloud_identity_cli":
            raise ValueError("aws-bedrock provider requires verified cloud identity login")
        executable_path = shutil.which("aws")
        if executable_path is None:
            raise RuntimeError("official AWS CLI is not installed")
        system, bedrock_messages = _bedrock_messages(messages)
        inference_config = {"maxTokens": 4096, "temperature": temperature}
        command = [
            executable_path,
            "bedrock-runtime",
            "converse",
            "--model-id",
            route.model,
            "--messages",
            json.dumps(bedrock_messages, separators=(",", ":")),
            "--inference-config",
            json.dumps(inference_config, separators=(",", ":")),
            "--output",
            "json",
            "--no-cli-pager",
        ]
        if system:
            command.extend(["--system", json.dumps(system, separators=(",", ":"))])
        with tempfile.TemporaryDirectory(prefix="aegis-bedrock-model-") as temp:
            try:
                completed = subprocess.run(
                    tuple(command),
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    cwd=Path(temp),
                )  # noqa: S603 - argv is a fixed official provider CLI bridge.
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("official AWS CLI Bedrock invocation timed out") from exc
            except OSError as exc:
                raise RuntimeError(f"official AWS CLI Bedrock invocation failed: {exc}") from exc
        if completed.returncode != 0:
            raise RuntimeError(f"official AWS CLI Bedrock invocation exited with {completed.returncode}")
        if not completed.stdout.strip():
            raise RuntimeError("official AWS CLI Bedrock invocation returned no response")
        response = json.loads(completed.stdout)
        if not isinstance(response, dict):
            raise RuntimeError("official AWS CLI Bedrock invocation returned invalid JSON")
        output = response.get("output", {}) if isinstance(response.get("output", {}), dict) else {}
        message = output.get("message", {}) if isinstance(output.get("message", {}), dict) else {}
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        raw_usage = dict(usage)
        raw_usage.update({"source": "official_cli", "bridge": "aws_bedrock_runtime_converse"})
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=_bedrock_content_text(message.get("content", [])),
            input_tokens=int(usage.get("inputTokens", 0) or 0),
            output_tokens=int(usage.get("outputTokens", 0) or 0),
            raw_usage=raw_usage,
        )

    def _chat_openai_compatible(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.provider.base_url is None:
            raise ValueError(f"provider {route.provider.provider!r} has no base URL")
        if route.provider.provider == "custom":
            _validate_custom_base_url(route.provider.base_url)
        if route.provider.provider == "nous" and route.auth_method == "oauth_token":
            api_key = self._resolve_nous_oauth_agent_key(route)
        else:
            api_key = self._resolve_api_key(route)
        payload = {
            "model": route.model,
            "messages": messages,
            "temperature": temperature,
        }
        response = self._post_openai_compatible(
            f"{route.provider.base_url}/chat/completions",
            api_key=api_key,
            payload=payload,
        )
        choices = response.get("choices", [])
        if not choices:
            raise RuntimeError("model provider returned no choices")
        message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
        content = str(message.get("content", "")).strip()
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        raw_usage = dict(usage)
        if route.provider.provider == "nous" and route.auth_method == "oauth_token":
            raw_usage.update({"source": "oauth_device_flow", "bridge": "nous_oauth_agent_key"})
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            raw_usage=raw_usage,
        )

    def _chat_azure_foundry(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.auth_method == "cloud_identity_cli":
            return self._chat_azure_foundry_az_cli(route, messages, temperature=temperature)
        if route.provider.base_url is None:
            raise ValueError("azure-foundry provider requires models.azure_foundry_base_url")
        _validate_azure_foundry_base_url(route.provider.base_url)
        api_key = self._resolve_api_key(route)
        if api_key is None:
            raise ValueError("azure-foundry provider requires an API key or verified cloud identity login")
        response = self._post_json(
            f"{route.provider.base_url.rstrip('/')}/chat/completions",
            payload={
                "model": route.model,
                "messages": messages,
                "temperature": temperature,
            },
            headers={
                "Content-Type": "application/json",
                "api-key": api_key,
            },
        )
        choices = response.get("choices", [])
        if not choices:
            raise RuntimeError("azure-foundry provider returned no choices")
        message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
        content = str(message.get("content", "")).strip()
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            raw_usage=dict(usage),
        )

    def _chat_azure_foundry_az_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.provider.base_url is None:
            raise ValueError("azure-foundry provider requires models.azure_foundry_base_url")
        _validate_azure_foundry_base_url(route.provider.base_url)
        executable_path = shutil.which("az")
        if executable_path is None:
            raise RuntimeError("official Azure CLI is not installed")
        payload = {
            "model": route.model,
            "messages": messages,
            "temperature": temperature,
        }
        command = (
            executable_path,
            "rest",
            "--method",
            "post",
            "--url",
            f"{route.provider.base_url.rstrip('/')}/chat/completions",
            "--resource",
            "https://ai.azure.com",
            "--body",
            json.dumps(payload, separators=(",", ":")),
            "--output",
            "json",
        )
        with tempfile.TemporaryDirectory(prefix="aegis-azure-model-") as temp:
            try:
                completed = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    cwd=Path(temp),
                )  # noqa: S603 - argv is a fixed official provider CLI bridge.
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("official Azure CLI model invocation timed out") from exc
            except OSError as exc:
                raise RuntimeError(f"official Azure CLI model invocation failed: {exc}") from exc
        if completed.returncode != 0:
            raise RuntimeError(f"official Azure CLI model invocation exited with {completed.returncode}")
        if not completed.stdout.strip():
            raise RuntimeError("official Azure CLI model invocation returned no response")
        response = json.loads(completed.stdout)
        if not isinstance(response, dict):
            raise RuntimeError("official Azure CLI model invocation returned invalid JSON")
        choices = response.get("choices", [])
        if not choices:
            raise RuntimeError("azure-foundry provider returned no choices")
        message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
        content = str(message.get("content", "")).strip()
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        raw_usage = dict(usage)
        raw_usage.update({"source": "official_cli", "bridge": "az_rest"})
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            raw_usage=raw_usage,
        )

    def _chat_anthropic(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.provider.base_url is None:
            raise ValueError("anthropic provider has no base URL")
        api_key = self._resolve_api_key(route)
        if api_key is None:
            raise ValueError("anthropic provider has no API key")
        system, anthropic_messages = _anthropic_messages(messages)
        payload: dict[str, Any] = {
            "model": route.model,
            "messages": anthropic_messages,
            "max_tokens": 4096,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        response = self._post_json(
            f"{route.provider.base_url}/messages",
            payload=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        content = _anthropic_text(response.get("content", []))
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("input_tokens", 0) or 0),
            output_tokens=int(usage.get("output_tokens", 0) or 0),
            raw_usage=dict(usage),
        )

    def _chat_minimax_token_plan(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.provider.base_url is None:
            raise ValueError("minimax-token-plan provider has no base URL")
        api_key = self._resolve_api_key(route)
        if api_key is None:
            raise ValueError("minimax-token-plan provider requires a Token Plan API key")
        system, anthropic_messages = _anthropic_messages(messages)
        payload: dict[str, Any] = {
            "model": route.model,
            "messages": anthropic_messages,
            "max_tokens": 4096,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        response = self._post_json(
            f"{route.provider.base_url}/messages",
            payload=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        content = _anthropic_text(response.get("content", []))
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        raw_usage = dict(usage)
        raw_usage.update({"source": "token_plan_api_key", "bridge": "minimax_anthropic_compatible"})
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("input_tokens", 0) or 0),
            output_tokens=int(usage.get("output_tokens", 0) or 0),
            raw_usage=raw_usage,
        )

    def _chat_minimax_oauth(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.auth_method != "oauth_token":
            raise ValueError("minimax-oauth provider requires verified MiniMax OAuth login")
        if route.provider.base_url is None:
            raise ValueError("minimax-oauth provider has no base URL")
        access_token = self._resolve_minimax_oauth_access_token(route)
        system, anthropic_messages = _anthropic_messages(messages)
        payload: dict[str, Any] = {
            "model": route.model,
            "messages": anthropic_messages,
            "max_tokens": 4096,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        response = self._post_json(
            f"{route.provider.base_url}/messages",
            payload=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": access_token,
                "anthropic-version": "2023-06-01",
            },
        )
        content = _anthropic_text(response.get("content", []))
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        raw_usage = dict(usage)
        raw_usage.update({"source": "oauth_device_flow", "bridge": "minimax_oauth_anthropic_compatible"})
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("input_tokens", 0) or 0),
            output_tokens=int(usage.get("output_tokens", 0) or 0),
            raw_usage=raw_usage,
        )

    def _chat_anthropic_compatible_api_key(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.provider.base_url is None:
            raise ValueError(f"{route.provider.provider} provider has no base URL")
        api_key = self._resolve_api_key(route)
        if api_key is None:
            raise ValueError(f"{route.provider.provider} provider requires an API key")
        system, anthropic_messages = _anthropic_messages(messages)
        payload: dict[str, Any] = {
            "model": route.model,
            "messages": anthropic_messages,
            "max_tokens": 4096,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        response = self._post_json(
            f"{route.provider.base_url}/messages",
            payload=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        content = _anthropic_text(response.get("content", []))
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        raw_usage = dict(usage)
        raw_usage.update(
            {
                "source": "api_key",
                "bridge": str(route.provider.metadata.get("invocation_bridge") or "anthropic_compatible"),
            }
        )
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("input_tokens", 0) or 0),
            output_tokens=int(usage.get("output_tokens", 0) or 0),
            raw_usage=raw_usage,
        )

    def _chat_cohere(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.provider.base_url is None:
            raise ValueError("cohere provider has no base URL")
        api_key = self._resolve_api_key(route)
        if api_key is None:
            raise ValueError("cohere provider has no API key")
        response = self._post_json(
            f"{route.provider.base_url}/chat",
            payload={
                "model": route.model,
                "messages": messages,
                "stream": False,
                "temperature": temperature,
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "X-Client-Name": "Aegis Agent",
            },
        )
        message = response.get("message", {}) if isinstance(response.get("message", {}), dict) else {}
        content = _content_blocks_text(message.get("content", []))
        usage = response.get("usage", {}) if isinstance(response.get("usage", {}), dict) else {}
        tokens = usage.get("tokens", {}) if isinstance(usage.get("tokens", {}), dict) else {}
        billed = usage.get("billed_units", {}) if isinstance(usage.get("billed_units", {}), dict) else {}
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(tokens.get("input_tokens", billed.get("input_tokens", 0)) or 0),
            output_tokens=int(tokens.get("output_tokens", billed.get("output_tokens", 0)) or 0),
            raw_usage=dict(usage),
        )

    def _chat_google(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.auth_method == "cloud_identity_cli":
            return self._chat_google_vertex_cli(route, messages, temperature=temperature)
        if route.provider.base_url is None:
            raise ValueError("google provider has no base URL")
        api_key = self._resolve_api_key(route)
        if api_key is None:
            raise ValueError("google provider has no API key")
        system, contents = _google_messages(messages)
        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature},
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        response = self._post_json(
            f"{route.provider.base_url}/models/{route.model}:generateContent",
            payload=payload,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
        )
        candidates = response.get("candidates", [])
        first = candidates[0] if candidates and isinstance(candidates[0], dict) else {}
        content = first.get("content", {}) if isinstance(first.get("content", {}), dict) else {}
        usage = response.get("usageMetadata", {}) if isinstance(response.get("usageMetadata", {}), dict) else {}
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=_google_parts_text(content.get("parts", [])),
            input_tokens=int(usage.get("promptTokenCount", 0) or 0),
            output_tokens=int(usage.get("candidatesTokenCount", 0) or 0),
            raw_usage=dict(usage),
        )

    def _chat_google_vertex_cli(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        project = str(route.provider.metadata.get("vertex_project") or "").strip()
        location = str(route.provider.metadata.get("vertex_location") or "").strip()
        if not project:
            raise ValueError("google provider requires models.google_vertex_project for cloud identity")
        if not location:
            raise ValueError("google provider requires models.google_vertex_location for cloud identity")
        bash_path = shutil.which("bash")
        gcloud_path = shutil.which("gcloud")
        curl_path = shutil.which("curl")
        missing = [name for name, path in (("bash", bash_path), ("gcloud", gcloud_path), ("curl", curl_path)) if path is None]
        if missing:
            raise RuntimeError(f"google Vertex cloud identity bridge requires installed executables: {', '.join(missing)}")
        system, contents = _google_messages(messages)
        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature},
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        url = _google_vertex_generate_content_url(project=project, location=location, model=route.model)
        script = (
            "set -euo pipefail\n"
            'token="$("$3" auth print-access-token)"\n'
            "printf 'header = \"Content-Type: application/json\"\\nheader = \"Authorization: Bearer %s\"\\n' \"$token\" "
            '| "$4" --silent --show-error --fail-with-body --config - --request POST --data-binary @"$1" "$2"\n'
        )
        with tempfile.TemporaryDirectory(prefix="aegis-google-vertex-model-") as temp:
            temp_dir = Path(temp)
            payload_path = temp_dir / "request.json"
            payload_path.write_text(json.dumps(payload), encoding="utf-8")
            try:
                completed = subprocess.run(
                    (bash_path, "-lc", script, "aegis-google-vertex", str(payload_path), url, gcloud_path, curl_path),
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    cwd=temp_dir,
                )  # noqa: S603 - argv is fixed; token is kept inside the child shell/curl pipeline.
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("official gcloud Vertex invocation timed out") from exc
            except OSError as exc:
                raise RuntimeError(f"official gcloud Vertex invocation failed: {exc}") from exc
        if completed.returncode != 0:
            raise RuntimeError(f"official gcloud Vertex invocation exited with {completed.returncode}")
        if not completed.stdout.strip():
            raise RuntimeError("official gcloud Vertex invocation returned no response")
        response = json.loads(completed.stdout)
        if not isinstance(response, dict):
            raise RuntimeError("official gcloud Vertex invocation returned invalid JSON")
        candidates = response.get("candidates", [])
        first = candidates[0] if candidates and isinstance(candidates[0], dict) else {}
        content = first.get("content", {}) if isinstance(first.get("content", {}), dict) else {}
        usage = response.get("usageMetadata", {}) if isinstance(response.get("usageMetadata", {}), dict) else {}
        raw_usage = dict(usage)
        raw_usage.update({"source": "official_cli", "bridge": "gcloud_vertex_rest"})
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=_google_parts_text(content.get("parts", [])),
            input_tokens=int(usage.get("promptTokenCount", 0) or 0),
            output_tokens=int(usage.get("candidatesTokenCount", 0) or 0),
            raw_usage=raw_usage,
        )

    def _chat_ollama(
        self,
        route: ModelRoute,
        messages: list[dict[str, str]],
        *,
        temperature: float,
    ) -> ModelInvocationResult:
        if route.provider.base_url is None:
            raise ValueError("ollama provider has no base URL")
        response = self._post_json(
            f"{route.provider.base_url}/api/chat",
            payload={
                "model": route.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature},
            },
            headers={"Content-Type": "application/json"},
        )
        message = response.get("message", {}) if isinstance(response.get("message", {}), dict) else {}
        usage = {
            "prompt_tokens": int(response.get("prompt_eval_count", 0) or 0),
            "completion_tokens": int(response.get("eval_count", 0) or 0),
        }
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=str(message.get("content", "")).strip(),
            input_tokens=usage["prompt_tokens"],
            output_tokens=usage["completion_tokens"],
            raw_usage={**usage, **{key: value for key, value in response.items() if key.endswith("_count")}},
        )

    def _resolve_api_key(self, route: ModelRoute) -> str | None:
        if route.provider.auth_secret is None:
            return None
        handle = self.secrets_broker.request_handle(
            name=route.provider.auth_secret,
            requester=f"model:{route.provider.provider}",
            reason="live model provider API call",
            scopes=("model.invoke",),
        )
        return self.secrets_broker.resolve_for_authorized_tool(handle, requester=f"model:{route.provider.provider}")

    def _resolve_nous_oauth_agent_key(self, route: ModelRoute) -> str:
        metadata = {**route.provider.metadata, **route.auth_metadata}
        access_secret = str(metadata.get("access_token_secret") or NOUS_OAUTH_ACCESS_TOKEN_SECRET)
        refresh_secret = str(metadata.get("refresh_token_secret") or NOUS_OAUTH_REFRESH_TOKEN_SECRET)
        agent_key_secret = str(metadata.get("agent_key_secret") or NOUS_OAUTH_AGENT_KEY_SECRET)
        min_ttl = int(metadata.get("agent_key_min_ttl_seconds") or NOUS_OAUTH_AGENT_KEY_MIN_TTL_SECONDS)
        if not _oauth_expires_soon(str(metadata.get("agent_key_expires_at") or ""), min_ttl):
            try:
                return self.secrets_broker.resolve_stored_secret(agent_key_secret)
            except KeyError:
                pass

        portal_base_url = str(metadata.get("portal_base_url") or NOUS_OAUTH_PORTAL_BASE_URL).rstrip("/")
        client_id = str(metadata.get("client_id") or NOUS_OAUTH_CLIENT_ID)
        access_token = self.secrets_broker.resolve_stored_secret(access_secret)
        if _oauth_expires_soon(str(metadata.get("expires_at") or ""), int(metadata.get("refresh_skew_seconds") or NOUS_OAUTH_REFRESH_SKEW_SECONDS)):
            refresh_token = self.secrets_broker.resolve_stored_secret(refresh_secret)
            refreshed = self._post_form(
                f"{portal_base_url}/api/oauth/token",
                {
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                },
                headers={"x-nous-refresh-token": refresh_token},
            )
            access_token = str(refreshed.get("access_token") or "").strip()
            if not access_token:
                raise RuntimeError("Nous OAuth refresh response did not include access_token")
            self.secrets_broker.store_secret(name=access_secret, value=access_token)
            rotated_refresh = str(refreshed.get("refresh_token") or "").strip()
            if rotated_refresh:
                self.secrets_broker.store_secret(name=refresh_secret, value=rotated_refresh)
            route.auth_metadata["expires_at"] = _expires_at_from_ttl(refreshed.get("expires_in"))

        minted = self._post_json(
            f"{portal_base_url}/api/oauth/agent-key",
            payload={"min_ttl_seconds": max(60, min_ttl)},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )
        agent_key = str(minted.get("api_key") or "").strip()
        if not agent_key:
            raise RuntimeError("Nous OAuth agent-key response did not include api_key")
        self.secrets_broker.store_secret(name=agent_key_secret, value=agent_key)
        route.auth_metadata["agent_key_expires_at"] = str(minted.get("expires_at") or _expires_at_from_ttl(minted.get("expires_in"))).strip()
        route.auth_metadata["agent_key_expires_in"] = minted.get("expires_in")
        return agent_key

    def _resolve_minimax_oauth_access_token(self, route: ModelRoute) -> str:
        metadata = {**route.provider.metadata, **route.auth_metadata}
        access_secret = str(metadata.get("access_token_secret") or "MINIMAX_OAUTH_ACCESS_TOKEN")
        refresh_secret = str(metadata.get("refresh_token_secret") or "MINIMAX_OAUTH_REFRESH_TOKEN")
        if not _oauth_expires_soon(str(metadata.get("expires_at") or ""), int(metadata.get("refresh_skew_seconds") or 60)):
            return self.secrets_broker.resolve_stored_secret(access_secret)
        refresh_token = self.secrets_broker.resolve_stored_secret(refresh_secret)
        portal_base_url = str(metadata.get("portal_base_url") or "https://api.minimax.io").rstrip("/")
        client_id = str(metadata.get("client_id") or "78257093-7e40-4613-99e0-527b14b39113")
        payload = self._post_form(
            f"{portal_base_url}/oauth/token",
            {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
        )
        if payload.get("status") != "success":
            raise RuntimeError("MiniMax OAuth refresh did not return success")
        access_token = str(payload.get("access_token") or "").strip()
        if not access_token:
            raise RuntimeError("MiniMax OAuth refresh response did not include access_token")
        self.secrets_broker.store_secret(name=access_secret, value=access_token)
        rotated_refresh = str(payload.get("refresh_token") or "").strip()
        if rotated_refresh:
            self.secrets_broker.store_secret(name=refresh_secret, value=rotated_refresh)
        return access_token

    def _resolve_github_copilot_oauth_token(self, route: ModelRoute) -> str:
        metadata = {**route.provider.metadata, **route.auth_metadata}
        access_secret = str(metadata.get("access_token_secret") or GITHUB_COPILOT_OAUTH_TOKEN_SECRET)
        return self.secrets_broker.resolve_stored_secret(access_secret)

    def _exchange_github_copilot_token(self, raw_token: str) -> str:
        token = raw_token.strip()
        if not token:
            raise ValueError("github-copilot provider requires a brokered OAuth token")
        if token.startswith("ghp_"):
            raise ValueError("github-copilot provider does not support classic GitHub personal access tokens")
        request = Request(
            "https://api.github.com/copilot_internal/v2/token",
            method="GET",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/json",
                "User-Agent": "GitHubCopilotChat/0.26.7",
                "Editor-Version": "vscode/1.104.1",
            },
        )
        try:
            with _open_model_request(request, timeout=self.timeout_seconds) as response:  # noqa: S310 - fixed GitHub Copilot token endpoint.
                raw = response.read().decode("utf-8")
            decoded = json.loads(raw)
        except (HTTPError, URLError, OSError, json.JSONDecodeError):
            return token
        if not isinstance(decoded, dict):
            return token
        api_token = str(decoded.get("token") or "").strip()
        return api_token or token

    def _post_openai_compatible(self, url: str, *, api_key: str | None, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
        }
        if api_key is not None:
            headers["Authorization"] = f"Bearer {api_key}"
        if "openrouter.ai" in url:
            headers["HTTP-Referer"] = "http://localhost/aegis-agent"
            headers["X-Title"] = "Aegis Agent"
        return self._post_json(url, payload=payload, headers=headers)

    def _post_json(self, url: str, *, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            url,
            data=body,
            method="POST",
            headers=headers,
        )
        try:
            with _open_model_request(request, timeout=self.timeout_seconds) as response:  # noqa: S310 - URL is provider registry controlled.
                raw = response.read().decode("utf-8")
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise RuntimeError("model provider redirect blocked") from exc
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"model provider HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"model provider connection failed: {exc.reason}") from exc
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise RuntimeError("model provider returned an invalid JSON payload")
        return decoded

    def _post_form(self, url: str, data: dict[str, str], *, headers: dict[str, str] | None = None) -> dict[str, Any]:
        body = urlencode(data).encode("utf-8")
        request_headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        if headers:
            request_headers.update(headers)
        request = Request(
            url,
            data=body,
            method="POST",
            headers=request_headers,
        )
        try:
            with _open_model_request(request, timeout=self.timeout_seconds) as response:  # noqa: S310 - URL is provider registry controlled.
                raw = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"model provider HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"model provider connection failed: {exc.reason}") from exc
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise RuntimeError("model provider returned an invalid JSON payload")
        return decoded


def _anthropic_messages(messages: list[dict[str, str]]) -> tuple[str, list[dict[str, str]]]:
    system_parts: list[str] = []
    routed: list[dict[str, str]] = []
    for message in messages:
        role = str(message.get("role", "user"))
        content = str(message.get("content", ""))
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
            continue
        next_role = "assistant" if role == "assistant" else "user"
        if routed and routed[-1]["role"] == next_role:
            routed[-1]["content"] = f"{routed[-1]['content']}\n\n{content}"
        else:
            routed.append({"role": next_role, "content": content})
    if not routed:
        routed.append({"role": "user", "content": "[no user content]"})
    return "\n\n".join(system_parts), routed


def _oauth_expires_soon(expires_at: str, skew_seconds: int) -> bool:
    if not expires_at:
        return True
    try:
        parsed = datetime.fromisoformat(expires_at)
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed.timestamp() - time.time()) <= max(0, skew_seconds)


def _expires_at_from_ttl(expires_in: Any) -> str:
    try:
        ttl = int(expires_in)
    except (TypeError, ValueError):
        ttl = 0
    return datetime.fromtimestamp(time.time() + max(0, ttl), tz=timezone.utc).isoformat()


def _subscription_cli_prompt(messages: list[dict[str, str]], *, provider: str, temperature: float) -> str:
    lines = [
        "You are acting as the subscription-backed model provider for Aegis Agent.",
        "Return only the final assistant answer. Do not inspect files, execute tools, or ask follow-up questions.",
        f"Provider bridge: {provider}",
        f"Requested temperature: {temperature}",
        "",
        "Conversation:",
    ]
    for message in messages:
        role = str(message.get("role", "user")).upper()
        content = str(message.get("content", "")).strip()
        if not content:
            continue
        lines.append(f"[{role}]")
        lines.append(content)
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _qwen_json_result_text(raw: str) -> str:
    if not raw.strip():
        return ""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("official Qwen Code CLI model invocation returned invalid JSON") from exc
    if isinstance(payload, dict):
        result = payload.get("result")
        if isinstance(result, str) and result.strip():
            return result.strip()
        return _qwen_message_text(payload.get("message", {}))
    if not isinstance(payload, list):
        raise RuntimeError("official Qwen Code CLI model invocation returned invalid JSON")
    for item in reversed(payload):
        if isinstance(item, dict) and item.get("type") == "result":
            result = item.get("result")
            if isinstance(result, str) and result.strip():
                return result.strip()
    for item in reversed(payload):
        if isinstance(item, dict) and item.get("type") == "assistant":
            content = _qwen_message_text(item.get("message", {}))
            if content:
                return content
    return ""


def _qwen_message_text(message: Any) -> str:
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for part in content:
        if isinstance(part, dict):
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
        elif isinstance(part, str) and part.strip():
            parts.append(part.strip())
    return "\n".join(parts).strip()


def _gemini_json_result(raw: str) -> tuple[str, dict[str, Any]]:
    if not raw.strip():
        return "", {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("official Gemini CLI model invocation returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("official Gemini CLI model invocation returned invalid JSON")
    error = payload.get("error")
    if isinstance(error, dict) and error:
        message = str(error.get("message") or error.get("details") or "unknown Gemini CLI error")
        raise RuntimeError(f"official Gemini CLI model invocation returned an error: {message}")
    response = payload.get("response")
    content = response.strip() if isinstance(response, str) else ""
    stats = payload.get("stats")
    return content, dict(stats) if isinstance(stats, dict) else {}


def _gemini_cli_model(model: str) -> str:
    if model == "gemini-pro":
        return "pro"
    if model == "gemini-flash":
        return "flash"
    return model


def _copilot_prompt_command(executable_path: str, *, prompt: str, model: str) -> tuple[str, ...]:
    return (
        executable_path,
        "-p",
        prompt,
        "--output-format=json",
        "--mode=plan",
        "--no-remote",
        "--no-custom-instructions",
        "--disable-builtin-mcps",
        "--no-ask-user",
        "--no-auto-update",
        "--no-bash-env",
        "--no-experimental",
        "--silent",
        "--stream=off",
        "--log-level=none",
        f"--model={model}",
        f"--excluded-tools={','.join(COPILOT_DENIED_TOOLS)}",
    )


def _copilot_safe_env() -> dict[str, str]:
    env = os.environ.copy()
    env["COPILOT_AUTO_UPDATE"] = "false"
    env["COPILOT_ALLOW_ALL"] = "false"
    env["GITHUB_COPILOT_PROMPT_MODE_EXTENSIONS"] = "false"
    env["GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS"] = "false"
    env["GITHUB_COPILOT_PROMPT_MODE_WORKSPACE_MCP"] = "false"
    return env


def _copilot_jsonl_result_text(raw: str) -> str:
    if not raw.strip():
        return ""
    messages: list[dict[str, Any]] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise RuntimeError("official GitHub Copilot CLI model invocation returned invalid JSONL") from exc
        if isinstance(item, dict):
            messages.append(item)
    for item in reversed(messages):
        content = _copilot_event_text(item)
        if content:
            return content
    return ""


def _copilot_event_text(item: dict[str, Any]) -> str:
    for key in ("result", "response", "text", "content"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    message = item.get("message")
    if isinstance(message, str) and message.strip():
        return message.strip()
    if isinstance(message, dict):
        qwen_style = _qwen_message_text(message)
        if qwen_style:
            return qwen_style
    delta = item.get("delta")
    if isinstance(delta, dict):
        return _copilot_event_text(delta)
    return ""


def _claude_cli_model(model: str) -> str:
    normalized = model.lower()
    if "opus" in normalized:
        return "opus"
    if "sonnet" in normalized:
        return "sonnet"
    return model


def _anthropic_text(content: Any) -> str:
    return _content_blocks_text(content)


def _google_messages(messages: list[dict[str, str]]) -> tuple[str, list[dict[str, Any]]]:
    system_parts: list[str] = []
    contents: list[dict[str, Any]] = []
    for message in messages:
        role = str(message.get("role", "user"))
        content = str(message.get("content", ""))
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
            continue
        gemini_role = "model" if role == "assistant" else "user"
        if contents and contents[-1]["role"] == gemini_role:
            contents[-1]["parts"].append({"text": content})
        else:
            contents.append({"role": gemini_role, "parts": [{"text": content}]})
    if not contents:
        contents.append({"role": "user", "parts": [{"text": "[no user content]"}]})
    return "\n\n".join(system_parts), contents


def _google_parts_text(parts: Any) -> str:
    if not isinstance(parts, list):
        return ""
    return "\n".join(str(part.get("text", "")).strip() for part in parts if isinstance(part, dict) and str(part.get("text", "")).strip()).strip()


def _google_vertex_generate_content_url(*, project: str, location: str, model: str) -> str:
    host = "aiplatform.googleapis.com" if location == "global" else f"{location}-aiplatform.googleapis.com"
    project_path = quote(project, safe="")
    location_path = quote(location, safe="")
    model_path = quote(model, safe="")
    return f"https://{host}/v1/projects/{project_path}/locations/{location_path}/publishers/google/models/{model_path}:generateContent"


def _bedrock_messages(messages: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    system_parts: list[str] = []
    routed: list[dict[str, Any]] = []
    for message in messages:
        role = str(message.get("role", "user"))
        content = str(message.get("content", ""))
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
            continue
        next_role = "assistant" if role == "assistant" else "user"
        block = {"text": content}
        if routed and routed[-1]["role"] == next_role:
            routed[-1]["content"].append(block)
        else:
            routed.append({"role": next_role, "content": [block]})
    if not routed:
        routed.append({"role": "user", "content": [{"text": "[no user content]"}]})
    return [{"text": "\n\n".join(system_parts)}] if system_parts else [], routed


def _bedrock_content_text(content: Any) -> str:
    if not isinstance(content, list):
        return ""
    return "\n".join(str(block.get("text", "")).strip() for block in content if isinstance(block, dict) and str(block.get("text", "")).strip()).strip()


def _content_blocks_text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    return "\n".join(part.strip() for part in parts if part.strip()).strip()


def _validate_custom_base_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.username or parsed.password:
        raise ValueError("custom model base URL must not include credentials")
    hostname = parsed.hostname or ""
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and _is_loopback_host(hostname):
        return
    raise ValueError("custom model base URL must use HTTPS unless it targets a local loopback host")


def _validate_azure_foundry_base_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.username or parsed.password:
        raise ValueError("azure-foundry base URL must not include credentials")
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not hostname.endswith((".openai.azure.com", ".services.ai.azure.com")):
        raise ValueError("azure-foundry base URL must be an HTTPS Azure OpenAI or Azure AI Foundry endpoint")
    if parsed.path.rstrip("/") != "/openai/v1":
        raise ValueError("azure-foundry base URL must include the /openai/v1 path")


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _open_model_request(request: Request, *, timeout: float):
    opener = build_opener(_NoRedirectHandler)
    return opener.open(request, timeout=timeout)
