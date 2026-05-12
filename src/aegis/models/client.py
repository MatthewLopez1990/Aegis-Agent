"""Minimal live model client for OpenAI-compatible providers."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aegis.models.registry import ModelRoute
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
    "minimax",
    "zai",
    "qwen",
}


class LiveModelClient:
    """Invokes configured live providers without exposing raw secrets to callers."""

    def __init__(self, secrets_broker: SecretsBroker, *, timeout_seconds: float = 60.0) -> None:
        self.secrets_broker = secrets_broker
        self.timeout_seconds = timeout_seconds

    def chat(self, route: ModelRoute, messages: list[dict[str, str]], *, temperature: float = 0.2) -> ModelInvocationResult:
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
        return ModelInvocationResult(
            provider=route.provider.provider,
            model=route.model,
            content=content,
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            raw_usage=dict(usage),
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
