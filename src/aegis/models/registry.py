"""Model-agnostic provider registry with aliases, fallbacks, and usage tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import now_utc


@dataclass(frozen=True)
class ModelProviderSpec:
    provider: str
    models: tuple[str, ...]
    auth_secret: str | None
    base_url: str | None
    local: bool
    supports_tools: bool
    supports_vision: bool = False
    supports_audio: bool = False
    input_cost_per_million: float = 0.0
    output_cost_per_million: float = 0.0
    context_window_tokens: int = 8192
    tokenizer_profile: str = "generic"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelRoute:
    identifier: str
    provider: ModelProviderSpec
    model: str
    fallback_identifiers: tuple[str, ...]
    secret_handle_id: str | None


class ModelRegistry:
    def __init__(
        self,
        store: LocalStore,
        audit_logger: AuditLogger,
        secrets_broker: SecretsBroker | None = None,
        *,
        custom_base_url: str | None = None,
    ) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.secrets_broker = secrets_broker or SecretsBroker()
        self.providers = default_providers(custom_base_url=custom_base_url)
        self.aliases: dict[str, str] = {
            "smart": "openrouter/anthropic/claude-sonnet-4.6",
            "fast": "openai/gpt-4o-mini",
            "private": "ollama/llama3",
        }
        self.fallbacks: dict[str, tuple[str, ...]] = {
            "openai/gpt-4o": ("anthropic/claude-sonnet-4.6", "ollama/llama3"),
            "anthropic/claude-sonnet-4.6": ("openai/gpt-4o", "ollama/llama3"),
            "openrouter/anthropic/claude-sonnet-4.6": ("openai/gpt-4o", "ollama/llama3"),
        }
        self._load_persisted_routes()

    def list_models(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for provider in self.providers.values():
            for model in provider.models:
                rows.append(
                    {
                        "identifier": f"{provider.provider}/{model}",
                        "provider": provider.provider,
                        "model": model,
                        "local": provider.local,
                        "supports_tools": provider.supports_tools,
                        "supports_vision": provider.supports_vision,
                        "supports_audio": provider.supports_audio,
                        "auth_required": provider.auth_secret is not None,
                        "auth_configured": self._auth_configured(provider),
                        "auth_source": self._auth_source(provider),
                        "auth_methods": self._auth_methods(provider),
                        "subscription_auth_supported": self._subscription_auth_supported(provider),
                        "subscription_auth_configured": False,
                        "context_window_tokens": provider.context_window_tokens,
                        "tokenizer_profile": provider.tokenizer_profile,
                    }
                )
        return rows

    def list_providers(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for provider in self.providers.values():
            rows.append(
                {
                    "provider": provider.provider,
                    "models": list(provider.models),
                    "base_url": provider.base_url,
                    "local": provider.local,
                    "supports_tools": provider.supports_tools,
                    "supports_vision": provider.supports_vision,
                    "supports_audio": provider.supports_audio,
                    "auth_required": provider.auth_secret is not None,
                    "auth_secret": provider.auth_secret,
                    "auth_configured": self._auth_configured(provider),
                    "auth_source": self._auth_source(provider),
                    "auth_methods": self._auth_methods(provider),
                    "subscription_auth_supported": self._subscription_auth_supported(provider),
                    "subscription_auth_configured": False,
                    "subscription_auth": self._subscription_auth_profile(provider),
                    "context_window_tokens": provider.context_window_tokens,
                    "tokenizer_profile": provider.tokenizer_profile,
                    "metadata": dict(provider.metadata),
                }
            )
        return rows

    def auth_status(self, provider_name: str | None = None) -> list[dict[str, Any]] | dict[str, Any]:
        if provider_name is not None:
            provider = self._provider(provider_name)
            return self._provider_auth_status(provider)
        return [self._provider_auth_status(provider) for provider in self.providers.values() if provider.auth_secret]

    def login_provider(self, provider_name: str, api_key: str) -> dict[str, Any]:
        provider = self._provider(provider_name)
        if provider.auth_secret is None:
            raise ValueError(f"provider {provider_name!r} does not require model auth")
        self.secrets_broker.store_secret(name=provider.auth_secret, value=api_key)
        status = self._provider_auth_status(provider)
        self.audit_logger.append(
            "model.auth_login",
            {"provider": provider.provider, "auth_secret": provider.auth_secret, "auth_source": status["auth_source"]},
        )
        return status

    def login_provider_subscription(self, provider_name: str) -> dict[str, Any]:
        provider = self._provider(provider_name)
        profile = self._subscription_auth_profile(provider)
        if profile is None:
            raise ValueError(f"provider {provider_name!r} does not support subscription login")
        status = {
            "provider": provider.provider,
            "method": "subscription",
            "status": "external_login_required",
            "auth_configured": False,
            "auth_source": None,
            "token_captured": False,
            "token_capture_supported": False,
            **profile,
        }
        self.audit_logger.append(
            "model.auth_subscription_login_requested",
            {
                "provider": provider.provider,
                "method": "subscription",
                "status": status["status"],
                "token_captured": False,
            },
        )
        return status

    def logout_provider(self, provider_name: str) -> dict[str, Any]:
        provider = self._provider(provider_name)
        if provider.auth_secret is None:
            raise ValueError(f"provider {provider_name!r} does not require model auth")
        removed = self.secrets_broker.delete_secret(provider.auth_secret)
        status = self._provider_auth_status(provider)
        self.audit_logger.append(
            "model.auth_logout",
            {"provider": provider.provider, "auth_secret": provider.auth_secret, "removed_local_secret": removed},
        )
        return status

    def set_alias(self, alias: str, identifier: str) -> None:
        self._split_identifier(identifier)
        self.aliases[alias] = identifier
        self._persist_routes()
        self.audit_logger.append("model.alias_set", {"alias": alias, "identifier": identifier})

    def set_fallbacks(self, identifier: str, fallbacks: tuple[str, ...]) -> None:
        self._split_identifier(identifier)
        for fallback in fallbacks:
            self._split_identifier(fallback)
        self.fallbacks[identifier] = fallbacks
        self._persist_routes()
        self.audit_logger.append("model.fallbacks_set", {"identifier": identifier, "fallbacks": list(fallbacks)})

    def route(self, identifier: str) -> ModelRoute:
        resolved = self.aliases.get(identifier.removeprefix("alias/"), identifier) if identifier.startswith("alias/") else self.aliases.get(identifier, identifier)
        provider_name, model = self._split_identifier(resolved)
        provider = self.providers[provider_name]
        secret_handle_id = None
        if provider.auth_secret:
            secret_handle = self.secrets_broker.request_handle(
                name=provider.auth_secret,
                requester=f"model:{provider.provider}",
                reason="model provider API call",
                scopes=("model.invoke",),
            )
            secret_handle_id = secret_handle.handle_id
        route = ModelRoute(resolved, provider, model, self.fallbacks.get(resolved, ()), secret_handle_id)
        self.audit_logger.append("model.routed", {"identifier": resolved, "fallbacks": list(route.fallback_identifiers)})
        return route

    def record_usage(
        self,
        *,
        identifier: str,
        input_tokens: int,
        output_tokens: int,
        task_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        provider_name, model = self._split_identifier(self.aliases.get(identifier, identifier))
        provider = self.providers[provider_name]
        cost = (input_tokens / 1_000_000 * provider.input_cost_per_million) + (output_tokens / 1_000_000 * provider.output_cost_per_million)
        row = {
            "id": str(uuid4()),
            "provider": provider_name,
            "model": model,
            "task_id": task_id,
            "session_id": session_id,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "estimated_cost": round(cost, 6),
            "created_at": now_utc(),
            "metadata": metadata or {},
        }
        self.store.insert_model_usage(row)
        self.audit_logger.append("model.usage_recorded", row, task_id=task_id)
        return row

    def usage_summary(self) -> dict[str, Any]:
        rows = self.store.list_model_usage(limit=10000)
        total_cost = sum(float(row["estimated_cost"]) for row in rows)
        total_input = sum(int(row["input_tokens"]) for row in rows)
        total_output = sum(int(row["output_tokens"]) for row in rows)
        by_provider: dict[str, dict[str, Any]] = {}
        by_model: dict[str, dict[str, Any]] = {}
        for row in rows:
            provider = str(row["provider"])
            model = str(row["model"])
            model_key = f"{provider}/{model}"
            _accumulate_usage(by_provider, provider, row)
            _accumulate_usage(by_model, model_key, row)
        return {
            "events": len(rows),
            "input_tokens": total_input,
            "output_tokens": total_output,
            "estimated_cost": round(total_cost, 6),
            "by_provider": list(by_provider.values()),
            "by_model": list(by_model.values()),
            "recent_events": [_usage_event_summary(row) for row in rows[:10]],
        }

    def _split_identifier(self, identifier: str) -> tuple[str, str]:
        if "/" not in identifier:
            raise ValueError("model identifier must be provider/model")
        provider_name, model = identifier.split("/", 1)
        if provider_name not in self.providers:
            raise KeyError(f"unknown model provider {provider_name!r}")
        if model not in self.providers[provider_name].models and provider_name not in {"custom", "lmstudio"}:
            raise KeyError(f"unknown model {model!r} for provider {provider_name!r}")
        return provider_name, model

    def _provider(self, provider_name: str) -> ModelProviderSpec:
        if provider_name not in self.providers:
            raise KeyError(f"unknown model provider {provider_name!r}")
        return self.providers[provider_name]

    def _load_persisted_routes(self) -> None:
        settings = self.store.list_model_route_settings()
        aliases = settings.get("aliases", {}).get("aliases", {})
        if isinstance(aliases, dict):
            for alias, identifier in aliases.items():
                try:
                    self._split_identifier(str(identifier))
                except (KeyError, ValueError):
                    continue
                self.aliases[str(alias)] = str(identifier)
        fallbacks = settings.get("fallbacks", {}).get("fallbacks", {})
        if isinstance(fallbacks, dict):
            for identifier, values in fallbacks.items():
                if not isinstance(values, list):
                    continue
                try:
                    self._split_identifier(str(identifier))
                    parsed = tuple(str(value) for value in values)
                    for fallback in parsed:
                        self._split_identifier(fallback)
                except (KeyError, ValueError):
                    continue
                self.fallbacks[str(identifier)] = parsed

    def _persist_routes(self) -> None:
        self.store.set_model_route_setting("aliases", {"aliases": dict(sorted(self.aliases.items()))})
        self.store.set_model_route_setting(
            "fallbacks",
            {"fallbacks": {identifier: list(values) for identifier, values in sorted(self.fallbacks.items())}},
        )

    def _provider_auth_status(self, provider: ModelProviderSpec) -> dict[str, Any]:
        return {
            "provider": provider.provider,
            "auth_required": provider.auth_secret is not None,
            "auth_secret": provider.auth_secret,
            "auth_configured": self._auth_configured(provider),
            "auth_source": self._auth_source(provider),
            "auth_methods": self._auth_methods(provider),
            "subscription_auth_supported": self._subscription_auth_supported(provider),
            "subscription_auth_configured": False,
            "subscription_auth": self._subscription_auth_profile(provider),
        }

    def _auth_configured(self, provider: ModelProviderSpec) -> bool:
        return provider.auth_secret is not None and self.secrets_broker.has_secret(provider.auth_secret)

    def _auth_source(self, provider: ModelProviderSpec) -> str | None:
        if provider.auth_secret is None:
            return None
        return self.secrets_broker.secret_source(provider.auth_secret)

    def _auth_methods(self, provider: ModelProviderSpec) -> list[str]:
        methods = ["none"] if provider.auth_secret is None else ["api_key"]
        if self._subscription_auth_supported(provider):
            methods.append("subscription")
        return methods

    def _subscription_auth_supported(self, provider: ModelProviderSpec) -> bool:
        return provider.provider in SUBSCRIPTION_AUTH_PROFILES

    def _subscription_auth_profile(self, provider: ModelProviderSpec) -> dict[str, Any] | None:
        profile = SUBSCRIPTION_AUTH_PROFILES.get(provider.provider)
        if profile is None:
            return None
        return {key: value for key, value in profile.items()}


def _accumulate_usage(bucket: dict[str, dict[str, Any]], key: str, row: dict[str, Any]) -> None:
    current = bucket.setdefault(
        key,
        {
            "key": key,
            "events": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "estimated_cost": 0.0,
            "latest_at": None,
        },
    )
    current["events"] += 1
    current["input_tokens"] += int(row["input_tokens"])
    current["output_tokens"] += int(row["output_tokens"])
    current["estimated_cost"] = round(float(current["estimated_cost"]) + float(row["estimated_cost"]), 6)
    latest_at = str(row.get("created_at") or "")
    if latest_at and (current["latest_at"] is None or latest_at > str(current["latest_at"])):
        current["latest_at"] = latest_at


def _usage_event_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "provider": str(row["provider"]),
        "model": str(row["model"]),
        "task_id": row.get("task_id"),
        "session_id": row.get("session_id"),
        "input_tokens": int(row["input_tokens"]),
        "output_tokens": int(row["output_tokens"]),
        "estimated_cost": round(float(row["estimated_cost"]), 6),
        "created_at": str(row.get("created_at") or ""),
        "metadata_keys": _metadata_keys(row.get("metadata_json")),
    }


def _metadata_keys(raw: Any) -> list[str]:
    if not isinstance(raw, str) or not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, dict):
        return []
    return sorted(str(key) for key in value.keys())


SUBSCRIPTION_AUTH_PROFILES: dict[str, dict[str, Any]] = {
    "openai": {
        "account_surface": "ChatGPT / Codex",
        "external_command": "codex login",
        "requires": "ChatGPT account with Codex access",
        "provider_token_source": "official Codex CLI auth store",
        "aegis_bridge_status": "not_implemented",
        "next_steps": [
            "Sign in with the official Codex CLI for subscription-backed local Codex access.",
            "Keep using model auth login openai --api-key-stdin for Aegis live OpenAI API calls until a governed token bridge is implemented.",
            "Do not paste ChatGPT session cookies or browser tokens into Aegis.",
        ],
    },
    "anthropic": {
        "account_surface": "claude.ai / Claude Code",
        "external_command": "claude auth login",
        "requires": "claude.ai account with Claude Code access; Remote Control requires full-scope claude.ai login, not API key auth",
        "provider_token_source": "official Claude Code auth store",
        "aegis_bridge_status": "not_implemented",
        "next_steps": [
            "Sign in with the official Claude Code CLI for subscription-backed Claude Code access.",
            "Keep using model auth login anthropic --api-key-stdin for Aegis live Anthropic API calls until a governed token bridge is implemented.",
            "Do not paste claude.ai browser session tokens into Aegis.",
        ],
    },
}


def default_providers(*, custom_base_url: str | None = None) -> dict[str, ModelProviderSpec]:
    providers = (
        ModelProviderSpec("openai", ("gpt-4o", "gpt-4o-mini", "o1", "o3", "o3-mini"), "OPENAI_API_KEY", "https://api.openai.com/v1", False, True, True, True, 2.5, 10.0, 128000, "openai"),
        ModelProviderSpec("anthropic", ("claude-opus", "claude-sonnet-4.6", "claude-haiku"), "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1", False, True, True, False, 3.0, 15.0, 200000, "anthropic"),
        ModelProviderSpec("google", ("gemini-pro", "gemini-flash"), "GOOGLE_API_KEY", "https://generativelanguage.googleapis.com/v1beta", False, True, True, True, 1.25, 5.0, 1000000, "google"),
        ModelProviderSpec("mistral", ("mistral-large", "mistral-medium", "mistral-small", "codestral"), "MISTRAL_API_KEY", "https://api.mistral.ai/v1", False, True, False, False, 2.0, 6.0, 32000, "mistral"),
        ModelProviderSpec("cohere", ("command-r-plus", "command-r"), "COHERE_API_KEY", "https://api.cohere.com/v2", False, True, False, False, 3.0, 15.0, 128000, "cohere"),
        ModelProviderSpec("openrouter", ("anthropic/claude-sonnet-4.6", "openai/gpt-4o", "meta-llama/llama-3.1-70b"), "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", False, True, True, True, 0.0, 0.0, 128000, "openrouter"),
        ModelProviderSpec("ollama", ("llama3", "llama3.1", "mistral", "mixtral", "phi3", "gemma2", "codellama", "deepseek-coder"), None, "http://localhost:11434", True, False, context_window_tokens=8192, tokenizer_profile="llama"),
        ModelProviderSpec("lmstudio", ("local",), None, "http://localhost:1234/v1", True, False, context_window_tokens=8192, tokenizer_profile="openai_compatible"),
        ModelProviderSpec("custom", ("*",), "CUSTOM_API_KEY", custom_base_url, False, True, context_window_tokens=8192, tokenizer_profile="openai_compatible"),
    )
    return {provider.provider: provider for provider in providers}
