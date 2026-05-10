"""Model-agnostic provider registry with aliases, fallbacks, and usage tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
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
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelRoute:
    identifier: str
    provider: ModelProviderSpec
    model: str
    fallback_identifiers: tuple[str, ...]
    secret_handle_id: str | None


class ModelRegistry:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger, secrets_broker: SecretsBroker | None = None) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.secrets_broker = secrets_broker or SecretsBroker()
        self.providers = default_providers()
        self.aliases: dict[str, str] = {"smart": "openai/gpt-4o", "fast": "openai/gpt-4o-mini", "private": "ollama/llama3"}
        self.fallbacks: dict[str, tuple[str, ...]] = {
            "openai/gpt-4o": ("anthropic/claude-sonnet-4.6", "ollama/llama3"),
            "anthropic/claude-sonnet-4.6": ("openai/gpt-4o", "ollama/llama3"),
        }

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
        self.audit_logger.append("model.alias_set", {"alias": alias, "identifier": identifier})

    def set_fallbacks(self, identifier: str, fallbacks: tuple[str, ...]) -> None:
        self._split_identifier(identifier)
        for fallback in fallbacks:
            self._split_identifier(fallback)
        self.fallbacks[identifier] = fallbacks
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
        return {"events": len(rows), "input_tokens": total_input, "output_tokens": total_output, "estimated_cost": round(total_cost, 6)}

    def _split_identifier(self, identifier: str) -> tuple[str, str]:
        if "/" not in identifier:
            raise ValueError("model identifier must be provider/model")
        provider_name, model = identifier.split("/", 1)
        if provider_name not in self.providers:
            raise KeyError(f"unknown model provider {provider_name!r}")
        if model not in self.providers[provider_name].models and provider_name != "custom":
            raise KeyError(f"unknown model {model!r} for provider {provider_name!r}")
        return provider_name, model

    def _provider(self, provider_name: str) -> ModelProviderSpec:
        if provider_name not in self.providers:
            raise KeyError(f"unknown model provider {provider_name!r}")
        return self.providers[provider_name]

    def _provider_auth_status(self, provider: ModelProviderSpec) -> dict[str, Any]:
        return {
            "provider": provider.provider,
            "auth_required": provider.auth_secret is not None,
            "auth_secret": provider.auth_secret,
            "auth_configured": self._auth_configured(provider),
            "auth_source": self._auth_source(provider),
        }

    def _auth_configured(self, provider: ModelProviderSpec) -> bool:
        return provider.auth_secret is not None and self.secrets_broker.has_secret(provider.auth_secret)

    def _auth_source(self, provider: ModelProviderSpec) -> str | None:
        if provider.auth_secret is None:
            return None
        return self.secrets_broker.secret_source(provider.auth_secret)


def default_providers() -> dict[str, ModelProviderSpec]:
    providers = (
        ModelProviderSpec("openai", ("gpt-4o", "gpt-4o-mini", "o1", "o3", "o3-mini"), "OPENAI_API_KEY", None, False, True, True, True, 2.5, 10.0),
        ModelProviderSpec("anthropic", ("claude-opus", "claude-sonnet-4.6", "claude-haiku"), "ANTHROPIC_API_KEY", None, False, True, True, False, 3.0, 15.0),
        ModelProviderSpec("google", ("gemini-pro", "gemini-flash"), "GOOGLE_API_KEY", None, False, True, True, True, 1.25, 5.0),
        ModelProviderSpec("mistral", ("mistral-large", "mistral-medium", "mistral-small", "codestral"), "MISTRAL_API_KEY", None, False, True, False, False, 2.0, 6.0),
        ModelProviderSpec("cohere", ("command-r-plus", "command-r"), "COHERE_API_KEY", None, False, True, False, False, 3.0, 15.0),
        ModelProviderSpec("openrouter", ("anthropic/claude-sonnet-4.6", "openai/gpt-4o", "meta-llama/llama-3.1-70b"), "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", False, True, True, True, 0.0, 0.0),
        ModelProviderSpec("ollama", ("llama3", "llama3.1", "mistral", "mixtral", "phi3", "gemma2", "codellama", "deepseek-coder"), None, "http://localhost:11434", True, False),
        ModelProviderSpec("lmstudio", ("local",), None, "http://localhost:1234/v1", True, False),
        ModelProviderSpec("custom", ("*",), "CUSTOM_API_KEY", None, False, True),
    )
    return {provider.provider: provider for provider in providers}
