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

    def auth_targets(self) -> dict[str, Any]:
        targets: list[dict[str, Any]] = []
        provider_rows = {row["provider"]: row for row in self.list_providers()}
        bridge_pending: list[str] = []
        not_started: list[str] = []
        api_key_ready: list[str] = []
        local_ready: list[str] = []
        for target in MODEL_PROVIDER_AUTH_TARGETS:
            target_row = dict(target)
            provider_name = target.get("aegis_provider")
            provider = provider_rows.get(str(provider_name)) if provider_name else None
            required_auth = list(target.get("required_auth", ()))
            target_row["required_auth"] = required_auth
            target_row["raw_tokens_captured"] = False
            target_row["existing_auth_methods"] = []
            target_row["auth_configured"] = False
            target_row["subscription_auth_supported"] = False
            target_row["subscription_auth_configured"] = False
            target_row["bridge_status"] = "not_started"
            if provider is None:
                target_row["status"] = "not_started"
                not_started.append(str(target["target"]))
            else:
                methods = list(provider.get("auth_methods") or [])
                target_row["existing_auth_methods"] = methods
                target_row["auth_configured"] = bool(provider.get("auth_configured"))
                target_row["subscription_auth_supported"] = bool(provider.get("subscription_auth_supported"))
                target_row["subscription_auth_configured"] = bool(provider.get("subscription_auth_configured"))
                subscription_profile = provider.get("subscription_auth") if isinstance(provider.get("subscription_auth"), dict) else {}
                if subscription_profile:
                    target_row["external_command"] = subscription_profile.get("external_command", target_row.get("external_command"))
                    target_row["bridge_status"] = subscription_profile.get("aegis_bridge_status", "not_implemented")
                    target_row["account_surface"] = subscription_profile.get("account_surface", target_row.get("account_surface"))
                elif provider.get("local"):
                    target_row["bridge_status"] = "not_required_local"
                elif "api_key" in methods:
                    target_row["bridge_status"] = "not_required_api_key"

                if "subscription" in required_auth or "oauth_device" in required_auth or "oauth" in required_auth or "cloud_identity" in required_auth:
                    if "subscription" in required_auth and target_row["subscription_auth_supported"]:
                        target_row["status"] = "metadata_only_bridge_pending"
                        bridge_pending.append(str(target["target"]))
                    else:
                        target_row["status"] = "provider_native_auth_bridge_required"
                        bridge_pending.append(str(target["target"]))
                elif provider.get("local") or "none" in methods:
                    target_row["status"] = "local_ready"
                    local_ready.append(str(target["target"]))
                elif "api_key" in required_auth and "api_key" in methods:
                    target_row["status"] = "api_key_ready"
                    api_key_ready.append(str(target["target"]))
                else:
                    target_row["status"] = "auth_surface_incomplete"
                    not_started.append(str(target["target"]))
            targets.append(target_row)

        missing_or_pending = len(bridge_pending) + len(not_started)
        return {
            "status": "target_surface_ready" if missing_or_pending == 0 else "auth_parity_gap_tracked",
            "target_provider_count": len(targets),
            "aegis_provider_count": len(provider_rows),
            "api_key_ready_count": len(api_key_ready),
            "local_ready_count": len(local_ready),
            "metadata_or_bridge_pending_count": len(bridge_pending),
            "not_started_count": len(not_started),
            "api_key_ready_targets": api_key_ready,
            "local_ready_targets": local_ready,
            "subscription_bridge_targets": bridge_pending,
            "not_started_targets": not_started,
            "implemented_auth_methods": sorted({method for row in provider_rows.values() for method in row.get("auth_methods", [])}),
            "required_controls": [
                "official_provider_login_flow",
                "scoped_refresh_token_bridge",
                "secret_broker_storage",
                "token_refresh_receipts",
                "no_browser_cookie_import",
                "provider_domain_allowlist",
            ],
            "verification_gates": [
                "api_key_secret_redaction",
                "subscription_login_metadata_only",
                "oauth_device_flow_denial_until_bridge",
                "raw_token_capture_rejection",
                "provider_allowlist_enforced_before_live_call",
            ],
            "targets": targets,
        }

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


MODEL_PROVIDER_AUTH_TARGETS: tuple[dict[str, Any], ...] = (
    {
        "target": "OpenAI API",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "openai",
        "required_auth": ("api_key",),
        "account_surface": "OpenAI platform",
    },
    {
        "target": "OpenAI Codex / ChatGPT subscription",
        "platforms": ("Hermes Agent", "Claude Code parity"),
        "aegis_provider": "openai",
        "required_auth": ("subscription",),
        "external_command": "codex login",
        "account_surface": "ChatGPT / Codex",
    },
    {
        "target": "Anthropic API",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "anthropic",
        "required_auth": ("api_key",),
        "account_surface": "Anthropic Console",
    },
    {
        "target": "Claude Code subscription",
        "platforms": ("Claude Code", "Hermes Agent"),
        "aegis_provider": "anthropic",
        "required_auth": ("subscription",),
        "external_command": "claude auth login",
        "account_surface": "claude.ai / Claude Code",
    },
    {
        "target": "Nous Portal API key",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "nous",
        "required_auth": ("api_key",),
        "account_surface": "Nous Portal",
    },
    {
        "target": "Nous Portal OAuth subscription",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "nous",
        "required_auth": ("oauth",),
        "account_surface": "Nous Portal",
    },
    {
        "target": "GitHub Copilot",
        "platforms": ("Hermes Agent",),
        "aegis_provider": None,
        "required_auth": ("oauth_device",),
        "account_surface": "GitHub Copilot subscription",
    },
    {
        "target": "OpenRouter",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "openrouter",
        "required_auth": ("api_key",),
        "account_surface": "OpenRouter",
    },
    {
        "target": "Google Gemini",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "google",
        "required_auth": ("api_key",),
        "account_surface": "Google AI Studio / Gemini API",
    },
    {
        "target": "Mistral",
        "platforms": ("Aegis current",),
        "aegis_provider": "mistral",
        "required_auth": ("api_key",),
        "account_surface": "Mistral Console",
    },
    {
        "target": "Cohere",
        "platforms": ("Aegis current",),
        "aegis_provider": "cohere",
        "required_auth": ("api_key",),
        "account_surface": "Cohere Dashboard",
    },
    {
        "target": "DeepSeek",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "deepseek",
        "required_auth": ("api_key",),
        "account_surface": "DeepSeek",
    },
    {
        "target": "xAI / Grok",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "xai",
        "required_auth": ("api_key",),
        "account_surface": "xAI Console",
    },
    {
        "target": "Z.AI",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "zai",
        "required_auth": ("api_key",),
        "account_surface": "Z.AI",
    },
    {
        "target": "Kimi",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "kimi",
        "required_auth": ("api_key",),
        "account_surface": "Kimi / Moonshot",
    },
    {
        "target": "MiniMax",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "minimax",
        "required_auth": ("api_key",),
        "account_surface": "MiniMax",
    },
    {
        "target": "MiniMax OAuth",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "minimax",
        "required_auth": ("oauth",),
        "account_surface": "MiniMax",
    },
    {
        "target": "AWS Bedrock",
        "platforms": ("Hermes Agent",),
        "aegis_provider": None,
        "required_auth": ("cloud_identity",),
        "account_surface": "AWS IAM / Bedrock",
    },
    {
        "target": "Azure Foundry",
        "platforms": ("Hermes Agent",),
        "aegis_provider": None,
        "required_auth": ("cloud_identity", "api_key"),
        "account_surface": "Azure AI Foundry",
    },
    {
        "target": "Qwen DashScope API",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "qwen",
        "required_auth": ("api_key",),
        "account_surface": "Alibaba Cloud Model Studio / DashScope",
    },
    {
        "target": "Qwen OAuth",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "qwen",
        "required_auth": ("oauth",),
        "account_surface": "Qwen",
    },
    {
        "target": "Ollama",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "ollama",
        "required_auth": ("none",),
        "account_surface": "local Ollama",
    },
    {
        "target": "LM Studio",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "lmstudio",
        "required_auth": ("none",),
        "account_surface": "local LM Studio",
    },
    {
        "target": "Custom OpenAI-compatible endpoint",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "custom",
        "required_auth": ("api_key",),
        "account_surface": "operator supplied endpoint",
    },
)


def default_providers(*, custom_base_url: str | None = None) -> dict[str, ModelProviderSpec]:
    providers = (
        ModelProviderSpec("openai", ("gpt-4o", "gpt-4o-mini", "o1", "o3", "o3-mini"), "OPENAI_API_KEY", "https://api.openai.com/v1", False, True, True, True, 2.5, 10.0, 128000, "openai"),
        ModelProviderSpec("anthropic", ("claude-opus", "claude-sonnet-4.6", "claude-haiku"), "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1", False, True, True, False, 3.0, 15.0, 200000, "anthropic"),
        ModelProviderSpec("google", ("gemini-pro", "gemini-flash"), "GOOGLE_API_KEY", "https://generativelanguage.googleapis.com/v1beta", False, True, True, True, 1.25, 5.0, 1000000, "google"),
        ModelProviderSpec("mistral", ("mistral-large", "mistral-medium", "mistral-small", "codestral"), "MISTRAL_API_KEY", "https://api.mistral.ai/v1", False, True, False, False, 2.0, 6.0, 32000, "mistral"),
        ModelProviderSpec("cohere", ("command-r-plus", "command-r"), "COHERE_API_KEY", "https://api.cohere.com/v2", False, True, False, False, 3.0, 15.0, 128000, "cohere"),
        ModelProviderSpec("openrouter", ("anthropic/claude-sonnet-4.6", "openai/gpt-4o", "meta-llama/llama-3.1-70b"), "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", False, True, True, True, 0.0, 0.0, 128000, "openrouter"),
        ModelProviderSpec("nous", ("Hermes-4-405B", "Hermes-4-70B"), "NOUS_API_KEY", "https://inference-api.nousresearch.com/v1", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("deepseek", ("deepseek-v4-flash", "deepseek-v4-pro", "deepseek-chat", "deepseek-reasoner"), "DEEPSEEK_API_KEY", "https://api.deepseek.com", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("xai", ("grok-4.20-reasoning", "grok-4", "grok-4-fast"), "XAI_API_KEY", "https://api.x.ai/v1", False, True, True, False, 0.0, 0.0, 256000, "openai_compatible"),
        ModelProviderSpec("kimi", ("kimi-k2.5", "kimi-k2-turbo-preview", "kimi-k2-thinking"), "KIMI_API_KEY", "https://api.moonshot.ai/v1", False, True, True, False, 0.0, 0.0, 256000, "openai_compatible"),
        ModelProviderSpec("minimax", ("MiniMax-M2.7", "MiniMax-M2.5", "MiniMax-M2"), "MINIMAX_API_KEY", "https://api.minimax.io/v1", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("zai", ("glm-5.1", "glm-5", "glm-4.7", "glm-4.6", "glm-4.5"), "GLM_API_KEY", "https://api.z.ai/api/paas/v4", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("qwen", ("qwen-plus", "qwen-max", "qwen-turbo"), "DASHSCOPE_API_KEY", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("ollama", ("llama3", "llama3.1", "mistral", "mixtral", "phi3", "gemma2", "codellama", "deepseek-coder"), None, "http://localhost:11434", True, False, context_window_tokens=8192, tokenizer_profile="llama"),
        ModelProviderSpec("lmstudio", ("local",), None, "http://localhost:1234/v1", True, False, context_window_tokens=8192, tokenizer_profile="openai_compatible"),
        ModelProviderSpec("custom", ("*",), "CUSTOM_API_KEY", custom_base_url, False, True, context_window_tokens=8192, tokenizer_profile="openai_compatible"),
    )
    return {provider.provider: provider for provider in providers}
