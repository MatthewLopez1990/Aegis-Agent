"""Model-agnostic provider registry with aliases, fallbacks, and usage tracking."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
import shlex
import shutil
import secrets
import subprocess
import tempfile
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
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
    external_auth_method: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelRoute:
    identifier: str
    provider: ModelProviderSpec
    model: str
    fallback_identifiers: tuple[str, ...]
    secret_handle_id: str | None
    auth_method: str = "none"
    auth_metadata: dict[str, Any] = field(default_factory=dict)


class ModelRegistry:
    def __init__(
        self,
        store: LocalStore,
        audit_logger: AuditLogger,
        secrets_broker: SecretsBroker | None = None,
        *,
        custom_base_url: str | None = None,
        azure_foundry_base_url: str | None = None,
        google_vertex_project: str | None = None,
        google_vertex_location: str | None = None,
    ) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.secrets_broker = secrets_broker or SecretsBroker()
        self.providers = default_providers(
            custom_base_url=custom_base_url,
            azure_foundry_base_url=azure_foundry_base_url,
            google_vertex_project=google_vertex_project,
            google_vertex_location=google_vertex_location,
        )
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
        self.external_auth_links: dict[str, dict[str, Any]] = {}
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
                        "auth_required": self._auth_required(provider),
                        "auth_configured": self._auth_configured(provider),
                        "api_key_auth_configured": self._api_key_auth_configured(provider),
                        "auth_source": self._auth_source(provider),
                        "auth_methods": self._auth_methods(provider),
                        "subscription_auth_supported": self._subscription_auth_supported(provider),
                        "subscription_auth_configured": self._subscription_auth_configured(provider),
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
                    "auth_required": self._auth_required(provider),
                    "auth_secret": provider.auth_secret,
                    "auth_configured": self._auth_configured(provider),
                    "api_key_auth_configured": self._api_key_auth_configured(provider),
                    "auth_source": self._auth_source(provider),
                    "auth_methods": self._auth_methods(provider),
                    "subscription_auth_supported": self._subscription_auth_supported(provider),
                    "subscription_auth_configured": self._subscription_auth_configured(provider),
                    "subscription_auth": self._subscription_auth_profile(provider),
                    "context_window_tokens": provider.context_window_tokens,
                    "tokenizer_profile": provider.tokenizer_profile,
                    "metadata": dict(provider.metadata),
                }
            )
        return rows

    def auth_status(self, provider_name: str | None = None) -> list[dict[str, Any]] | dict[str, Any]:
        if provider_name is not None:
            if provider_name in self.providers:
                provider = self.providers[provider_name]
                return self._provider_auth_status(provider)
            profile = _external_auth_handoff_profile(provider_name)
            if profile is not None:
                return self._external_auth_status(profile)
            raise KeyError(f"unknown model provider {provider_name!r}")
        return [self._provider_auth_status(provider) for provider in self.providers.values() if self._auth_required(provider)]

    def auth_targets(self) -> dict[str, Any]:
        targets: list[dict[str, Any]] = []
        provider_rows = {row["provider"]: row for row in self.list_providers()}
        bridge_pending: list[str] = []
        not_started: list[str] = []
        api_key_ready: list[str] = []
        local_ready: list[str] = []
        verified_external: list[str] = []
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
            target_row["external_auth_configured"] = False
            target_row["bridge_status"] = "not_started"
            handoff_profile = _external_auth_handoff_profile(str(target.get("target")))
            external_status = self._external_auth_status(handoff_profile) if handoff_profile is not None else None
            external_verified = external_status is not None and bool(external_status["external_auth_configured"])
            if handoff_profile is not None:
                target_row.update(_handoff_profile_public_fields(handoff_profile))
                target_row["bridge_status"] = str(handoff_profile.get("aegis_bridge_status") or "official_cli_handoff_only")
            if external_verified and external_status is not None:
                target_row.update(
                    {
                        "status": "external_login_verified",
                        "bridge_status": external_status.get("bridge_status") or "official_cli_link_verified",
                        "auth_configured": True,
                        "external_auth_configured": True,
                        "auth_source": external_status.get("auth_source"),
                        "last_verified_at": external_status.get("last_verified_at"),
                        "token_captured": False,
                        "token_capture_supported": False,
                        "oauth_token_brokered": bool(external_status.get("oauth_token_brokered", False)),
                    }
                )
                verified_external.append(str(target["target"]))
                targets.append(target_row)
                continue
            if provider is None:
                if handoff_profile is not None:
                    target_row["status"] = target_row["bridge_status"]
                    bridge_pending.append(str(target["target"]))
                else:
                    target_row["status"] = "not_started"
                    not_started.append(str(target["target"]))
            else:
                methods = list(provider.get("auth_methods") or [])
                target_row["existing_auth_methods"] = methods
                target_row["auth_configured"] = bool(provider.get("auth_configured"))
                target_row["subscription_auth_supported"] = bool(provider.get("subscription_auth_supported"))
                target_row["subscription_auth_configured"] = bool(provider.get("subscription_auth_configured"))
                subscription_profile = provider.get("subscription_auth") if isinstance(provider.get("subscription_auth"), dict) else {}
                if subscription_profile and "subscription" in required_auth:
                    target_row["external_command"] = subscription_profile.get("external_command", target_row.get("external_command"))
                    target_row["external_status_command"] = subscription_profile.get("external_status_command", target_row.get("external_status_command"))
                    target_row["external_login_instruction"] = subscription_profile.get("external_login_instruction", target_row.get("external_login_instruction"))
                    target_row["invocation_bridge"] = subscription_profile.get("invocation_bridge", target_row.get("invocation_bridge"))
                    target_row["bridge_status"] = subscription_profile.get("aegis_bridge_status", "not_implemented")
                    target_row["account_surface"] = subscription_profile.get("account_surface", target_row.get("account_surface"))
                elif handoff_profile is not None:
                    target_row["bridge_status"] = str(handoff_profile.get("aegis_bridge_status") or "official_cli_handoff_only")
                elif provider.get("local"):
                    target_row["bridge_status"] = "not_required_local"
                elif "api_key" in methods:
                    target_row["bridge_status"] = "not_required_api_key"

                if "subscription" in required_auth or "oauth_device" in required_auth or "oauth" in required_auth or "cloud_identity" in required_auth:
                    if "subscription" in required_auth and target_row["subscription_auth_supported"] and target_row["subscription_auth_configured"]:
                        target_row["status"] = "subscription_cli_ready"
                        target_row["bridge_status"] = "official_cli_bridge_ready"
                        target_row["token_captured"] = False
                        target_row["token_capture_supported"] = False
                    elif "subscription" in required_auth and target_row["subscription_auth_supported"]:
                        target_row["status"] = target_row["bridge_status"]
                        bridge_pending.append(str(target["target"]))
                    elif handoff_profile is not None:
                        target_row["status"] = target_row["bridge_status"]
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
            "verified_external_auth_count": len(verified_external),
            "metadata_or_bridge_pending_count": len(bridge_pending),
            "not_started_count": len(not_started),
            "api_key_ready_targets": api_key_ready,
            "local_ready_targets": local_ready,
            "verified_external_auth_targets": verified_external,
            "subscription_bridge_targets": bridge_pending,
            "provider_auth_bridge_targets": bridge_pending,
            "not_started_targets": not_started,
            "implemented_auth_methods": sorted(
                {
                    *{method for row in provider_rows.values() for method in row.get("auth_methods", [])},
                    *{str(profile["method"]) for profile in EXTERNAL_AUTH_HANDOFF_PROFILES.values()},
                }
            ),
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
                "subscription_login_official_cli_handoff",
                "oauth_device_flow_official_cli_handoff",
                "cloud_identity_official_cli_handoff",
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

    def login_provider_subscription(
        self,
        provider_name: str,
        *,
        run_external: bool = False,
        verify_external: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        provider = self._provider(provider_name)
        profile = self._subscription_auth_profile(provider)
        if profile is None:
            raise ValueError(f"provider {provider_name!r} does not support subscription login")
        command_argv = _subscription_command_argv(profile)
        executable_path = shutil.which(command_argv[0]) if command_argv else None
        status = {
            "provider": provider.provider,
            "method": "subscription",
            "status": "external_login_required",
            "auth_configured": False,
            "auth_source": None,
            "token_captured": False,
            "token_capture_supported": False,
            "external_command_argv": list(command_argv),
            "external_command_available": executable_path is not None,
            "external_command_path": executable_path,
            "external_login_attempted": False,
            "external_login_exit_code": None,
            "external_login_error": None,
            **profile,
        }
        if run_external:
            status.update(_run_subscription_login_command(command_argv, timeout_seconds=timeout_seconds))
        if run_external or verify_external:
            status.update(_run_external_status_command(profile, timeout_seconds=timeout_seconds))
            if status.get("external_status_verified"):
                status.update(
                    {
                        "status": "external_login_verified",
                        "auth_configured": True,
                        "auth_source": "subscription_cli",
                        "aegis_bridge_status": "official_cli_bridge_ready",
                        "subscription_auth_configured": True,
                        "token_captured": False,
                        "token_capture_supported": False,
                    }
                )
                invocation_bridge = profile.get("invocation_bridge")
                if isinstance(invocation_bridge, str) and invocation_bridge:
                    status["invocation_bridge"] = invocation_bridge
                self._remember_external_auth_link(provider.provider, "subscription", status)
        self.audit_logger.append(
            "model.auth_subscription_login_requested",
            {
                "provider": provider.provider,
                "method": "subscription",
                "status": status["status"],
                "external_command": status["external_command"],
                "external_login_attempted": status["external_login_attempted"],
                "external_login_exit_code": status["external_login_exit_code"],
                "token_captured": False,
            },
        )
        return status

    def login_provider_external(
        self,
        name: str,
        *,
        method: str,
        run_external: bool = False,
        verify_external: bool = False,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        normalized_method = method.replace("-", "_")
        if normalized_method == "subscription":
            return self.login_provider_subscription(name, run_external=run_external, verify_external=verify_external, timeout_seconds=timeout_seconds)
        profile = _external_auth_handoff_profile_for_login(name, normalized_method)
        if profile is None:
            raise ValueError(f"{method} login is not supported for {name!r}")
        if profile.get("oauth_device_flow") == "minimax_pkce_user_code":
            status = _minimax_oauth_status_template(profile)
            if run_external:
                status.update(_run_minimax_oauth_login_flow(profile, self.secrets_broker, timeout_seconds=timeout_seconds))
            elif verify_external:
                status.update(_verify_minimax_oauth_link(profile, self.secrets_broker, self._external_auth_link(str(profile.get("provider") or name), normalized_method)))
            if status.get("external_status_verified"):
                status.update(
                    {
                        "status": "external_login_verified",
                        "auth_configured": True,
                        "auth_source": "oauth_device_flow",
                        "aegis_bridge_status": "oauth_device_flow_ready",
                        "token_captured": False,
                        "token_capture_supported": False,
                    }
                )
                self._remember_external_auth_link(str(status["provider"]), normalized_method, status)
            self.audit_logger.append(
                "model.auth_external_login_requested",
                {
                    "provider": status["provider"],
                    "target": status["target"],
                    "method": status["method"],
                    "status": status["status"],
                    "external_command": status.get("external_command"),
                    "external_login_attempted": status["external_login_attempted"],
                    "external_login_exit_code": status["external_login_exit_code"],
                    "token_captured": False,
                    "oauth_token_brokered": bool(status.get("oauth_token_brokered", False)),
                },
            )
            return status
        command_argv = _external_command_argv(profile)
        executable_path = shutil.which(command_argv[0]) if command_argv else None
        status = {
            "provider": profile.get("provider") or name,
            "target": profile["target"],
            "method": profile["method"],
            "status": "external_login_required",
            "auth_configured": False,
            "auth_source": None,
            "token_captured": False,
            "token_capture_supported": False,
            "external_command_argv": list(command_argv),
            "external_command_available": executable_path is not None,
            "external_command_path": executable_path,
            "external_login_attempted": False,
            "external_login_exit_code": None,
            "external_login_error": None,
            **_handoff_profile_public_fields(profile),
        }
        if run_external:
            status.update(_run_external_login_command(command_argv, timeout_seconds=timeout_seconds, manual_profile=profile))
        if run_external or verify_external:
            status.update(_run_external_status_command(profile, timeout_seconds=timeout_seconds))
            if status.get("external_status_verified"):
                status.update(
                    {
                        "status": "external_login_verified",
                        "auth_configured": True,
                        "auth_source": "official_cli",
                        "token_captured": False,
                        "token_capture_supported": False,
                    }
                )
                self._remember_external_auth_link(str(status["provider"]), normalized_method, status)
        self.audit_logger.append(
            "model.auth_external_login_requested",
            {
                "provider": status["provider"],
                "target": status["target"],
                "method": status["method"],
                "status": status["status"],
                "external_command": status.get("external_command"),
                "external_login_attempted": status["external_login_attempted"],
                "external_login_exit_code": status["external_login_exit_code"],
                "token_captured": False,
            },
        )
        return status

    def logout_provider(self, provider_name: str) -> dict[str, Any]:
        if provider_name in self.providers:
            provider = self.providers[provider_name]
            if provider.auth_secret is None and not self._external_auth_profiles(provider.provider):
                raise ValueError(f"provider {provider_name!r} does not require model auth")
            removed = self.secrets_broker.delete_secret(provider.auth_secret) if provider.auth_secret is not None else False
            removed_external_links = self._forget_external_auth_links(provider.provider)
            status = self._provider_auth_status(provider)
            audit_provider = provider.provider
            auth_secret = provider.auth_secret
        else:
            profile = _external_auth_handoff_profile(provider_name)
            if profile is None:
                raise KeyError(f"unknown model provider {provider_name!r}")
            audit_provider = str(profile.get("provider") or provider_name)
            auth_secret = None
            removed = False
            removed_external_links = self._forget_external_auth_links(audit_provider)
            status = self._external_auth_status(profile)
        self.audit_logger.append(
            "model.auth_logout",
            {"provider": audit_provider, "auth_secret": auth_secret, "removed_local_secret": removed, "removed_external_auth_links": removed_external_links},
        )
        status["removed_local_secret"] = removed
        status["removed_external_auth_links"] = removed_external_links
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
        auth_method = "none"
        auth_metadata: dict[str, Any] = {}
        if provider.auth_secret:
            if self._api_key_auth_configured(provider):
                secret_handle = self.secrets_broker.request_handle(
                    name=provider.auth_secret,
                    requester=f"model:{provider.provider}",
                    reason="model provider API call",
                    scopes=("model.invoke",),
                )
                secret_handle_id = secret_handle.handle_id
                auth_method = "api_key"
            elif self._subscription_auth_configured(provider):
                auth_method = "subscription_cli"
        if auth_method == "none" and provider.external_auth_method:
            external_link = self._external_auth_link(provider.provider, provider.external_auth_method)
            if external_link is not None:
                auth_metadata = dict(external_link)
                if external_link.get("auth_source") == "oauth_device_flow" or provider.metadata.get("auth_surface") == "oauth_device":
                    auth_method = "oauth_token"
                else:
                    auth_method = f"{provider.external_auth_method}_cli"
        route = ModelRoute(resolved, provider, model, self.fallbacks.get(resolved, ()), secret_handle_id, auth_method, auth_metadata)
        self.audit_logger.append("model.routed", {"identifier": resolved, "fallbacks": list(route.fallback_identifiers), "auth_method": auth_method})
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
        if model not in self.providers[provider_name].models and provider_name not in {"custom", "lmstudio", "azure-foundry", "aws-bedrock", "google", "qwen", "github-copilot"}:
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
        external_auth_links = settings.get("external_auth_links", {}).get("links", {})
        if isinstance(external_auth_links, dict):
            for key, value in external_auth_links.items():
                if not isinstance(value, dict):
                    continue
                method = str(value.get("method") or "")
                provider = str(value.get("provider") or "")
                status = str(value.get("status") or "")
                if not provider or not method or status != "external_login_verified":
                    continue
                self.external_auth_links[str(key)] = dict(value)

    def _persist_routes(self) -> None:
        self.store.set_model_route_setting("aliases", {"aliases": dict(sorted(self.aliases.items()))})
        self.store.set_model_route_setting(
            "fallbacks",
            {"fallbacks": {identifier: list(values) for identifier, values in sorted(self.fallbacks.items())}},
        )

    def _persist_external_auth_links(self) -> None:
        self.store.set_model_route_setting("external_auth_links", {"links": dict(sorted(self.external_auth_links.items()))})

    def _provider_auth_status(self, provider: ModelProviderSpec) -> dict[str, Any]:
        external_profiles = self._external_auth_profiles(provider.provider)
        external_statuses = [self._external_auth_status(profile) for profile in external_profiles]
        return {
            "provider": provider.provider,
            "auth_required": self._auth_required(provider),
            "auth_secret": provider.auth_secret,
            "auth_configured": self._auth_configured(provider),
            "api_key_auth_configured": self._api_key_auth_configured(provider),
            "auth_source": self._auth_source(provider),
            "auth_methods": self._auth_methods(provider),
            "subscription_auth_supported": self._subscription_auth_supported(provider),
            "subscription_auth_configured": self._subscription_auth_configured(provider),
            "subscription_auth": self._subscription_auth_profile(provider),
            "provider_native_auth_methods": [status["method"] for status in external_statuses],
            "provider_native_auth": external_statuses,
            "external_auth_configured": any(bool(status["external_auth_configured"]) for status in external_statuses),
        }

    def _auth_configured(self, provider: ModelProviderSpec) -> bool:
        return self._api_key_auth_configured(provider) or self._subscription_auth_configured(provider) or self._external_auth_configured(provider)

    def _auth_required(self, provider: ModelProviderSpec) -> bool:
        return provider.auth_secret is not None or provider.external_auth_method is not None

    def _api_key_auth_configured(self, provider: ModelProviderSpec) -> bool:
        return provider.auth_secret is not None and self.secrets_broker.has_secret(provider.auth_secret)

    def _auth_source(self, provider: ModelProviderSpec) -> str | None:
        if provider.auth_secret is not None:
            source = self.secrets_broker.secret_source(provider.auth_secret)
            if source is not None:
                return source
        if self._subscription_auth_configured(provider):
            return "subscription_cli"
        external_link = self._external_auth_link(provider.provider, provider.external_auth_method) if provider.external_auth_method else None
        if external_link is not None:
            if external_link.get("auth_source"):
                return str(external_link["auth_source"])
            return "official_cli"
        return None

    def _auth_methods(self, provider: ModelProviderSpec) -> list[str]:
        methods = ["api_key"] if provider.auth_secret is not None else []
        if provider.auth_secret is None and provider.external_auth_method is None:
            methods.append("none")
        if self._subscription_auth_supported(provider):
            methods.append("subscription")
        for profile in self._external_auth_profiles(provider.provider):
            method = str(profile.get("method") or "")
            if method and method not in methods:
                methods.append(method)
        return methods

    def _external_auth_profiles(self, provider_name: str) -> list[dict[str, Any]]:
        return [profile for profile in EXTERNAL_AUTH_HANDOFF_PROFILES.values() if str(profile.get("provider") or "") == provider_name]

    def _external_auth_configured(self, provider: ModelProviderSpec) -> bool:
        if provider.external_auth_method is None:
            return False
        return self._external_auth_link(provider.provider, provider.external_auth_method) is not None

    def _external_auth_status(self, profile: dict[str, Any]) -> dict[str, Any]:
        provider_name = str(profile.get("provider") or "")
        method = str(profile.get("method") or "")
        link = self._external_auth_link(provider_name, method)
        status = {
            "provider": provider_name,
            "target": profile["target"],
            "method": method,
            "status": str(profile.get("aegis_bridge_status") or "official_cli_handoff_only"),
            "auth_configured": False,
            "external_auth_configured": False,
            "auth_source": None,
            "bridge_status": str(profile.get("aegis_bridge_status") or "official_cli_handoff_only"),
            "token_captured": False,
            "token_capture_supported": False,
            **_handoff_profile_public_fields(profile),
        }
        if link is not None:
            status.update(
                {
                    "status": "external_login_verified",
                    "auth_configured": True,
                    "external_auth_configured": True,
                    "auth_source": link.get("auth_source") or "official_cli",
                    "bridge_status": link.get("bridge_status") or "official_cli_link_verified",
                    "external_command": link.get("external_command", status.get("external_command")),
                    "external_status_command": link.get("external_status_command", status.get("external_status_command")),
                    "last_verified_at": link.get("verified_at"),
                    "token_captured": False,
                    "token_capture_supported": False,
                    "oauth_token_brokered": bool(link.get("oauth_token_brokered", False)),
                    "access_token_secret": link.get("access_token_secret"),
                    "refresh_token_secret": link.get("refresh_token_secret"),
                }
            )
        return status

    def _subscription_auth_supported(self, provider: ModelProviderSpec) -> bool:
        return provider.provider in SUBSCRIPTION_AUTH_PROFILES

    def _subscription_auth_profile(self, provider: ModelProviderSpec) -> dict[str, Any] | None:
        profile = SUBSCRIPTION_AUTH_PROFILES.get(provider.provider)
        if profile is None:
            return None
        result = {key: value for key, value in profile.items()}
        command_argv = _subscription_command_argv(result)
        result["external_command_argv"] = list(command_argv)
        result["external_command_available"] = shutil.which(command_argv[0]) is not None if command_argv else False
        link = self._external_auth_link(provider.provider, "subscription")
        if link is not None:
            result.update(
                {
                    "aegis_bridge_status": "official_cli_bridge_ready",
                    "subscription_auth_configured": True,
                    "auth_source": "subscription_cli",
                    "last_verified_at": link.get("verified_at"),
                    "external_status_command": link.get("external_status_command", result.get("external_status_command")),
                    "token_captured": False,
                    "token_capture_supported": False,
                    "invocation_bridge": link.get("invocation_bridge"),
                }
            )
        return result

    def _subscription_auth_configured(self, provider: ModelProviderSpec) -> bool:
        return self._external_auth_link(provider.provider, "subscription") is not None

    def _external_auth_link(self, provider_name: str, method: str) -> dict[str, Any] | None:
        return self.external_auth_links.get(_external_auth_link_key(provider_name, method))

    def _remember_external_auth_link(self, provider_name: str, method: str, status: dict[str, Any]) -> None:
        auth_source = status.get("auth_source") or ("subscription_cli" if method == "subscription" else "official_cli")
        bridge_status = status.get("aegis_bridge_status") if auth_source == "oauth_device_flow" else None
        link = {
            "provider": provider_name,
            "method": method,
            "target": status.get("target"),
            "status": "external_login_verified",
            "auth_source": auth_source,
            "bridge_status": bridge_status or "official_cli_link_verified",
            "external_command": status.get("external_command"),
            "external_status_command": status.get("external_status_command"),
            "verified_at": now_utc(),
            "token_captured": False,
            "token_capture_supported": False,
        }
        for key in (
            "invocation_bridge",
            "portal_base_url",
            "inference_base_url",
            "client_id",
            "scope",
            "token_type",
            "expires_at",
            "expires_in",
            "access_token_secret",
            "refresh_token_secret",
            "refresh_skew_seconds",
            "oauth_token_brokered",
            "raw_browser_token_captured",
        ):
            value = status.get(key)
            if value is not None:
                link[key] = value
        self.external_auth_links[_external_auth_link_key(provider_name, method)] = link
        self._persist_external_auth_links()

    def _forget_external_auth_links(self, provider_name: str) -> int:
        prefix = f"{_normalize_auth_key(provider_name)}:"
        matching = [key for key in self.external_auth_links if key.startswith(prefix)]
        for key in matching:
            self.external_auth_links.pop(key, None)
        if matching:
            self._persist_external_auth_links()
        return len(matching)


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


MINIMAX_OAUTH_CLIENT_ID = "78257093-7e40-4613-99e0-527b14b39113"
MINIMAX_OAUTH_SCOPE = "group_id profile model.completion"
MINIMAX_OAUTH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:user_code"
MINIMAX_OAUTH_PORTAL_BASE_URL = "https://api.minimax.io"
MINIMAX_OAUTH_INFERENCE_BASE_URL = "https://api.minimax.io/anthropic/v1"
MINIMAX_OAUTH_ACCESS_TOKEN_SECRET = "MINIMAX_OAUTH_ACCESS_TOKEN"
MINIMAX_OAUTH_REFRESH_TOKEN_SECRET = "MINIMAX_OAUTH_REFRESH_TOKEN"
MINIMAX_OAUTH_REFRESH_SKEW_SECONDS = 60


EXTERNAL_AUTH_HANDOFF_PROFILES: dict[str, dict[str, Any]] = {
    "github-copilot": {
        "target": "GitHub Copilot",
        "aliases": ("github", "github-copilot", "copilot"),
        "provider": "github-copilot",
        "method": "oauth_device",
        "account_surface": "GitHub Copilot subscription",
        "external_command": "copilot login",
        "external_command_argv": ("copilot", "login"),
        "external_status_command": "copilot -p \"Respond with OK only.\" --output-format=json --mode=plan --no-remote --no-custom-instructions --disable-builtin-mcps --no-ask-user --silent --stream=off --log-level=none",
        "external_status_command_argv": (
            "copilot",
            "-p",
            "Respond with OK only.",
            "--output-format=json",
            "--mode=plan",
            "--no-remote",
            "--no-custom-instructions",
            "--disable-builtin-mcps",
            "--no-ask-user",
            "--silent",
            "--stream=off",
            "--log-level=none",
        ),
        "provider_token_source": "official GitHub Copilot CLI credential store or GitHub CLI fallback token",
        "aegis_bridge_status": "official_cli_bridge_available",
        "interactive": True,
        "next_steps": [
            "Run model auth login github-copilot --method oauth-device --run-external or sign in with copilot login directly.",
            "Route github-copilot/<model-id> after verification to use isolated copilot -p JSON invocation.",
            "Do not paste GitHub OAuth tokens or Copilot session tokens into Aegis.",
        ],
    },
    "aws-bedrock": {
        "target": "AWS Bedrock",
        "aliases": ("aws", "aws-bedrock", "bedrock"),
        "provider": "aws-bedrock",
        "method": "cloud_identity",
        "account_surface": "AWS IAM Identity Center / Bedrock",
        "external_command": "aws sso login",
        "external_command_argv": ("aws", "sso", "login"),
        "external_status_command": "aws sts get-caller-identity",
        "external_status_command_argv": ("aws", "sts", "get-caller-identity"),
        "setup_required": "aws configure sso",
        "provider_token_source": "official AWS CLI SSO cache",
        "aegis_bridge_status": "official_cli_bridge_available",
        "interactive": True,
        "next_steps": [
            "Configure an AWS SSO profile with aws configure sso before running the handoff.",
            "Use model auth login aws-bedrock --method cloud-identity --run-external from a local terminal, then verify with the non-secret AWS CLI identity status check.",
            "Do not paste AWS SSO cache entries, access keys, or session tokens into Aegis.",
        ],
    },
    "azure-foundry": {
        "target": "Azure Foundry",
        "aliases": ("azure", "azure-foundry", "azure-ai-foundry"),
        "provider": "azure-foundry",
        "method": "cloud_identity",
        "account_surface": "Azure AI Foundry",
        "external_command": "az login",
        "external_command_argv": ("az", "login"),
        "external_status_command": "az account show",
        "external_status_command_argv": ("az", "account", "show"),
        "provider_token_source": "official Azure CLI token cache",
        "aegis_bridge_status": "official_cli_bridge_available",
        "interactive": True,
        "next_steps": [
            "Run model auth login azure-foundry --method cloud-identity --run-external from a local terminal.",
            "Do not paste Azure access tokens into Aegis.",
        ],
    },
    "google-vertex": {
        "target": "Google Vertex AI / Gemini cloud identity",
        "aliases": ("google", "google-cloud", "google-vertex", "vertex-ai", "google-adc"),
        "provider": "google",
        "method": "cloud_identity",
        "account_surface": "Google Cloud / Vertex AI",
        "external_command": "gcloud auth login --update-adc",
        "external_command_argv": ("gcloud", "auth", "login", "--update-adc"),
        "external_status_command": "gcloud auth list --filter=status:ACTIVE --format=value(account)",
        "external_status_command_argv": ("gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"),
        "provider_token_source": "official Google Cloud CLI credential and ADC stores",
        "aegis_bridge_status": "official_cli_bridge_available",
        "interactive": True,
        "next_steps": [
            "Run model auth login google --method cloud-identity --run-external from a local terminal to use the official gcloud account flow and update Application Default Credentials.",
            "Configure models.google_vertex_project and models.google_vertex_location, then route google/<model-id> after verifying the official gcloud account flow.",
            "Do not paste Google OAuth access tokens, refresh tokens, ADC JSON, or browser session cookies into Aegis.",
        ],
    },
    "qwen-oauth": {
        "target": "Qwen OAuth (discontinued)",
        "aliases": ("qwen-oauth", "dashscope-oauth"),
        "provider": "qwen",
        "method": "oauth",
        "account_surface": "Qwen Code / Alibaba Cloud Coding Plan",
        "external_command": None,
        "provider_token_source": "official Qwen Code auth store",
        "aegis_bridge_status": "provider_discontinued",
        "interactive": True,
        "next_steps": [
            "Qwen Code OAuth free-tier access was discontinued on 2026-04-15; use model auth login qwen --subscription for Alibaba Cloud Coding Plan instead.",
            "Use DASHSCOPE_API_KEY for direct Aegis live Qwen calls, or verify the official Qwen Code Coding Plan subscription bridge.",
        ],
    },
    "nous-oauth": {
        "target": "Nous Portal OAuth subscription",
        "aliases": ("nous-oauth", "nous-portal"),
        "provider": "nous",
        "method": "oauth",
        "account_surface": "Nous Portal",
        "external_command": None,
        "aegis_bridge_status": "manual_provider_handoff_only",
        "interactive": True,
        "next_steps": [
            "Sign in through the Nous Portal and use NOUS_API_KEY for Aegis live model calls.",
            "Aegis does not yet import Nous OAuth refresh tokens.",
        ],
    },
    "minimax-oauth": {
        "target": "MiniMax OAuth",
        "aliases": ("minimax-oauth", "minimax-portal", "minimax-global"),
        "provider": "minimax-oauth",
        "method": "oauth",
        "account_surface": "MiniMax",
        "external_command": "MiniMax browser OAuth",
        "oauth_device_flow": "minimax_pkce_user_code",
        "portal_base_url": MINIMAX_OAUTH_PORTAL_BASE_URL,
        "inference_base_url": MINIMAX_OAUTH_INFERENCE_BASE_URL,
        "client_id": MINIMAX_OAUTH_CLIENT_ID,
        "scope": MINIMAX_OAUTH_SCOPE,
        "access_token_secret": MINIMAX_OAUTH_ACCESS_TOKEN_SECRET,
        "refresh_token_secret": MINIMAX_OAUTH_REFRESH_TOKEN_SECRET,
        "refresh_skew_seconds": MINIMAX_OAUTH_REFRESH_SKEW_SECONDS,
        "aegis_bridge_status": "oauth_device_flow_available",
        "invocation_bridge": "minimax_oauth_anthropic_compatible",
        "provider_token_source": "official MiniMax OAuth device-code flow",
        "interactive": True,
        "next_steps": [
            "Run model auth login minimax-oauth --method oauth --run-external and approve the MiniMax browser/device-code prompt.",
            "Route minimax-oauth/MiniMax-M2.7 after verification to use the brokered MiniMax OAuth bridge.",
            "Do not paste MiniMax browser cookies, access tokens, refresh tokens, or portal session values into Aegis.",
        ],
    },
}


SUBSCRIPTION_AUTH_PROFILES: dict[str, dict[str, Any]] = {
    "openai": {
        "account_surface": "ChatGPT / Codex",
        "external_command": "codex login",
        "external_command_argv": ("codex", "login"),
        "external_status_command": "codex login status",
        "external_status_command_argv": ("codex", "login", "status"),
        "requires": "ChatGPT account with Codex access",
        "provider_token_source": "official Codex CLI auth store",
        "aegis_bridge_status": "official_cli_bridge_available",
        "invocation_bridge": "codex_exec",
        "interactive": True,
        "next_steps": [
            "Run model auth login openai --subscription --run-external or sign in with the official Codex CLI directly, then use --verify-external to record the non-secret bridge link.",
            "Use model auth login openai --api-key-stdin for direct OpenAI HTTP calls, or use the verified subscription bridge for isolated codex exec invocation.",
            "Do not paste ChatGPT session cookies or browser tokens into Aegis.",
        ],
    },
    "anthropic": {
        "account_surface": "claude.ai / Claude Code",
        "external_command": "claude auth login",
        "external_command_argv": ("claude", "auth", "login"),
        "external_status_command": "claude auth status",
        "external_status_command_argv": ("claude", "auth", "status"),
        "external_login_instruction": "/login",
        "requires": "claude.ai account with Claude Code access; Remote Control requires full-scope claude.ai login, not API key auth",
        "provider_token_source": "official Claude Code auth store",
        "aegis_bridge_status": "official_cli_bridge_available",
        "invocation_bridge": "claude_print",
        "interactive": True,
        "next_steps": [
            "Run model auth login anthropic --subscription --run-external or sign in with Claude Code directly, then use --verify-external to record the non-secret bridge link.",
            "Use model auth login anthropic --api-key-stdin for direct Anthropic HTTP calls, or use the verified subscription bridge for isolated claude -p invocation.",
            "Do not paste claude.ai browser session tokens into Aegis.",
        ],
    },
    "qwen": {
        "account_surface": "Alibaba Cloud Coding Plan / Qwen Code",
        "external_command": "qwen auth coding-plan",
        "external_command_argv": ("qwen", "auth", "coding-plan"),
        "external_status_command": "qwen auth status",
        "external_status_command_argv": ("qwen", "auth", "status"),
        "external_login_instruction": "/auth",
        "requires": "Alibaba Cloud Coding Plan subscription configured in the official Qwen Code CLI",
        "provider_token_source": "official Qwen Code auth store",
        "aegis_bridge_status": "official_cli_bridge_available",
        "invocation_bridge": "qwen_headless_json",
        "interactive": True,
        "next_steps": [
            "Run model auth login qwen --subscription --run-external or sign in with qwen auth coding-plan directly, then use --verify-external to record the non-secret bridge link.",
            "Use model auth login qwen --api-key-stdin for direct DashScope HTTP calls, or use the verified subscription bridge for isolated qwen headless invocation.",
            "Do not paste Qwen OAuth tokens, Coding Plan API keys, or Qwen settings.json contents into Aegis.",
        ],
    },
    "google": {
        "account_surface": "Google Gemini CLI / Gemini Code Assist",
        "external_command": "gemini",
        "external_command_argv": ("gemini",),
        "external_status_command": 'gemini -p "Respond with OK only." --output-format=json --approval-mode=plan --sandbox --skip-trust',
        "external_status_command_argv": (
            "gemini",
            "-p",
            "Respond with OK only.",
            "--output-format=json",
            "--approval-mode=plan",
            "--sandbox",
            "--skip-trust",
        ),
        "external_login_instruction": "/auth",
        "requires": "Google account or Gemini Code Assist entitlement configured in the official Gemini CLI",
        "provider_token_source": "official Gemini CLI credential store",
        "aegis_bridge_status": "official_cli_bridge_available",
        "invocation_bridge": "gemini_prompt_json",
        "interactive": True,
        "next_steps": [
            "Run model auth login google --subscription --run-external or sign in with gemini directly and use /auth, then use --verify-external to record the non-secret bridge link.",
            "Use model auth login google --api-key-stdin for direct Gemini API calls, gcloud cloud identity for Vertex AI, or the verified Gemini CLI bridge for isolated gemini -p invocation.",
            "Do not paste Google OAuth access tokens, refresh tokens, ADC JSON, or browser session cookies into Aegis.",
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
        "external_login_instruction": "/login",
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
        "aegis_provider": "github-copilot",
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
        "target": "Google Vertex AI / Gemini cloud identity",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "google",
        "required_auth": ("cloud_identity",),
        "account_surface": "Google Cloud / Vertex AI",
    },
    {
        "target": "Google Gemini CLI subscription",
        "platforms": ("Hermes Agent", "Gemini CLI parity"),
        "aegis_provider": "google",
        "required_auth": ("subscription",),
        "external_command": "gemini",
        "external_login_instruction": "/auth",
        "account_surface": "Google Gemini CLI / Gemini Code Assist",
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
        "aegis_provider": "minimax-oauth",
        "required_auth": ("oauth",),
        "account_surface": "MiniMax",
    },
    {
        "target": "MiniMax Token Plan",
        "platforms": ("Hermes Agent", "MiniMax Token Plan"),
        "aegis_provider": "minimax-token-plan",
        "required_auth": ("api_key",),
        "account_surface": "MiniMax Token Plan",
    },
    {
        "target": "AWS Bedrock",
        "platforms": ("Hermes Agent",),
        "aegis_provider": None,
        "required_auth": ("cloud_identity",),
        "account_surface": "AWS IAM / Bedrock",
    },
    {
        "target": "Azure Foundry API key",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "azure-foundry",
        "required_auth": ("api_key",),
        "account_surface": "Azure AI Foundry",
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
        "target": "Qwen Code Coding Plan subscription",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "qwen",
        "required_auth": ("subscription",),
        "external_command": "qwen auth coding-plan",
        "external_login_instruction": "/auth",
        "account_surface": "Alibaba Cloud Coding Plan / Qwen Code",
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


def _subscription_command_argv(profile: dict[str, Any]) -> tuple[str, ...]:
    return _external_command_argv(profile)


def _external_command_argv(profile: dict[str, Any]) -> tuple[str, ...]:
    raw_argv = profile.get("external_command_argv")
    if isinstance(raw_argv, (tuple, list)) and raw_argv and all(isinstance(item, str) and item for item in raw_argv):
        return tuple(raw_argv)
    command = str(profile.get("external_command") or "").strip()
    if not command:
        return ()
    return tuple(shlex.split(command))


def _external_status_command_argv(profile: dict[str, Any]) -> tuple[str, ...]:
    raw_argv = profile.get("external_status_command_argv")
    if isinstance(raw_argv, (tuple, list)) and raw_argv and all(isinstance(item, str) and item for item in raw_argv):
        return tuple(raw_argv)
    command = str(profile.get("external_status_command") or "").strip()
    if not command:
        return ()
    return tuple(shlex.split(command))


def _minimax_oauth_status_template(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": profile.get("provider") or "minimax-oauth",
        "target": profile["target"],
        "method": profile["method"],
        "status": "external_login_required",
        "auth_configured": False,
        "auth_source": None,
        "token_captured": False,
        "token_capture_supported": False,
        "raw_browser_token_captured": False,
        "oauth_token_brokered": False,
        "external_command_argv": [],
        "external_command_available": True,
        "external_command_path": None,
        "external_login_attempted": False,
        "external_login_exit_code": None,
        "external_login_error": None,
        "external_status_checked": False,
        "external_status_verified": False,
        **_handoff_profile_public_fields(profile),
    }


def _run_minimax_oauth_login_flow(profile: dict[str, Any], secrets_broker: SecretsBroker, *, timeout_seconds: float | None) -> dict[str, Any]:
    portal_base_url = str(profile.get("portal_base_url") or MINIMAX_OAUTH_PORTAL_BASE_URL).rstrip("/")
    client_id = str(profile.get("client_id") or MINIMAX_OAUTH_CLIENT_ID)
    verifier, challenge, state = _minimax_pkce_pair()
    try:
        code_payload = _minimax_request_user_code(portal_base_url=portal_base_url, client_id=client_id, code_challenge=challenge, state=state, timeout_seconds=timeout_seconds)
        verification_uri = str(code_payload["verification_uri"])
        user_code = str(code_payload["user_code"])
        print(f"MiniMax OAuth: open {verification_uri} and enter code {user_code}", file=sys.stderr)
        token_payload = _minimax_poll_token(
            portal_base_url=portal_base_url,
            client_id=client_id,
            user_code=user_code,
            code_verifier=verifier,
            expired_in=int(code_payload["expired_in"]),
            interval_ms=int(code_payload.get("interval") or 2000),
            timeout_seconds=timeout_seconds,
        )
    except TimeoutError as exc:
        return {
            "status": "external_login_timeout",
            "external_login_attempted": True,
            "external_login_exit_code": None,
            "external_login_error": str(exc),
            "external_status_checked": False,
            "external_status_verified": False,
        }
    except (RuntimeError, ValueError, OSError) as exc:
        return {
            "status": "external_login_failed",
            "external_login_attempted": True,
            "external_login_exit_code": None,
            "external_login_error": str(exc),
            "external_status_checked": True,
            "external_status_verified": False,
        }

    access_token = str(token_payload.get("access_token") or "").strip()
    refresh_token = str(token_payload.get("refresh_token") or "").strip()
    if not access_token or not refresh_token:
        return {
            "status": "external_login_failed",
            "external_login_attempted": True,
            "external_login_exit_code": None,
            "external_login_error": "MiniMax OAuth token response did not include brokerable tokens",
            "external_status_checked": True,
            "external_status_verified": False,
        }
    access_secret = str(profile.get("access_token_secret") or MINIMAX_OAUTH_ACCESS_TOKEN_SECRET)
    refresh_secret = str(profile.get("refresh_token_secret") or MINIMAX_OAUTH_REFRESH_TOKEN_SECRET)
    secrets_broker.store_secret(name=access_secret, value=access_token)
    secrets_broker.store_secret(name=refresh_secret, value=refresh_token)
    now = datetime.now(timezone.utc)
    expires_at = _minimax_resolve_token_expiry(int(token_payload["expired_in"]), now=now)
    return {
        "status": "external_login_verified",
        "auth_configured": True,
        "auth_source": "oauth_device_flow",
        "aegis_bridge_status": "oauth_device_flow_ready",
        "external_login_attempted": True,
        "external_login_exit_code": 0,
        "external_login_error": None,
        "external_status_checked": True,
        "external_status_verified": True,
        "token_captured": False,
        "token_capture_supported": False,
        "raw_browser_token_captured": False,
        "oauth_token_brokered": True,
        "access_token_secret": access_secret,
        "refresh_token_secret": refresh_secret,
        "portal_base_url": portal_base_url,
        "inference_base_url": str(profile.get("inference_base_url") or MINIMAX_OAUTH_INFERENCE_BASE_URL).rstrip("/"),
        "client_id": client_id,
        "scope": str(profile.get("scope") or MINIMAX_OAUTH_SCOPE),
        "token_type": str(token_payload.get("token_type") or "Bearer"),
        "expires_at": expires_at.isoformat(),
        "expires_in": max(0, int(expires_at.timestamp() - now.timestamp())),
        "refresh_skew_seconds": int(profile.get("refresh_skew_seconds") or MINIMAX_OAUTH_REFRESH_SKEW_SECONDS),
        "invocation_bridge": str(profile.get("invocation_bridge") or "minimax_oauth_anthropic_compatible"),
    }


def _verify_minimax_oauth_link(profile: dict[str, Any], secrets_broker: SecretsBroker, link: dict[str, Any] | None) -> dict[str, Any]:
    access_secret = str((link or {}).get("access_token_secret") or profile.get("access_token_secret") or MINIMAX_OAUTH_ACCESS_TOKEN_SECRET)
    refresh_secret = str((link or {}).get("refresh_token_secret") or profile.get("refresh_token_secret") or MINIMAX_OAUTH_REFRESH_TOKEN_SECRET)
    verified = link is not None and secrets_broker.has_secret(access_secret) and secrets_broker.has_secret(refresh_secret)
    return {
        "external_status_checked": True,
        "external_status_verified": verified,
        "status": "external_login_verified" if verified else "external_login_required",
        "auth_configured": verified,
        "auth_source": "oauth_device_flow" if verified else None,
        "aegis_bridge_status": "oauth_device_flow_ready" if verified else "oauth_device_flow_available",
        "oauth_token_brokered": verified,
        "access_token_secret": access_secret,
        "refresh_token_secret": refresh_secret,
        **{key: value for key, value in (link or {}).items() if key in {"portal_base_url", "inference_base_url", "client_id", "scope", "token_type", "expires_at", "expires_in", "refresh_skew_seconds", "invocation_bridge"}},
    }


def _minimax_pkce_pair() -> tuple[str, str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    state = secrets.token_urlsafe(16)
    return verifier, challenge, state


def _minimax_request_user_code(*, portal_base_url: str, client_id: str, code_challenge: str, state: str, timeout_seconds: float | None) -> dict[str, Any]:
    payload = _post_auth_form(
        f"{portal_base_url}/oauth/code",
        {
            "response_type": "code",
            "client_id": client_id,
            "scope": MINIMAX_OAUTH_SCOPE,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        },
        timeout_seconds=timeout_seconds,
    )
    for field in ("user_code", "verification_uri", "expired_in"):
        if field not in payload:
            raise RuntimeError(f"MiniMax OAuth response missing field: {field}")
    if payload.get("state") != state:
        raise RuntimeError("MiniMax OAuth state mismatch")
    return payload


def _minimax_poll_token(
    *,
    portal_base_url: str,
    client_id: str,
    user_code: str,
    code_verifier: str,
    expired_in: int,
    interval_ms: int,
    timeout_seconds: float | None,
) -> dict[str, Any]:
    now = time.time()
    deadline = min(_minimax_expiry_deadline(expired_in, now=now), now + (timeout_seconds or 300.0))
    interval = max(2.0, interval_ms / 1000.0)
    while time.time() < deadline:
        payload = _post_auth_form(
            f"{portal_base_url}/oauth/token",
            {
                "grant_type": MINIMAX_OAUTH_GRANT_TYPE,
                "client_id": client_id,
                "user_code": user_code,
                "code_verifier": code_verifier,
            },
            timeout_seconds=timeout_seconds,
        )
        status = payload.get("status")
        if status == "success":
            return payload
        if status == "error":
            raise RuntimeError("MiniMax OAuth authorization was denied")
        time.sleep(interval)
    raise TimeoutError("MiniMax OAuth timed out before authorization completed")


def _post_auth_form(url: str, data: dict[str, str], *, timeout_seconds: float | None) -> dict[str, Any]:
    request = Request(
        url,
        data=urlencode(data).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        with _open_auth_request(request, timeout=timeout_seconds or 30.0) as response:  # noqa: S310 - URL is fixed provider OAuth metadata.
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"MiniMax OAuth HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"MiniMax OAuth connection failed: {exc.reason}") from exc
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise RuntimeError("MiniMax OAuth returned invalid JSON")
    return decoded


def _minimax_expiry_deadline(expired_in: int, *, now: float) -> float:
    raw = int(expired_in)
    now_ms = int(now * 1000)
    if raw > (now_ms // 2):
        return raw / 1000.0
    return now + max(1, raw)


def _minimax_resolve_token_expiry(expired_in: int, *, now: datetime) -> datetime:
    return datetime.fromtimestamp(_minimax_expiry_deadline(expired_in, now=now.timestamp()), tz=timezone.utc)


def _open_auth_request(request: Request, *, timeout: float):
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
            return None

    return build_opener(NoRedirect).open(request, timeout=timeout)


def _run_subscription_login_command(command_argv: tuple[str, ...], *, timeout_seconds: float | None) -> dict[str, Any]:
    return _run_external_login_command(command_argv, timeout_seconds=timeout_seconds)


def _run_external_login_command(command_argv: tuple[str, ...], *, timeout_seconds: float | None, manual_profile: dict[str, Any] | None = None) -> dict[str, Any]:
    if not command_argv:
        manual = manual_profile is not None and manual_profile.get("aegis_bridge_status") == "manual_provider_handoff_only"
        return {
            "status": "external_login_manual_required" if manual else "external_command_unavailable",
            "external_command_available": False,
            "external_command_path": None,
            "external_login_attempted": False,
            "external_login_exit_code": None,
            "external_login_error": "provider requires manual browser/account handoff" if manual else "auth profile has no external command",
        }
    executable_path = shutil.which(command_argv[0])
    if executable_path is None:
        return {
            "status": "external_command_unavailable",
            "external_command_available": False,
            "external_command_path": None,
            "external_login_attempted": False,
            "external_login_exit_code": None,
            "external_login_error": f"executable not found: {command_argv[0]}",
        }
    try:
        completed = subprocess.run(command_argv, timeout=timeout_seconds, check=False)  # noqa: S603 - argv is a hardcoded provider login command.
    except subprocess.TimeoutExpired:
        return {
            "status": "external_login_timeout",
            "external_command_available": True,
            "external_command_path": executable_path,
            "external_login_attempted": True,
            "external_login_exit_code": None,
            "external_login_error": "external login command timed out",
        }
    except OSError as exc:
        return {
            "status": "external_login_failed",
            "external_command_available": True,
            "external_command_path": executable_path,
            "external_login_attempted": True,
            "external_login_exit_code": None,
            "external_login_error": str(exc),
        }
    return {
        "status": "external_login_completed_unverified" if completed.returncode == 0 else "external_login_failed",
        "external_command_available": True,
        "external_command_path": executable_path,
        "external_login_attempted": True,
        "external_login_exit_code": completed.returncode,
        "external_login_error": None if completed.returncode == 0 else f"external login command exited with {completed.returncode}",
    }


def _run_external_status_command(profile: dict[str, Any], *, timeout_seconds: float | None) -> dict[str, Any]:
    command_argv = _external_status_command_argv(profile)
    if not command_argv:
        return {
            "external_status_checked": False,
            "external_status_verified": False,
            "external_status_command_argv": [],
            "external_status_command_available": False,
            "external_status_exit_code": None,
            "external_status_error": "auth profile has no status command",
        }
    executable_path = shutil.which(command_argv[0])
    if executable_path is None:
        return {
            "external_status_checked": False,
            "external_status_verified": False,
            "external_status_command_argv": list(command_argv),
            "external_status_command_available": False,
            "external_status_exit_code": None,
            "external_status_error": f"executable not found: {command_argv[0]}",
        }
    cwd: str | None = None
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    try:
        if command_argv[0] == "gemini":
            temp_dir = tempfile.TemporaryDirectory(prefix="aegis-gemini-auth-status-")
            cwd = temp_dir.name
        completed = subprocess.run(
            command_argv,
            timeout=timeout_seconds,
            check=False,
            capture_output=True,
            text=True,
            env=_external_status_env(command_argv),
            cwd=cwd,
        )  # noqa: S603 - argv is a hardcoded provider status command.
    except subprocess.TimeoutExpired:
        return {
            "external_status_checked": True,
            "external_status_verified": False,
            "external_status_command_argv": list(command_argv),
            "external_status_command_available": True,
            "external_status_exit_code": None,
            "external_status_error": "external status command timed out",
        }
    except OSError as exc:
        return {
            "external_status_checked": True,
            "external_status_verified": False,
            "external_status_command_argv": list(command_argv),
            "external_status_command_available": True,
            "external_status_exit_code": None,
            "external_status_error": str(exc),
        }
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()
    return {
        "external_status_checked": True,
        "external_status_verified": completed.returncode == 0,
        "external_status_command_argv": list(command_argv),
        "external_status_command_available": True,
        "external_status_exit_code": completed.returncode,
        "external_status_error": None if completed.returncode == 0 else f"external status command exited with {completed.returncode}",
    }


def _external_status_env(command_argv: tuple[str, ...]) -> dict[str, str] | None:
    if not command_argv or command_argv[0] != "copilot":
        return None
    env = os.environ.copy()
    env["COPILOT_AUTO_UPDATE"] = "false"
    env["COPILOT_ALLOW_ALL"] = "false"
    env["GITHUB_COPILOT_PROMPT_MODE_EXTENSIONS"] = "false"
    env["GITHUB_COPILOT_PROMPT_MODE_REPO_HOOKS"] = "false"
    env["GITHUB_COPILOT_PROMPT_MODE_WORKSPACE_MCP"] = "false"
    return env


def _external_auth_handoff_profile(target: str) -> dict[str, Any] | None:
    normalized_target = _normalize_auth_key(target)
    for profile in EXTERNAL_AUTH_HANDOFF_PROFILES.values():
        aliases = {_normalize_auth_key(str(alias)) for alias in profile.get("aliases", ())}
        aliases.add(_normalize_auth_key(str(profile.get("target") or "")))
        if normalized_target in aliases:
            return profile
    return None


def _external_auth_handoff_profile_for_login(name: str, method: str) -> dict[str, Any] | None:
    normalized_name = _normalize_auth_key(name)
    normalized_method = method.replace("-", "_")
    for profile in EXTERNAL_AUTH_HANDOFF_PROFILES.values():
        if str(profile.get("method")) != normalized_method:
            continue
        aliases = {_normalize_auth_key(str(alias)) for alias in profile.get("aliases", ())}
        aliases.add(_normalize_auth_key(str(profile.get("target") or "")))
        aliases.add(_normalize_auth_key(str(profile.get("provider") or "")))
        if normalized_name in aliases:
            return profile
    return None


def _handoff_profile_public_fields(profile: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "account_surface",
        "external_command",
        "external_status_command",
        "external_login_instruction",
        "setup_required",
        "provider_token_source",
        "aegis_bridge_status",
        "oauth_device_flow",
        "portal_base_url",
        "inference_base_url",
        "client_id",
        "scope",
        "access_token_secret",
        "refresh_token_secret",
        "refresh_skew_seconds",
        "invocation_bridge",
        "interactive",
        "next_steps",
    }
    result = {key: value for key, value in profile.items() if key in allowed and value is not None}
    command_argv = _external_command_argv(profile)
    result["external_command_argv"] = list(command_argv)
    result["external_command_available"] = shutil.which(command_argv[0]) is not None if command_argv else False
    if profile.get("oauth_device_flow"):
        result["external_command_argv"] = []
        result["external_command_available"] = True
    return result


def _normalize_auth_key(value: str) -> str:
    return value.lower().replace("_", "-").replace(" ", "-").strip()


def _external_auth_link_key(provider_name: str, method: str) -> str:
    return f"{_normalize_auth_key(provider_name)}:{method.replace('-', '_')}"


def default_providers(
    *,
    custom_base_url: str | None = None,
    azure_foundry_base_url: str | None = None,
    google_vertex_project: str | None = None,
    google_vertex_location: str | None = None,
) -> dict[str, ModelProviderSpec]:
    providers = (
        ModelProviderSpec("openai", ("gpt-4o", "gpt-4o-mini", "o1", "o3", "o3-mini"), "OPENAI_API_KEY", "https://api.openai.com/v1", False, True, True, True, 2.5, 10.0, 128000, "openai"),
        ModelProviderSpec("anthropic", ("claude-opus", "claude-sonnet-4.6", "claude-haiku"), "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1", False, True, True, False, 3.0, 15.0, 200000, "anthropic"),
        ModelProviderSpec(
            "google",
            ("gemini-pro", "gemini-flash", "gemini-2.5-pro", "gemini-3-pro-preview", "gemini-2.5-flash", "gemini-2.5-flash-lite"),
            "GOOGLE_API_KEY",
            "https://generativelanguage.googleapis.com/v1beta",
            False,
            True,
            True,
            True,
            1.25,
            5.0,
            1000000,
            "google",
            "cloud_identity",
            {"vertex_project": google_vertex_project, "vertex_location": google_vertex_location},
        ),
        ModelProviderSpec("mistral", ("mistral-large", "mistral-medium", "mistral-small", "codestral"), "MISTRAL_API_KEY", "https://api.mistral.ai/v1", False, True, False, False, 2.0, 6.0, 32000, "mistral"),
        ModelProviderSpec("cohere", ("command-r-plus", "command-r"), "COHERE_API_KEY", "https://api.cohere.com/v2", False, True, False, False, 3.0, 15.0, 128000, "cohere"),
        ModelProviderSpec("openrouter", ("anthropic/claude-sonnet-4.6", "openai/gpt-4o", "meta-llama/llama-3.1-70b"), "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", False, True, True, True, 0.0, 0.0, 128000, "openrouter"),
        ModelProviderSpec("nous", ("Hermes-4-405B", "Hermes-4-70B"), "NOUS_API_KEY", "https://inference-api.nousresearch.com/v1", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("deepseek", ("deepseek-v4-flash", "deepseek-v4-pro", "deepseek-chat", "deepseek-reasoner"), "DEEPSEEK_API_KEY", "https://api.deepseek.com", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("xai", ("grok-4.20-reasoning", "grok-4", "grok-4-fast"), "XAI_API_KEY", "https://api.x.ai/v1", False, True, True, False, 0.0, 0.0, 256000, "openai_compatible"),
        ModelProviderSpec("kimi", ("kimi-k2.5", "kimi-k2-turbo-preview", "kimi-k2-thinking"), "KIMI_API_KEY", "https://api.moonshot.ai/v1", False, True, True, False, 0.0, 0.0, 256000, "openai_compatible"),
        ModelProviderSpec("minimax", ("MiniMax-M2.7", "MiniMax-M2.5", "MiniMax-M2"), "MINIMAX_API_KEY", "https://api.minimax.io/v1", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec(
            "minimax-oauth",
            ("MiniMax-M2.7", "MiniMax-M2.7-highspeed"),
            None,
            MINIMAX_OAUTH_INFERENCE_BASE_URL,
            False,
            True,
            False,
            False,
            0.0,
            0.0,
            204800,
            "anthropic",
            "oauth",
            {
                "auth_surface": "oauth_device",
                "compatibility": "anthropic_messages",
                "portal_base_url": MINIMAX_OAUTH_PORTAL_BASE_URL,
                "client_id": MINIMAX_OAUTH_CLIENT_ID,
                "scope": MINIMAX_OAUTH_SCOPE,
                "access_token_secret": MINIMAX_OAUTH_ACCESS_TOKEN_SECRET,
                "refresh_token_secret": MINIMAX_OAUTH_REFRESH_TOKEN_SECRET,
                "refresh_skew_seconds": MINIMAX_OAUTH_REFRESH_SKEW_SECONDS,
            },
        ),
        ModelProviderSpec(
            "minimax-token-plan",
            ("MiniMax-M2.7", "MiniMax-M2.7-highspeed", "MiniMax-M2.5", "MiniMax-M2.5-highspeed", "MiniMax-M2.1", "MiniMax-M2.1-highspeed", "MiniMax-M2"),
            "MINIMAX_TOKEN_PLAN_API_KEY",
            "https://api.minimax.io/anthropic/v1",
            False,
            True,
            False,
            False,
            0.0,
            0.0,
            204800,
            "anthropic",
            metadata={"auth_surface": "token_plan", "compatibility": "anthropic_messages"},
        ),
        ModelProviderSpec("zai", ("glm-5.1", "glm-5", "glm-4.7", "glm-4.6", "glm-4.5"), "GLM_API_KEY", "https://api.z.ai/api/paas/v4", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("qwen", ("qwen-plus", "qwen-max", "qwen-turbo"), "DASHSCOPE_API_KEY", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("azure-foundry", ("*",), "AZURE_OPENAI_API_KEY", azure_foundry_base_url, False, True, True, True, 0.0, 0.0, 128000, "openai_compatible", "cloud_identity"),
        ModelProviderSpec("aws-bedrock", ("*",), None, None, False, True, True, False, 0.0, 0.0, 200000, "bedrock_converse", "cloud_identity"),
        ModelProviderSpec("github-copilot", ("gpt-5.1-codex", "gpt-5.1", "gpt-4.1"), None, None, False, True, False, False, 0.0, 0.0, 200000, "openai_compatible", "oauth_device"),
        ModelProviderSpec("ollama", ("llama3", "llama3.1", "mistral", "mixtral", "phi3", "gemma2", "codellama", "deepseek-coder"), None, "http://localhost:11434", True, False, context_window_tokens=8192, tokenizer_profile="llama"),
        ModelProviderSpec("lmstudio", ("local",), None, "http://localhost:1234/v1", True, False, context_window_tokens=8192, tokenizer_profile="openai_compatible"),
        ModelProviderSpec("custom", ("*",), "CUSTOM_API_KEY", custom_base_url, False, True, context_window_tokens=8192, tokenizer_profile="openai_compatible"),
    )
    return {provider.provider: provider for provider in providers}
