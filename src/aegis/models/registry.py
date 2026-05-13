"""Model-agnostic provider registry with aliases, fallbacks, and usage tracking."""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import shlex
import shutil
import secrets
import subprocess
import tempfile
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4
import webbrowser

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import now_utc
from aegis.storage.state import ensure_private_dir, ensure_private_file


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


DYNAMIC_MODEL_ID_PROVIDERS = {
    "custom",
    "lmstudio",
    "azure-foundry",
    "aws-bedrock",
    "google",
    "google-gemini-oauth",
    "qwen",
    "github-copilot",
    "arcee",
    "gmi",
    "nvidia",
    "ai-gateway",
    "opencode-zen",
    "opencode-go",
    "kilocode",
    "huggingface",
    "xiaomi",
    "tencent-tokenhub",
    "ollama-cloud",
    "alibaba-coding-plan",
}


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
        login_required: list[str] = []
        implementation_gaps: list[str] = []
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
                        "agent_key_brokered": bool(external_status.get("agent_key_brokered", False)),
                    }
                )
                for key in (
                    "access_token_secret",
                    "refresh_token_secret",
                    "agent_key_secret",
                    "agent_key_expires_at",
                    "agent_key_min_ttl_seconds",
                    "portal_base_url",
                    "inference_base_url",
                    "invocation_bridge",
                ):
                    if external_status.get(key) is not None:
                        target_row[key] = external_status[key]
                verified_external.append(str(target["target"]))
                targets.append(target_row)
                continue
            if provider is None:
                if handoff_profile is not None:
                    target_row["status"] = target_row["bridge_status"]
                    login_required.append(str(target["target"]))
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
                        login_required.append(str(target["target"]))
                    elif handoff_profile is not None:
                        target_row["status"] = target_row["bridge_status"]
                        login_required.append(str(target["target"]))
                    else:
                        target_row["status"] = "provider_native_auth_bridge_required"
                        implementation_gaps.append(str(target["target"]))
                elif provider.get("local") or "none" in methods:
                    target_row["status"] = "local_ready"
                    local_ready.append(str(target["target"]))
                elif "api_key" in required_auth and "api_key" in methods:
                    target_row["status"] = "api_key_ready"
                    api_key_ready.append(str(target["target"]))
                else:
                    target_row["status"] = "auth_surface_incomplete"
                    implementation_gaps.append(str(target["target"]))
            targets.append(target_row)

        missing_or_pending = len(implementation_gaps) + len(not_started)
        return {
            "status": "target_surface_ready" if missing_or_pending == 0 else "auth_parity_gap_tracked",
            "target_provider_count": len(targets),
            "aegis_provider_count": len(provider_rows),
            "api_key_ready_count": len(api_key_ready),
            "local_ready_count": len(local_ready),
            "verified_external_auth_count": len(verified_external),
            "metadata_or_bridge_pending_count": len(login_required),
            "operator_login_required_count": len(login_required),
            "implementation_gap_count": len(implementation_gaps),
            "not_started_count": len(not_started),
            "api_key_ready_targets": api_key_ready,
            "local_ready_targets": local_ready,
            "verified_external_auth_targets": verified_external,
            "subscription_bridge_targets": login_required,
            "provider_auth_bridge_targets": implementation_gaps,
            "operator_login_required_targets": login_required,
            "implementation_gap_targets": implementation_gaps,
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

    def auth_doctor(self) -> dict[str, Any]:
        targets = self.auth_targets()
        checks: list[dict[str, Any]] = []
        missing_commands: list[str] = []
        verified_targets = set(targets.get("verified_external_auth_targets") or [])
        activation_state_counts: dict[str, int] = {}
        for row in targets["targets"]:
            required = list(row.get("required_auth") or [])
            method = next(
                (
                    candidate
                    for candidate in ("subscription", "oauth_device", "oauth", "cloud_identity")
                    if candidate in required
                ),
                None,
            )
            if method is None:
                continue
            target = str(row.get("target") or "")
            login_name = str(row.get("aegis_provider") or row.get("provider") or _normalize_auth_key(target))
            command_argv = row.get("external_command_argv") if isinstance(row.get("external_command_argv"), list) else []
            if not command_argv and row.get("status") == "official_cli_bridge_available":
                command = str(row.get("external_command") or "").strip()
                if command:
                    command_argv = shlex.split(command)
            executable = command_argv[0] if command_argv else None
            command_available = bool(row.get("external_command_available", False))
            if executable:
                command_available = shutil.which(str(executable)) is not None
            login_flag = "--subscription" if method == "subscription" else f"--method {method.replace('_', '-')}"
            verified = target in verified_targets or bool(row.get("auth_configured") and row.get("external_auth_configured"))
            activation = self._auth_activation_preflight(row, method=method, verified=verified, command_available=command_available)
            activation_state = str(activation["activation_state"])
            activation_state_counts[activation_state] = activation_state_counts.get(activation_state, 0) + 1
            check = {
                "target": target,
                "provider": login_name,
                "method": method,
                "status": row.get("status"),
                "verified": verified,
                "activation_state": activation_state,
                "activation": activation,
                "external_command": row.get("external_command"),
                "external_command_argv": command_argv,
                "external_command_available": command_available,
                "setup_required": row.get("setup_required"),
                "login_command": f"PYTHONPATH=src python3 -m aegis.cli.main model auth login {login_name} {login_flag} --run-external",
                "verify_command": f"PYTHONPATH=src python3 -m aegis.cli.main model auth login {login_name} {login_flag} --verify-external",
                "token_captured": False,
                "raw_secret_values_included": False,
            }
            if not verified and executable and not command_available:
                missing_commands.append(str(executable))
            checks.append(check)
        pending = [check["target"] for check in checks if not check["verified"]]
        return {
            "status": "ready" if not pending else "operator_login_required",
            "target_provider_count": targets["target_provider_count"],
            "checked_login_target_count": len(checks),
            "verified_external_auth_count": targets["verified_external_auth_count"],
            "operator_login_required_count": len(pending),
            "operator_login_required_targets": pending,
            "missing_external_commands": sorted(set(missing_commands)),
            "activation_state_counts": activation_state_counts,
            "implementation_gap_count": targets["implementation_gap_count"],
            "raw_secret_values_included": False,
            "checks": checks,
            "next_steps": [
                "Run the listed login_command entries from a local terminal for providers you want active on this PC.",
                "Use verify_command after signing in directly with an official provider CLI.",
                "Do not paste browser cookies, OAuth tokens, refresh tokens, CLI credential files, or subscription session values into Aegis.",
            ],
        }

    def create_auth_readiness_packet(self, *, actor: str = "operator") -> dict[str, Any]:
        packet_id = str(uuid4())
        created_at = now_utc()
        data_dir = Path(self.store.database_path).parent
        packet_dir = ensure_private_dir(data_dir / "model-auth-readiness-packets")
        packet_path = ensure_private_file(packet_dir / f"{packet_id}.json")
        checksum_path = ensure_private_file(packet_dir / f"{packet_id}.sha256")
        packet = _model_auth_readiness_packet(
            packet_id=packet_id,
            actor=actor,
            created_at=created_at,
            targets=self.auth_targets(),
            doctor=self.auth_doctor(),
        )
        packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        packet_path.chmod(0o600)
        artifact_sha256 = hashlib.sha256(packet_path.read_bytes()).hexdigest()
        checksum_path.write_text(f"{artifact_sha256}\n", encoding="utf-8")
        checksum_path.chmod(0o600)
        receipt = {
            "receipt_schema": "aegis.model.auth_readiness_packet.v1",
            "event_type": "model.auth_readiness_packet_created",
            "packet_id": packet_id,
            "actor": _model_auth_safe_text(actor, limit=80),
            "artifact": str(packet_path),
            "artifact_sha256": artifact_sha256,
            "checksum": str(checksum_path),
            "checksum_sha256": hashlib.sha256(checksum_path.read_bytes()).hexdigest(),
            "status": packet["status"],
            "target_provider_count": packet["target_provider_count"],
            "checked_login_target_count": packet["checked_login_target_count"],
            "operator_login_required_count": packet["operator_login_required_count"],
            "implementation_gap_count": packet["implementation_gap_count"],
            "raw_secret_values_included": False,
            "raw_token_values_included": False,
            "model_invocation_performed": False,
            "created_at": created_at,
        }
        audit_entry = self.audit_logger.append("model.auth_readiness_packet_created", receipt)
        return {
            "ok": True,
            "packet": packet,
            "receipt": receipt,
            "audit_event_hash": audit_entry["event_hash"],
        }

    def verify_auth_readiness_packet(self, packet: str, *, actor: str = "operator") -> dict[str, Any]:
        packet_path, checksum_path = _model_auth_readiness_packet_paths(Path(self.store.database_path).parent, packet)
        packet_bytes = packet_path.read_bytes()
        artifact_sha256 = hashlib.sha256(packet_bytes).hexdigest()
        checksum_value = checksum_path.read_text(encoding="utf-8").strip() if checksum_path.exists() else ""
        try:
            decoded = json.loads(packet_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = {}
        packet_payload = decoded if isinstance(decoded, dict) else {}
        controls = packet_payload.get("controls") if isinstance(packet_payload.get("controls"), dict) else {}
        checks = packet_payload.get("checks") if isinstance(packet_payload.get("checks"), list) else []
        checksum_matches = bool(checksum_value) and checksum_value == artifact_sha256
        packet_schema_valid = packet_payload.get("packet_schema") == "aegis.model.auth_readiness_packet.v1"
        controls_valid = _model_auth_readiness_controls_valid(controls)
        checks_valid = _model_auth_readiness_checks_valid(packet_payload, checks)
        forbidden_keys_present = _model_auth_readiness_forbidden_keys_present(packet_payload)
        receipt = {
            "receipt_schema": "aegis.model.auth_readiness_packet_verification.v1",
            "event_type": "model.auth_readiness_packet_verified",
            "packet_id": str(packet_payload.get("packet_id") or packet_path.stem),
            "actor": _model_auth_safe_text(actor, limit=80),
            "artifact": str(packet_path),
            "artifact_sha256": artifact_sha256,
            "checksum": str(checksum_path),
            "checksum_present": bool(checksum_value),
            "checksum_matches": checksum_matches,
            "packet_schema_valid": packet_schema_valid,
            "controls_valid": controls_valid,
            "checks_valid": checks_valid,
            "forbidden_raw_keys_present": forbidden_keys_present,
            "packet_integrity_ok": bool(packet_schema_valid and checksum_matches and controls_valid and checks_valid and not forbidden_keys_present),
            "raw_secret_values_included": False,
            "raw_token_values_included": False,
            "raw_packet_payload_included": False,
            "model_invocation_performed": False,
            "verified_at": now_utc(),
        }
        audit_entry = self.audit_logger.append("model.auth_readiness_packet_verified", receipt)
        return {
            "ok": bool(receipt["packet_integrity_ok"]),
            "packet": _model_auth_readiness_packet_summary(packet_payload),
            "receipt": receipt,
            "audit_event_hash": audit_entry["event_hash"],
        }

    def _auth_activation_preflight(self, row: dict[str, Any], *, method: str, verified: bool, command_available: bool) -> dict[str, Any]:
        target = str(row.get("target") or "")
        provider_name = str(row.get("provider") or row.get("aegis_provider") or "")
        provider = self.providers.get(provider_name)
        configured_controls = ["raw_token_capture_denied", "secret_redaction"]
        blockers: list[dict[str, str]] = []
        required_config: list[str] = []
        missing_config: list[str] = []
        configured_config: list[str] = []
        if command_available or row.get("oauth_device_flow"):
            configured_controls.append("official_login_handoff")
        else:
            blockers.append({"control": "official_login_handoff", "detail": "official provider login command is not available on this machine"})
        if verified:
            configured_controls.append("external_login_verified")
        else:
            blockers.append({"control": "local_operator_login", "detail": "run the listed login and verification commands from a local terminal"})
        if method == "cloud_identity" and target == "Google Vertex AI / Gemini cloud identity":
            required_config.extend(["models.google_vertex_project", "models.google_vertex_location"])
            metadata = provider.metadata if provider is not None else {}
            if str(metadata.get("vertex_project") or "").strip():
                configured_config.append("models.google_vertex_project")
            else:
                missing_config.append("models.google_vertex_project")
            if str(metadata.get("vertex_location") or "").strip():
                configured_config.append("models.google_vertex_location")
            else:
                missing_config.append("models.google_vertex_location")
        if method == "cloud_identity" and target == "Azure Foundry":
            required_config.append("models.azure_foundry_base_url")
            if provider is not None and provider.base_url:
                configured_config.append("models.azure_foundry_base_url")
            else:
                missing_config.append("models.azure_foundry_base_url")
        for config_key in missing_config:
            blockers.append({"control": "config_required", "detail": f"{config_key} must be configured before invocation"})
        if missing_config:
            activation_state = "verified_but_invocation_blocked" if verified else "config_required"
        elif verified:
            activation_state = "verified_ready"
        else:
            activation_state = "login_required"
        return {
            "activation_state": activation_state,
            "final_ready": activation_state == "verified_ready",
            "required_controls": ["official_provider_login_flow", "local_operator_verification", "no_raw_token_import"],
            "configured_controls": configured_controls,
            "required_config": required_config,
            "configured_config": configured_config,
            "missing_config": missing_config,
            "blockers": blockers,
            "invocation_bridge": row.get("invocation_bridge"),
            "raw_secret_values_included": False,
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
        if profile.get("oauth_device_flow") == "nous_device_code":
            status = _nous_oauth_status_template(profile)
            if run_external:
                status.update(_run_nous_oauth_login_flow(profile, self.secrets_broker, timeout_seconds=timeout_seconds))
            elif verify_external:
                status.update(_verify_nous_oauth_link(profile, self.secrets_broker, self._external_auth_link(str(profile.get("provider") or name), normalized_method)))
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
                    "agent_key_brokered": bool(status.get("agent_key_brokered", False)),
                },
            )
            return status
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
        if profile.get("oauth_device_flow") == "github_copilot_device_code":
            status = _github_copilot_oauth_status_template(profile)
            if run_external:
                status.update(_run_github_copilot_oauth_login_flow(profile, self.secrets_broker, timeout_seconds=timeout_seconds))
            elif verify_external:
                status.update(_verify_github_copilot_oauth_link(profile, self.secrets_broker, self._external_auth_link(str(profile.get("provider") or name), normalized_method)))
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
        if profile.get("oauth_device_flow") == "google_gemini_pkce":
            status = _google_gemini_oauth_status_template(profile)
            if run_external:
                status.update(_run_google_gemini_oauth_login_flow(profile, self.secrets_broker, timeout_seconds=timeout_seconds))
            elif verify_external:
                status.update(_verify_google_gemini_oauth_link(profile, self.secrets_broker, self._external_auth_link(str(profile.get("provider") or name), normalized_method)))
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
        if self._subscription_auth_configured(provider):
            auth_method = "subscription_cli"
        if auth_method == "none" and provider.external_auth_method:
            external_link = self._external_auth_link(provider.provider, provider.external_auth_method)
            if external_link is not None:
                auth_metadata = dict(external_link)
                if external_link.get("auth_source") == "oauth_device_flow":
                    auth_method = "oauth_token"
                else:
                    auth_method = f"{provider.external_auth_method}_cli"
        if auth_method == "none" and provider.auth_secret and self._api_key_auth_configured(provider):
            secret_handle = self.secrets_broker.request_handle(
                name=provider.auth_secret,
                requester=f"model:{provider.provider}",
                reason="model provider API call",
                scopes=("model.invoke",),
            )
            secret_handle_id = secret_handle.handle_id
            auth_method = "api_key"
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

    def usage_insights(self, *, days: int = 30) -> dict[str, Any]:
        window_days = max(1, int(days))
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        rows = [row for row in self.store.list_model_usage(limit=10000) if _usage_created_at(row) >= cutoff]
        total_cost = sum(float(row["estimated_cost"]) for row in rows)
        total_input = sum(int(row["input_tokens"]) for row in rows)
        total_output = sum(int(row["output_tokens"]) for row in rows)
        by_provider: dict[str, dict[str, Any]] = {}
        by_model: dict[str, dict[str, Any]] = {}
        by_day: dict[str, dict[str, Any]] = {}
        for row in rows:
            provider = str(row["provider"])
            model_key = f"{provider}/{row['model']}"
            _accumulate_usage(by_provider, provider, row)
            _accumulate_usage(by_model, model_key, row)
            day_key = _usage_created_at(row).date().isoformat()
            _accumulate_usage(by_day, day_key, row)
        top_provider = _top_usage_bucket(by_provider)
        top_model = _top_usage_bucket(by_model)
        busiest_day = _top_usage_bucket(by_day)
        total_tokens = total_input + total_output
        return {
            "status": "usage_insights",
            "window_days": window_days,
            "events": len(rows),
            "input_tokens": total_input,
            "output_tokens": total_output,
            "total_tokens": total_tokens,
            "estimated_cost": round(total_cost, 6),
            "avg_events_per_day": round(len(rows) / window_days, 3),
            "avg_tokens_per_day": round(total_tokens / window_days, 2),
            "top_provider": top_provider,
            "top_model": top_model,
            "busiest_day": busiest_day,
            "by_provider": list(by_provider.values()),
            "by_model": list(by_model.values()),
            "by_day": list(sorted(by_day.values(), key=lambda row: row["key"], reverse=True)),
            "recent_events": [_usage_event_summary(row) for row in rows[:10]],
            "raw_metadata_values_included": False,
        }

    def _split_identifier(self, identifier: str) -> tuple[str, str]:
        if "/" not in identifier:
            raise ValueError("model identifier must be provider/model")
        provider_name, model = identifier.split("/", 1)
        if provider_name not in self.providers:
            raise KeyError(f"unknown model provider {provider_name!r}")
        if model not in self.providers[provider_name].models and provider_name not in DYNAMIC_MODEL_ID_PROVIDERS:
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
        if self._subscription_auth_configured(provider):
            return "subscription_cli"
        external_link = self._external_auth_link(provider.provider, provider.external_auth_method) if provider.external_auth_method else None
        if external_link is not None:
            if external_link.get("auth_source"):
                return str(external_link["auth_source"])
            return "official_cli"
        if provider.auth_secret is not None:
            source = self.secrets_broker.secret_source(provider.auth_secret)
            if source is not None:
                return source
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
                    "agent_key_brokered": bool(link.get("agent_key_brokered", False)),
                    "access_token_secret": link.get("access_token_secret"),
                    "refresh_token_secret": link.get("refresh_token_secret"),
                    "agent_key_secret": link.get("agent_key_secret"),
                    "agent_key_expires_at": link.get("agent_key_expires_at"),
                    "inference_base_url": link.get("inference_base_url", status.get("inference_base_url")),
                    "invocation_bridge": link.get("invocation_bridge", status.get("invocation_bridge")),
                    "project_id": link.get("project_id"),
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
            "agent_key_secret",
            "agent_key_expires_at",
            "agent_key_expires_in",
            "agent_key_min_ttl_seconds",
            "refresh_skew_seconds",
            "oauth_token_brokered",
            "agent_key_brokered",
            "raw_browser_token_captured",
            "project_id",
        ):
            value = status.get(key)
            if value is not None:
                link[key] = value
        self.external_auth_links[_external_auth_link_key(provider_name, method)] = link
        self._persist_external_auth_links()

    def record_external_auth_metadata(self, route: ModelRoute, updates: dict[str, Any]) -> bool:
        method = str(route.auth_metadata.get("method") or route.provider.external_auth_method or "")
        if not method:
            return False
        link = self._external_auth_link(route.provider.provider, method)
        if link is None:
            return False
        allowed_keys = {
            "expires_at",
            "expires_in",
            "agent_key_expires_at",
            "agent_key_expires_in",
            "project_id",
        }
        applied: dict[str, Any] = {}
        for key in allowed_keys:
            value = updates.get(key)
            if value is None:
                continue
            link[key] = value
            route.auth_metadata[key] = value
            applied[key] = value
        if not applied:
            return False
        link["metadata_updated_at"] = now_utc()
        self._persist_external_auth_links()
        self.audit_logger.append(
            "model.auth_external_metadata_updated",
            {
                "provider": route.provider.provider,
                "method": method,
                "metadata_keys": sorted(applied),
                "raw_secret_values_included": False,
            },
        )
        return True

    def _forget_external_auth_links(self, provider_name: str) -> int:
        prefix = f"{_normalize_auth_key(provider_name)}:"
        matching = [key for key in self.external_auth_links if key.startswith(prefix)]
        for key in matching:
            self.external_auth_links.pop(key, None)
        if matching:
            self._persist_external_auth_links()
        return len(matching)


_MODEL_AUTH_PACKET_FALSE_CONTROLS = (
    "raw_secret_values_included",
    "raw_token_values_included",
    "browser_cookie_import_allowed",
    "credential_file_import_allowed",
    "model_invocation_performed",
)

_MODEL_AUTH_PACKET_TRUE_CONTROLS = (
    "official_provider_login_flow_required",
    "local_operator_verification_required",
    "secret_broker_storage_required",
    "provider_domain_allowlist_required",
)


def _model_auth_readiness_packet(*, packet_id: str, actor: str, created_at: str, targets: dict[str, Any], doctor: dict[str, Any]) -> dict[str, Any]:
    checks = [_model_auth_readiness_check_summary(check) for check in doctor.get("checks", []) if isinstance(check, dict)]
    return {
        "packet_schema": "aegis.model.auth_readiness_packet.v1",
        "packet_id": packet_id,
        "created_at": created_at,
        "actor": _model_auth_safe_text(actor, limit=80),
        "taint": "MODEL_AUTH_READINESS_METADATA",
        "status": doctor.get("status"),
        "target_provider_count": int(targets.get("target_provider_count") or 0),
        "checked_login_target_count": len(checks),
        "verified_external_auth_count": int(targets.get("verified_external_auth_count") or 0),
        "operator_login_required_count": int(doctor.get("operator_login_required_count") or 0),
        "operator_login_required_targets": [_model_auth_safe_text(item, limit=120) for item in doctor.get("operator_login_required_targets", [])],
        "missing_external_commands": [_model_auth_safe_text(item, limit=80) for item in doctor.get("missing_external_commands", [])],
        "activation_state_counts": dict(doctor.get("activation_state_counts") or {}),
        "implementation_gap_count": int(targets.get("implementation_gap_count") or 0),
        "required_controls": list(targets.get("required_controls") or []),
        "verification_gates": list(targets.get("verification_gates") or []),
        "checks": checks,
        "controls": {
            **{control: False for control in _MODEL_AUTH_PACKET_FALSE_CONTROLS},
            **{control: True for control in _MODEL_AUTH_PACKET_TRUE_CONTROLS},
        },
        "next_steps": [_model_auth_safe_text(item, limit=300) for item in doctor.get("next_steps", [])],
    }


def _model_auth_readiness_check_summary(check: dict[str, Any]) -> dict[str, Any]:
    activation = check.get("activation") if isinstance(check.get("activation"), dict) else {}
    blockers = activation.get("blockers") if isinstance(activation.get("blockers"), list) else []
    command_argv = check.get("external_command_argv") if isinstance(check.get("external_command_argv"), list) else []
    return {
        "target": _model_auth_safe_text(check.get("target"), limit=160),
        "provider": _model_auth_safe_text(check.get("provider"), limit=80),
        "method": _model_auth_safe_text(check.get("method"), limit=40),
        "status": _model_auth_safe_text(check.get("status"), limit=80),
        "verified": bool(check.get("verified", False)),
        "activation_state": _model_auth_safe_text(check.get("activation_state"), limit=80),
        "external_command_name": _model_auth_safe_text(command_argv[0] if command_argv else "", limit=80),
        "external_command_available": bool(check.get("external_command_available", False)),
        "setup_required": _model_auth_safe_text(check.get("setup_required"), limit=160) if check.get("setup_required") else None,
        "login_command": _model_auth_safe_text(check.get("login_command"), limit=320),
        "verify_command": _model_auth_safe_text(check.get("verify_command"), limit=320),
        "token_captured": False,
        "raw_secret_values_included": False,
        "activation": {
            "activation_state": _model_auth_safe_text(activation.get("activation_state"), limit=80),
            "final_ready": bool(activation.get("final_ready", False)),
            "required_controls": list(activation.get("required_controls") or []),
            "configured_controls": list(activation.get("configured_controls") or []),
            "required_config": list(activation.get("required_config") or []),
            "configured_config": list(activation.get("configured_config") or []),
            "missing_config": list(activation.get("missing_config") or []),
            "blocker_controls": [_model_auth_safe_text(blocker.get("control"), limit=80) for blocker in blockers if isinstance(blocker, dict)],
            "invocation_bridge": _model_auth_safe_text(activation.get("invocation_bridge"), limit=120) if activation.get("invocation_bridge") else None,
            "raw_secret_values_included": False,
        },
    }


def _model_auth_readiness_packet_paths(data_dir: Path, packet: str) -> tuple[Path, Path]:
    packet_dir = ensure_private_dir(data_dir / "model-auth-readiness-packets")
    packet_ref = str(packet or "").strip()
    if not packet_ref:
        raise ValueError("model auth readiness packet id or path is required")
    candidate = Path(packet_ref)
    packet_path = candidate if candidate.is_absolute() or candidate.parent != Path(".") else packet_dir / (packet_ref if packet_ref.endswith(".json") else f"{packet_ref}.json")
    resolved_dir = packet_dir.resolve()
    resolved_packet = packet_path.resolve()
    try:
        resolved_packet.relative_to(resolved_dir)
    except ValueError as exc:
        raise ValueError("model auth readiness packet path must stay inside the private model auth packet directory") from exc
    if resolved_packet.suffix != ".json":
        raise ValueError("model auth readiness packet artifact must be a .json file")
    if not resolved_packet.exists():
        raise FileNotFoundError(str(resolved_packet))
    return resolved_packet, resolved_packet.with_suffix(".sha256")


def _model_auth_readiness_controls_valid(controls: dict[str, Any]) -> bool:
    expected = {*_MODEL_AUTH_PACKET_FALSE_CONTROLS, *_MODEL_AUTH_PACKET_TRUE_CONTROLS}
    if set(controls) != expected:
        return False
    return all(controls.get(control) is False for control in _MODEL_AUTH_PACKET_FALSE_CONTROLS) and all(
        controls.get(control) is True for control in _MODEL_AUTH_PACKET_TRUE_CONTROLS
    )


def _model_auth_readiness_checks_valid(packet: dict[str, Any], checks: list[Any]) -> bool:
    if packet.get("checked_login_target_count") != len(checks):
        return False
    pending = 0
    for check in checks:
        if not isinstance(check, dict):
            return False
        if check.get("token_captured") is not False or check.get("raw_secret_values_included") is not False:
            return False
        if check.get("method") not in {"subscription", "oauth_device", "oauth", "cloud_identity"}:
            return False
        activation = check.get("activation") if isinstance(check.get("activation"), dict) else {}
        if activation.get("raw_secret_values_included") is not False:
            return False
        required_controls = set(str(item) for item in activation.get("required_controls") or [])
        if not {"official_provider_login_flow", "local_operator_verification", "no_raw_token_import"}.issubset(required_controls):
            return False
        if check.get("verified") is not True:
            pending += 1
    return packet.get("operator_login_required_count") == pending


def _model_auth_readiness_packet_summary(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "packet_schema": packet.get("packet_schema"),
        "packet_id": packet.get("packet_id"),
        "created_at": packet.get("created_at"),
        "status": packet.get("status"),
        "target_provider_count": packet.get("target_provider_count"),
        "checked_login_target_count": packet.get("checked_login_target_count"),
        "verified_external_auth_count": packet.get("verified_external_auth_count"),
        "operator_login_required_count": packet.get("operator_login_required_count"),
        "implementation_gap_count": packet.get("implementation_gap_count"),
        "missing_external_commands": list(packet.get("missing_external_commands") or []),
        "activation_state_counts": dict(packet.get("activation_state_counts") or {}),
        "raw_secret_values_included": False,
        "raw_token_values_included": False,
        "model_invocation_performed": False,
    }


def _model_auth_readiness_forbidden_keys_present(value: Any) -> bool:
    forbidden = {
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "raw_api_key",
        "client_secret",
        "session_cookie",
        "browser_cookie",
        "cookie",
        "credential_file",
        "adc_json",
        "raw_secret",
        "secret_value",
    }
    allowed_false_keys = {
        "raw_secret_values_included",
        "raw_token_values_included",
        "token_captured",
        "model_invocation_performed",
        "browser_cookie_import_allowed",
        "credential_file_import_allowed",
    }
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = str(key)
            if normalized_key in allowed_false_keys and item is not False:
                return True
            if normalized_key not in allowed_false_keys and (normalized_key in forbidden or normalized_key.startswith("raw_")):
                return True
            if _model_auth_readiness_forbidden_keys_present(item):
                return True
    if isinstance(value, list):
        return any(_model_auth_readiness_forbidden_keys_present(item) for item in value)
    return False


def _model_auth_safe_text(value: Any, *, limit: int) -> str:
    text = str(value or "")
    sanitized = "".join(ch if ch.isprintable() else " " for ch in text).strip()
    if len(sanitized) > limit:
        return sanitized[: limit - 3] + "..."
    return sanitized


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


def _top_usage_bucket(bucket: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not bucket:
        return None
    return max(bucket.values(), key=lambda row: (int(row["input_tokens"]) + int(row["output_tokens"]), int(row["events"]), str(row["key"])))


def _usage_created_at(row: dict[str, Any]) -> datetime:
    raw = str(row.get("created_at") or "").strip()
    if not raw:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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


NOUS_OAUTH_PORTAL_BASE_URL = "https://portal.nousresearch.com"
NOUS_OAUTH_INFERENCE_BASE_URL = "https://inference-api.nousresearch.com/v1"
NOUS_OAUTH_CLIENT_ID = "hermes-cli"
NOUS_OAUTH_SCOPE = "inference:mint_agent_key"
NOUS_OAUTH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
NOUS_OAUTH_ACCESS_TOKEN_SECRET = "NOUS_OAUTH_ACCESS_TOKEN"
NOUS_OAUTH_REFRESH_TOKEN_SECRET = "NOUS_OAUTH_REFRESH_TOKEN"
NOUS_OAUTH_AGENT_KEY_SECRET = "NOUS_OAUTH_AGENT_KEY"
NOUS_OAUTH_REFRESH_SKEW_SECONDS = 120
NOUS_OAUTH_AGENT_KEY_MIN_TTL_SECONDS = 30 * 60
NOUS_DEVICE_AUTH_POLL_INTERVAL_CAP_SECONDS = 1

MINIMAX_OAUTH_CLIENT_ID = "78257093-7e40-4613-99e0-527b14b39113"
MINIMAX_OAUTH_SCOPE = "group_id profile model.completion"
MINIMAX_OAUTH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:user_code"
MINIMAX_OAUTH_PORTAL_BASE_URL = "https://api.minimax.io"
MINIMAX_OAUTH_INFERENCE_BASE_URL = "https://api.minimax.io/anthropic/v1"
MINIMAX_OAUTH_ACCESS_TOKEN_SECRET = "MINIMAX_OAUTH_ACCESS_TOKEN"
MINIMAX_OAUTH_REFRESH_TOKEN_SECRET = "MINIMAX_OAUTH_REFRESH_TOKEN"
MINIMAX_OAUTH_REFRESH_SKEW_SECONDS = 60

GITHUB_COPILOT_OAUTH_CLIENT_ID = "Ov23li8tweQw6odWQebz"
GITHUB_COPILOT_OAUTH_SCOPE = "read:user"
GITHUB_COPILOT_OAUTH_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
GITHUB_COPILOT_OAUTH_PORTAL_BASE_URL = "https://github.com"
GITHUB_COPILOT_OAUTH_TOKEN_SECRET = "GITHUB_COPILOT_OAUTH_TOKEN"
GITHUB_COPILOT_DEVICE_AUTH_POLL_INTERVAL_CAP_SECONDS = 1

GOOGLE_GEMINI_OAUTH_CLIENT_ID_ENV = "AEGIS_GOOGLE_GEMINI_OAUTH_CLIENT_ID"
GOOGLE_GEMINI_OAUTH_CLIENT_SECRET_ENV = "AEGIS_GOOGLE_GEMINI_OAUTH_CLIENT_SECRET"
GOOGLE_GEMINI_OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
GOOGLE_GEMINI_OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_GEMINI_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN_SECRET = "GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN"
GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN_SECRET = "GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN"
GOOGLE_GEMINI_OAUTH_REFRESH_SKEW_SECONDS = 60
GOOGLE_GEMINI_CLOUDCODE_BASE_URL = "https://cloudcode-pa.googleapis.com"
GOOGLE_GEMINI_OAUTH_REDIRECT_HOST = "127.0.0.1"
GOOGLE_GEMINI_OAUTH_REDIRECT_PORT = 8085
GOOGLE_GEMINI_OAUTH_CALLBACK_PATH = "/oauth2callback"


EXTERNAL_AUTH_HANDOFF_PROFILES: dict[str, dict[str, Any]] = {
    "github-copilot": {
        "target": "GitHub Copilot",
        "aliases": ("github", "github-copilot", "copilot"),
        "provider": "github-copilot",
        "method": "oauth_device",
        "account_surface": "GitHub Copilot subscription",
        "external_command": "GitHub browser OAuth device-code login",
        "external_command_argv": (),
        "external_status_command": "brokered GitHub Copilot OAuth token",
        "external_status_command_argv": (),
        "provider_token_source": "official GitHub OAuth device-code flow for Copilot",
        "aegis_bridge_status": "oauth_device_flow_available",
        "oauth_device_flow": "github_copilot_device_code",
        "portal_base_url": GITHUB_COPILOT_OAUTH_PORTAL_BASE_URL,
        "client_id": GITHUB_COPILOT_OAUTH_CLIENT_ID,
        "scope": GITHUB_COPILOT_OAUTH_SCOPE,
        "access_token_secret": GITHUB_COPILOT_OAUTH_TOKEN_SECRET,
        "invocation_bridge": "copilot_oauth_chat_completions",
        "interactive": True,
        "next_steps": [
            "Run model auth login github-copilot --method oauth-device --run-external and approve the GitHub device-code prompt.",
            "Route github-copilot/<model-id> after verification to use the brokered Copilot OAuth chat-completions bridge.",
            "Do not paste GitHub OAuth tokens, Copilot session tokens, or GitHub CLI credential files into Aegis.",
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
    "google-gemini-oauth": {
        "target": "Google Gemini OAuth / Code Assist",
        "aliases": ("google-gemini-oauth", "gemini-oauth", "google-gemini-cli", "gemini-cli"),
        "provider": "google-gemini-oauth",
        "method": "oauth",
        "account_surface": "Google Gemini CLI / Code Assist OAuth",
        "external_command": "Google browser OAuth PKCE login",
        "external_command_argv": (),
        "external_status_command": "brokered Google Gemini OAuth token",
        "external_status_command_argv": (),
        "oauth_device_flow": "google_gemini_pkce",
        "portal_base_url": "https://accounts.google.com",
        "inference_base_url": GOOGLE_GEMINI_CLOUDCODE_BASE_URL,
        "client_id_env": GOOGLE_GEMINI_OAUTH_CLIENT_ID_ENV,
        "client_secret_env": GOOGLE_GEMINI_OAUTH_CLIENT_SECRET_ENV,
        "scope": GOOGLE_GEMINI_OAUTH_SCOPE,
        "access_token_secret": GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN_SECRET,
        "refresh_token_secret": GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN_SECRET,
        "refresh_skew_seconds": GOOGLE_GEMINI_OAUTH_REFRESH_SKEW_SECONDS,
        "aegis_bridge_status": "oauth_device_flow_available",
        "invocation_bridge": "google_gemini_cloudcode_generate_content",
        "provider_token_source": "official Google Gemini CLI desktop OAuth PKCE flow",
        "setup_required": f"set {GOOGLE_GEMINI_OAUTH_CLIENT_ID_ENV} and {GOOGLE_GEMINI_OAUTH_CLIENT_SECRET_ENV} from an authorized Google OAuth desktop client",
        "interactive": True,
        "next_steps": [
            f"Set {GOOGLE_GEMINI_OAUTH_CLIENT_ID_ENV} and {GOOGLE_GEMINI_OAUTH_CLIENT_SECRET_ENV} for an authorized Google OAuth desktop client.",
            "Run model auth login google-gemini-oauth --method oauth --run-external and approve the Google browser PKCE prompt.",
            "Route google-gemini-oauth/<model-id> after verification to use the brokered Cloud Code Assist generateContent bridge.",
            "Google treats third-party use of the Gemini CLI OAuth client as policy-risky; prefer a Gemini API key for the lowest-risk path.",
            "Do not paste Google browser cookies, access tokens, refresh tokens, ADC JSON, or Gemini CLI credential files into Aegis.",
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
        "external_command": "Nous Portal browser OAuth",
        "oauth_device_flow": "nous_device_code",
        "portal_base_url": NOUS_OAUTH_PORTAL_BASE_URL,
        "inference_base_url": NOUS_OAUTH_INFERENCE_BASE_URL,
        "client_id": NOUS_OAUTH_CLIENT_ID,
        "scope": NOUS_OAUTH_SCOPE,
        "access_token_secret": NOUS_OAUTH_ACCESS_TOKEN_SECRET,
        "refresh_token_secret": NOUS_OAUTH_REFRESH_TOKEN_SECRET,
        "agent_key_secret": NOUS_OAUTH_AGENT_KEY_SECRET,
        "refresh_skew_seconds": NOUS_OAUTH_REFRESH_SKEW_SECONDS,
        "agent_key_min_ttl_seconds": NOUS_OAUTH_AGENT_KEY_MIN_TTL_SECONDS,
        "aegis_bridge_status": "oauth_device_flow_available",
        "invocation_bridge": "nous_oauth_agent_key",
        "provider_token_source": "official Nous Portal OAuth device-code flow",
        "interactive": True,
        "next_steps": [
            "Run model auth login nous --method oauth --run-external and approve the Nous Portal device-code prompt.",
            "Route nous/<model-id> after verification to use the brokered Nous OAuth agent-key bridge.",
            "Do not paste Nous browser cookies, access tokens, refresh tokens, portal session values, or minted agent keys into Aegis.",
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
        "target": "Google Gemini OAuth / Code Assist",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "google-gemini-oauth",
        "required_auth": ("oauth",),
        "account_surface": "Google Gemini CLI / Code Assist OAuth",
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
        "target": "Kimi China",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "kimi-cn",
        "required_auth": ("api_key",),
        "account_surface": "Moonshot China",
    },
    {
        "target": "Arcee AI",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "arcee",
        "required_auth": ("api_key",),
        "account_surface": "Arcee AI",
    },
    {
        "target": "GMI Cloud",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "gmi",
        "required_auth": ("api_key",),
        "account_surface": "GMI Cloud",
    },
    {
        "target": "MiniMax",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "minimax",
        "required_auth": ("api_key",),
        "account_surface": "MiniMax",
    },
    {
        "target": "MiniMax China",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "minimax-cn",
        "required_auth": ("api_key",),
        "account_surface": "MiniMax China",
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
        "target": "Alibaba Cloud Coding Plan API",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "alibaba-coding-plan",
        "required_auth": ("api_key",),
        "account_surface": "Alibaba Cloud Coding Plan",
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
        "target": "StepFun Step Plan",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "stepfun",
        "required_auth": ("api_key",),
        "account_surface": "StepFun",
    },
    {
        "target": "Hugging Face",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "huggingface",
        "required_auth": ("api_key",),
        "account_surface": "Hugging Face Inference Providers",
    },
    {
        "target": "NVIDIA NIM",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "nvidia",
        "required_auth": ("api_key",),
        "account_surface": "NVIDIA Build / NIM",
    },
    {
        "target": "Vercel AI Gateway",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "ai-gateway",
        "required_auth": ("api_key",),
        "account_surface": "Vercel AI Gateway",
    },
    {
        "target": "OpenCode Zen",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "opencode-zen",
        "required_auth": ("api_key",),
        "account_surface": "OpenCode Zen",
    },
    {
        "target": "OpenCode Go",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "opencode-go",
        "required_auth": ("api_key",),
        "account_surface": "OpenCode Go",
    },
    {
        "target": "Kilo Code",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "kilocode",
        "required_auth": ("api_key",),
        "account_surface": "Kilo Code",
    },
    {
        "target": "Xiaomi MiMo",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "xiaomi",
        "required_auth": ("api_key",),
        "account_surface": "Xiaomi MiMo",
    },
    {
        "target": "Tencent TokenHub",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "tencent-tokenhub",
        "required_auth": ("api_key",),
        "account_surface": "Tencent MaaS TokenHub",
    },
    {
        "target": "Ollama Cloud",
        "platforms": ("Hermes Agent",),
        "aegis_provider": "ollama-cloud",
        "required_auth": ("api_key",),
        "account_surface": "Ollama Cloud",
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


def _nous_oauth_status_template(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": profile.get("provider") or "nous",
        "target": profile["target"],
        "method": profile["method"],
        "status": "external_login_required",
        "auth_configured": False,
        "auth_source": None,
        "token_captured": False,
        "token_capture_supported": False,
        "raw_browser_token_captured": False,
        "oauth_token_brokered": False,
        "agent_key_brokered": False,
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


def _run_nous_oauth_login_flow(profile: dict[str, Any], secrets_broker: SecretsBroker, *, timeout_seconds: float | None) -> dict[str, Any]:
    portal_base_url = str(profile.get("portal_base_url") or NOUS_OAUTH_PORTAL_BASE_URL).rstrip("/")
    inference_base_url = str(profile.get("inference_base_url") or NOUS_OAUTH_INFERENCE_BASE_URL).rstrip("/")
    client_id = str(profile.get("client_id") or NOUS_OAUTH_CLIENT_ID)
    scope = str(profile.get("scope") or NOUS_OAUTH_SCOPE)
    try:
        device_payload = _nous_request_device_code(
            portal_base_url=portal_base_url,
            client_id=client_id,
            scope=scope,
            timeout_seconds=timeout_seconds,
        )
        verification_uri = str(device_payload.get("verification_uri_complete") or device_payload["verification_uri"])
        user_code = str(device_payload["user_code"])
        print(f"Nous Portal OAuth: open {verification_uri} and enter code {user_code}", file=sys.stderr)
        token_payload = _nous_poll_token(
            portal_base_url=portal_base_url,
            client_id=client_id,
            device_code=str(device_payload["device_code"]),
            expires_in=int(device_payload["expires_in"]),
            poll_interval=int(device_payload.get("interval") or 1),
            timeout_seconds=timeout_seconds,
        )
        access_token = _required_oauth_value(token_payload, "access_token", "Nous OAuth token response")
        refresh_token = _required_oauth_value(token_payload, "refresh_token", "Nous OAuth token response")
        resolved_inference_url = str(token_payload.get("inference_base_url") or inference_base_url).strip().rstrip("/") or inference_base_url
        min_ttl = int(profile.get("agent_key_min_ttl_seconds") or NOUS_OAUTH_AGENT_KEY_MIN_TTL_SECONDS)
        agent_payload = _nous_mint_agent_key(
            portal_base_url=portal_base_url,
            access_token=access_token,
            min_ttl_seconds=min_ttl,
            timeout_seconds=timeout_seconds,
        )
        agent_key = _required_oauth_value(agent_payload, "api_key", "Nous OAuth agent-key response")
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

    access_secret = str(profile.get("access_token_secret") or NOUS_OAUTH_ACCESS_TOKEN_SECRET)
    refresh_secret = str(profile.get("refresh_token_secret") or NOUS_OAUTH_REFRESH_TOKEN_SECRET)
    agent_key_secret = str(profile.get("agent_key_secret") or NOUS_OAUTH_AGENT_KEY_SECRET)
    secrets_broker.store_secret(name=access_secret, value=access_token)
    secrets_broker.store_secret(name=refresh_secret, value=refresh_token)
    secrets_broker.store_secret(name=agent_key_secret, value=agent_key)
    now = datetime.now(timezone.utc)
    expires_at = _oauth_ttl_expiry(token_payload.get("expires_in"), now=now)
    agent_key_expires_at = _oauth_payload_expiry(agent_payload, now=now)
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
        "agent_key_brokered": True,
        "access_token_secret": access_secret,
        "refresh_token_secret": refresh_secret,
        "agent_key_secret": agent_key_secret,
        "portal_base_url": portal_base_url,
        "inference_base_url": resolved_inference_url,
        "client_id": client_id,
        "scope": str(token_payload.get("scope") or scope),
        "token_type": str(token_payload.get("token_type") or "Bearer"),
        "expires_at": expires_at.isoformat(),
        "expires_in": max(0, int(expires_at.timestamp() - now.timestamp())),
        "refresh_skew_seconds": int(profile.get("refresh_skew_seconds") or NOUS_OAUTH_REFRESH_SKEW_SECONDS),
        "agent_key_expires_at": agent_key_expires_at,
        "agent_key_expires_in": agent_payload.get("expires_in"),
        "agent_key_min_ttl_seconds": min_ttl,
        "invocation_bridge": str(profile.get("invocation_bridge") or "nous_oauth_agent_key"),
    }


def _verify_nous_oauth_link(profile: dict[str, Any], secrets_broker: SecretsBroker, link: dict[str, Any] | None) -> dict[str, Any]:
    access_secret = str((link or {}).get("access_token_secret") or profile.get("access_token_secret") or NOUS_OAUTH_ACCESS_TOKEN_SECRET)
    refresh_secret = str((link or {}).get("refresh_token_secret") or profile.get("refresh_token_secret") or NOUS_OAUTH_REFRESH_TOKEN_SECRET)
    agent_key_secret = str((link or {}).get("agent_key_secret") or profile.get("agent_key_secret") or NOUS_OAUTH_AGENT_KEY_SECRET)
    verified = link is not None and secrets_broker.has_secret(access_secret) and secrets_broker.has_secret(refresh_secret) and secrets_broker.has_secret(agent_key_secret)
    return {
        "external_status_checked": True,
        "external_status_verified": verified,
        "status": "external_login_verified" if verified else "external_login_required",
        "auth_configured": verified,
        "auth_source": "oauth_device_flow" if verified else None,
        "aegis_bridge_status": "oauth_device_flow_ready" if verified else "oauth_device_flow_available",
        "oauth_token_brokered": verified,
        "agent_key_brokered": verified,
        "access_token_secret": access_secret,
        "refresh_token_secret": refresh_secret,
        "agent_key_secret": agent_key_secret,
        **{
            key: value
            for key, value in (link or {}).items()
            if key
            in {
                "portal_base_url",
                "inference_base_url",
                "client_id",
                "scope",
                "token_type",
                "expires_at",
                "expires_in",
                "refresh_skew_seconds",
                "agent_key_expires_at",
                "agent_key_expires_in",
                "agent_key_min_ttl_seconds",
                "invocation_bridge",
            }
        },
    }


def _github_copilot_oauth_status_template(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": profile.get("provider") or "github-copilot",
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


def _run_github_copilot_oauth_login_flow(profile: dict[str, Any], secrets_broker: SecretsBroker, *, timeout_seconds: float | None) -> dict[str, Any]:
    portal_base_url = str(profile.get("portal_base_url") or GITHUB_COPILOT_OAUTH_PORTAL_BASE_URL).rstrip("/")
    client_id = str(profile.get("client_id") or GITHUB_COPILOT_OAUTH_CLIENT_ID)
    scope = str(profile.get("scope") or GITHUB_COPILOT_OAUTH_SCOPE)
    try:
        device_payload = _github_copilot_request_device_code(
            portal_base_url=portal_base_url,
            client_id=client_id,
            scope=scope,
            timeout_seconds=timeout_seconds,
        )
        verification_uri = str(device_payload.get("verification_uri") or "https://github.com/login/device")
        user_code = str(device_payload["user_code"])
        print(f"GitHub Copilot OAuth: open {verification_uri} and enter code {user_code}", file=sys.stderr)
        token_payload = _github_copilot_poll_token(
            portal_base_url=portal_base_url,
            client_id=client_id,
            device_code=str(device_payload["device_code"]),
            expires_in=int(device_payload.get("expires_in") or 300),
            poll_interval=int(device_payload.get("interval") or 5),
            timeout_seconds=timeout_seconds,
        )
        access_token = _required_oauth_value(token_payload, "access_token", "GitHub Copilot OAuth token response")
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

    access_secret = str(profile.get("access_token_secret") or GITHUB_COPILOT_OAUTH_TOKEN_SECRET)
    secrets_broker.store_secret(name=access_secret, value=access_token)
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
        "portal_base_url": portal_base_url,
        "client_id": client_id,
        "scope": str(token_payload.get("scope") or scope),
        "token_type": str(token_payload.get("token_type") or "Bearer"),
        "invocation_bridge": str(profile.get("invocation_bridge") or "copilot_oauth_chat_completions"),
    }


def _verify_github_copilot_oauth_link(profile: dict[str, Any], secrets_broker: SecretsBroker, link: dict[str, Any] | None) -> dict[str, Any]:
    access_secret = str((link or {}).get("access_token_secret") or profile.get("access_token_secret") or GITHUB_COPILOT_OAUTH_TOKEN_SECRET)
    verified = link is not None and secrets_broker.has_secret(access_secret)
    return {
        "external_status_checked": True,
        "external_status_verified": verified,
        "status": "external_login_verified" if verified else "external_login_required",
        "auth_configured": verified,
        "auth_source": "oauth_device_flow" if verified else None,
        "aegis_bridge_status": "oauth_device_flow_ready" if verified else "oauth_device_flow_available",
        "oauth_token_brokered": verified,
        "access_token_secret": access_secret,
        **{
            key: value
            for key, value in (link or {}).items()
            if key in {"portal_base_url", "client_id", "scope", "token_type", "invocation_bridge"}
        },
    }


def _google_gemini_oauth_status_template(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": profile.get("provider") or "google-gemini-oauth",
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
        "client_id_configured": bool(os.environ.get(GOOGLE_GEMINI_OAUTH_CLIENT_ID_ENV, "").strip()),
        "client_secret_configured": bool(os.environ.get(GOOGLE_GEMINI_OAUTH_CLIENT_SECRET_ENV, "").strip()),
        **_handoff_profile_public_fields(profile),
    }


def _run_google_gemini_oauth_login_flow(profile: dict[str, Any], secrets_broker: SecretsBroker, *, timeout_seconds: float | None) -> dict[str, Any]:
    scope = str(profile.get("scope") or GOOGLE_GEMINI_OAUTH_SCOPE)
    verifier, challenge = _oauth_pkce_pair()
    state = secrets.token_urlsafe(16)
    redirect_uri = f"http://{GOOGLE_GEMINI_OAUTH_REDIRECT_HOST}:{GOOGLE_GEMINI_OAUTH_REDIRECT_PORT}{GOOGLE_GEMINI_OAUTH_CALLBACK_PATH}"
    try:
        client_id = _google_gemini_oauth_client_id(profile)
        client_secret = _google_gemini_oauth_client_secret(profile)
        code, redirect_uri = _google_gemini_collect_authorization_code(
            client_id=client_id,
            scope=scope,
            verifier=verifier,
            challenge=challenge,
            state=state,
            timeout_seconds=timeout_seconds,
        )
        token_payload = _google_gemini_exchange_code(
            code=code,
            verifier=verifier,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            timeout_seconds=timeout_seconds,
        )
        access_token = _required_oauth_value(token_payload, "access_token", "Google Gemini OAuth token response")
        refresh_token = _required_oauth_value(token_payload, "refresh_token", "Google Gemini OAuth token response")
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

    access_secret = str(profile.get("access_token_secret") or GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN_SECRET)
    refresh_secret = str(profile.get("refresh_token_secret") or GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN_SECRET)
    secrets_broker.store_secret(name=access_secret, value=access_token)
    secrets_broker.store_secret(name=refresh_secret, value=refresh_token)
    now = datetime.now(timezone.utc)
    expires_at = _oauth_ttl_expiry(token_payload.get("expires_in"), now=now)
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
        "inference_base_url": str(profile.get("inference_base_url") or GOOGLE_GEMINI_CLOUDCODE_BASE_URL).rstrip("/"),
        "client_id": client_id,
        "scope": str(token_payload.get("scope") or scope),
        "token_type": str(token_payload.get("token_type") or "Bearer"),
        "expires_at": expires_at.isoformat(),
        "expires_in": max(0, int(expires_at.timestamp() - now.timestamp())),
        "refresh_skew_seconds": int(profile.get("refresh_skew_seconds") or GOOGLE_GEMINI_OAUTH_REFRESH_SKEW_SECONDS),
        "invocation_bridge": str(profile.get("invocation_bridge") or "google_gemini_cloudcode_generate_content"),
        "client_id_configured": True,
        "client_secret_configured": True,
    }


def _verify_google_gemini_oauth_link(profile: dict[str, Any], secrets_broker: SecretsBroker, link: dict[str, Any] | None) -> dict[str, Any]:
    access_secret = str((link or {}).get("access_token_secret") or profile.get("access_token_secret") or GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN_SECRET)
    refresh_secret = str((link or {}).get("refresh_token_secret") or profile.get("refresh_token_secret") or GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN_SECRET)
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
        **{
            key: value
            for key, value in (link or {}).items()
            if key in {"inference_base_url", "client_id", "scope", "token_type", "expires_at", "expires_in", "refresh_skew_seconds", "invocation_bridge", "project_id"}
        },
    }


def _google_gemini_collect_authorization_code(
    *,
    client_id: str,
    scope: str,
    verifier: str,
    challenge: str,
    state: str,
    timeout_seconds: float | None,
) -> tuple[str, str]:
    del verifier
    server, redirect_uri = _google_gemini_callback_server(state)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    auth_url = f"{GOOGLE_GEMINI_OAUTH_AUTH_URL}?{urlencode(params)}#aegis"
    print(f"Google Gemini OAuth: open {auth_url}", file=sys.stderr)
    try:
        webbrowser.open(auth_url, new=1, autoraise=True)
    except Exception:
        pass
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        wait_seconds = max(1.0, float(timeout_seconds or 300.0))
        if not _GoogleGeminiOAuthCallback.ready.wait(timeout=wait_seconds):
            raise TimeoutError("Google Gemini OAuth timed out before callback completed")
        if _GoogleGeminiOAuthCallback.error:
            raise RuntimeError(f"Google Gemini OAuth authorization failed: {_GoogleGeminiOAuthCallback.error}")
        if not _GoogleGeminiOAuthCallback.code:
            raise RuntimeError("Google Gemini OAuth callback did not include an authorization code")
        return str(_GoogleGeminiOAuthCallback.code), redirect_uri
    finally:
        try:
            server.shutdown()
        finally:
            server.server_close()
        thread.join(timeout=2.0)


class _GoogleGeminiOAuthCallback(BaseHTTPRequestHandler):
    expected_state: str = ""
    code: str | None = None
    error: str | None = None
    ready = threading.Event()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002, N802
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != GOOGLE_GEMINI_OAUTH_CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            return
        params = parse_qs(parsed.query)
        state = (params.get("state") or [""])[0]
        if state != type(self).expected_state:
            type(self).error = "state_mismatch"
            self._respond(400, "Google Gemini OAuth state mismatch. Return to Aegis.")
        elif (params.get("error") or [""])[0]:
            type(self).error = (params.get("error") or ["authorization_failed"])[0]
            self._respond(400, "Google Gemini OAuth authorization failed. Return to Aegis.")
        else:
            type(self).code = (params.get("code") or [""])[0] or None
            self._respond(200, "Google Gemini OAuth complete. You can close this tab.")
        type(self).ready.set()

    def _respond(self, status: int, message: str) -> None:
        payload = f"<!doctype html><meta charset=\"utf-8\"><title>Aegis</title><p>{message}</p>".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _google_gemini_callback_server(state: str) -> tuple[HTTPServer, str]:
    _GoogleGeminiOAuthCallback.expected_state = state
    _GoogleGeminiOAuthCallback.code = None
    _GoogleGeminiOAuthCallback.error = None
    _GoogleGeminiOAuthCallback.ready = threading.Event()
    try:
        server = HTTPServer((GOOGLE_GEMINI_OAUTH_REDIRECT_HOST, GOOGLE_GEMINI_OAUTH_REDIRECT_PORT), _GoogleGeminiOAuthCallback)
    except OSError:
        server = HTTPServer((GOOGLE_GEMINI_OAUTH_REDIRECT_HOST, 0), _GoogleGeminiOAuthCallback)
    port = int(server.server_address[1])
    return server, f"http://{GOOGLE_GEMINI_OAUTH_REDIRECT_HOST}:{port}{GOOGLE_GEMINI_OAUTH_CALLBACK_PATH}"


def _google_gemini_oauth_client_id(profile: dict[str, Any]) -> str:
    value = str(profile.get("client_id") or os.environ.get(GOOGLE_GEMINI_OAUTH_CLIENT_ID_ENV, "")).strip()
    if not value:
        raise RuntimeError(f"Google Gemini OAuth requires {GOOGLE_GEMINI_OAUTH_CLIENT_ID_ENV}")
    return value


def _google_gemini_oauth_client_secret(profile: dict[str, Any]) -> str:
    value = str(profile.get("client_secret") or os.environ.get(GOOGLE_GEMINI_OAUTH_CLIENT_SECRET_ENV, "")).strip()
    if not value:
        raise RuntimeError(f"Google Gemini OAuth requires {GOOGLE_GEMINI_OAUTH_CLIENT_SECRET_ENV}")
    return value


def _google_gemini_exchange_code(*, code: str, verifier: str, redirect_uri: str, client_id: str, client_secret: str, timeout_seconds: float | None) -> dict[str, Any]:
    return _post_auth_form(
        GOOGLE_GEMINI_OAUTH_TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
        },
        timeout_seconds=timeout_seconds,
        label="Google Gemini OAuth",
    )


def _oauth_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _github_copilot_request_device_code(*, portal_base_url: str, client_id: str, scope: str, timeout_seconds: float | None) -> dict[str, Any]:
    payload = _post_auth_form(
        f"{portal_base_url}/login/device/code",
        {"client_id": client_id, "scope": scope},
        timeout_seconds=timeout_seconds,
        label="GitHub Copilot OAuth",
    )
    for field in ("device_code", "user_code"):
        if field not in payload:
            raise RuntimeError(f"GitHub Copilot OAuth device-code response missing field: {field}")
    return payload


def _github_copilot_poll_token(
    *,
    portal_base_url: str,
    client_id: str,
    device_code: str,
    expires_in: int,
    poll_interval: int,
    timeout_seconds: float | None,
) -> dict[str, Any]:
    deadline = min(time.monotonic() + max(1, expires_in), time.monotonic() + (timeout_seconds or max(1, expires_in)))
    interval = max(1, min(poll_interval, GITHUB_COPILOT_DEVICE_AUTH_POLL_INTERVAL_CAP_SECONDS))
    while time.monotonic() < deadline:
        status_code, payload = _post_auth_form_status(
            f"{portal_base_url}/login/oauth/access_token",
            {
                "client_id": client_id,
                "device_code": device_code,
                "grant_type": GITHUB_COPILOT_OAUTH_GRANT_TYPE,
            },
            timeout_seconds=timeout_seconds,
            label="GitHub Copilot OAuth",
        )
        if status_code == 200 and payload.get("access_token"):
            return payload
        error_code = str(payload.get("error") or "")
        if error_code == "authorization_pending":
            time.sleep(interval)
            continue
        if error_code == "slow_down":
            interval = min(interval + 5, 30)
            time.sleep(interval)
            continue
        if error_code == "expired_token":
            raise RuntimeError("GitHub Copilot OAuth device code expired")
        if error_code == "access_denied":
            raise RuntimeError("GitHub Copilot OAuth authorization was denied")
        description = str(payload.get("error_description") or "unknown authentication error")
        raise RuntimeError(f"GitHub Copilot OAuth {error_code or status_code}: {description}")
    raise TimeoutError("GitHub Copilot OAuth timed out before authorization completed")


def _nous_request_device_code(*, portal_base_url: str, client_id: str, scope: str, timeout_seconds: float | None) -> dict[str, Any]:
    data = {"client_id": client_id}
    if scope:
        data["scope"] = scope
    payload = _post_auth_form(
        f"{portal_base_url}/api/oauth/device/code",
        data,
        timeout_seconds=timeout_seconds,
        label="Nous OAuth",
    )
    for field in ("device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in", "interval"):
        if field not in payload:
            raise RuntimeError(f"Nous OAuth device-code response missing field: {field}")
    return payload


def _nous_poll_token(
    *,
    portal_base_url: str,
    client_id: str,
    device_code: str,
    expires_in: int,
    poll_interval: int,
    timeout_seconds: float | None,
) -> dict[str, Any]:
    deadline = min(time.monotonic() + max(1, expires_in), time.monotonic() + (timeout_seconds or max(1, expires_in)))
    interval = max(1, min(poll_interval, NOUS_DEVICE_AUTH_POLL_INTERVAL_CAP_SECONDS))
    while time.monotonic() < deadline:
        status_code, payload = _post_auth_form_status(
            f"{portal_base_url}/api/oauth/token",
            {
                "grant_type": NOUS_OAUTH_GRANT_TYPE,
                "client_id": client_id,
                "device_code": device_code,
            },
            timeout_seconds=timeout_seconds,
            label="Nous OAuth",
        )
        if status_code == 200:
            if "access_token" not in payload:
                raise RuntimeError("Nous OAuth token response did not include access_token")
            return payload
        error_code = str(payload.get("error") or "")
        if error_code == "authorization_pending":
            time.sleep(interval)
            continue
        if error_code == "slow_down":
            interval = min(interval + 1, 30)
            time.sleep(interval)
            continue
        description = str(payload.get("error_description") or "unknown authentication error")
        raise RuntimeError(f"Nous OAuth {error_code or status_code}: {description}")
    raise TimeoutError("Nous OAuth timed out before authorization completed")


def _nous_mint_agent_key(*, portal_base_url: str, access_token: str, min_ttl_seconds: int, timeout_seconds: float | None) -> dict[str, Any]:
    payload = _post_auth_json(
        f"{portal_base_url}/api/oauth/agent-key",
        {"min_ttl_seconds": max(60, int(min_ttl_seconds))},
        headers={"Authorization": f"Bearer {access_token}"},
        timeout_seconds=timeout_seconds,
        label="Nous OAuth",
    )
    if "api_key" not in payload:
        raise RuntimeError("Nous OAuth agent-key response did not include api_key")
    return payload


def _required_oauth_value(payload: dict[str, Any], field: str, label: str) -> str:
    value = str(payload.get(field) or "").strip()
    if not value:
        raise RuntimeError(f"{label} did not include {field}")
    return value


def _oauth_ttl_expiry(expires_in: Any, *, now: datetime) -> datetime:
    try:
        ttl = int(expires_in)
    except (TypeError, ValueError):
        ttl = 0
    return datetime.fromtimestamp(now.timestamp() + max(0, ttl), tz=timezone.utc)


def _oauth_payload_expiry(payload: dict[str, Any], *, now: datetime) -> str:
    raw = str(payload.get("expires_at") or "").strip()
    if raw:
        return raw
    return _oauth_ttl_expiry(payload.get("expires_in"), now=now).isoformat()


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


def _post_auth_form(url: str, data: dict[str, str], *, timeout_seconds: float | None, headers: dict[str, str] | None = None, label: str = "MiniMax OAuth") -> dict[str, Any]:
    status_code, payload = _post_auth_form_status(url, data, timeout_seconds=timeout_seconds, headers=headers, label=label)
    if status_code >= 400:
        raise RuntimeError(f"{label} HTTP {status_code}: {json.dumps(payload, sort_keys=True)[:500]}")
    return payload


def _post_auth_form_status(
    url: str,
    data: dict[str, str],
    *,
    timeout_seconds: float | None,
    headers: dict[str, str] | None = None,
    label: str = "MiniMax OAuth",
) -> tuple[int, dict[str, Any]]:
    request_headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    request = Request(
        url,
        data=urlencode(data).encode("utf-8"),
        method="POST",
        headers=request_headers,
    )
    try:
        with _open_auth_request(request, timeout=timeout_seconds or 30.0) as response:  # noqa: S310 - URL is fixed provider OAuth metadata.
            raw = response.read().decode("utf-8")
            status_code = int(getattr(response, "status", 200) or 200)
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status_code = exc.code
    except URLError as exc:
        raise RuntimeError(f"{label} connection failed: {exc.reason}") from exc
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{label} returned invalid JSON")
    return status_code, decoded


def _post_auth_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: float | None,
    label: str,
) -> dict[str, Any]:
    request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=request_headers,
    )
    try:
        with _open_auth_request(request, timeout=timeout_seconds or 30.0) as response:  # noqa: S310 - URL is fixed provider OAuth metadata.
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"{label} HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"{label} connection failed: {exc.reason}") from exc
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{label} returned invalid JSON")
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
        "provider",
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
        "client_id_env",
        "client_secret_env",
        "scope",
        "access_token_secret",
        "refresh_token_secret",
        "agent_key_secret",
        "agent_key_min_ttl_seconds",
        "refresh_skew_seconds",
        "invocation_bridge",
        "project_id",
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
        ModelProviderSpec(
            "google-gemini-oauth",
            ("gemini-3-pro-preview", "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash", "*"),
            None,
            GOOGLE_GEMINI_CLOUDCODE_BASE_URL,
            False,
            True,
            True,
            True,
            0.0,
            0.0,
            1000000,
            "google",
            "oauth",
            {
                "auth_surface": "oauth_device",
                "inference_base_url": GOOGLE_GEMINI_CLOUDCODE_BASE_URL,
                "access_token_secret": GOOGLE_GEMINI_OAUTH_ACCESS_TOKEN_SECRET,
                "refresh_token_secret": GOOGLE_GEMINI_OAUTH_REFRESH_TOKEN_SECRET,
                "refresh_skew_seconds": GOOGLE_GEMINI_OAUTH_REFRESH_SKEW_SECONDS,
                "client_id_env": GOOGLE_GEMINI_OAUTH_CLIENT_ID_ENV,
                "client_secret_env": GOOGLE_GEMINI_OAUTH_CLIENT_SECRET_ENV,
                "project_id": google_vertex_project or "",
                "invocation_bridge": "google_gemini_cloudcode_generate_content",
            },
        ),
        ModelProviderSpec("mistral", ("mistral-large", "mistral-medium", "mistral-small", "codestral"), "MISTRAL_API_KEY", "https://api.mistral.ai/v1", False, True, False, False, 2.0, 6.0, 32000, "mistral"),
        ModelProviderSpec("cohere", ("command-r-plus", "command-r"), "COHERE_API_KEY", "https://api.cohere.com/v2", False, True, False, False, 3.0, 15.0, 128000, "cohere"),
        ModelProviderSpec("openrouter", ("anthropic/claude-sonnet-4.6", "openai/gpt-4o", "meta-llama/llama-3.1-70b"), "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", False, True, True, True, 0.0, 0.0, 128000, "openrouter"),
        ModelProviderSpec(
            "nous",
            ("Hermes-4-405B", "Hermes-4-70B"),
            "NOUS_API_KEY",
            NOUS_OAUTH_INFERENCE_BASE_URL,
            False,
            True,
            False,
            False,
            0.0,
            0.0,
            128000,
            "openai_compatible",
            "oauth",
            {
                "auth_surface": "oauth_device",
                "compatibility": "openai_chat_completions",
                "portal_base_url": NOUS_OAUTH_PORTAL_BASE_URL,
                "client_id": NOUS_OAUTH_CLIENT_ID,
                "scope": NOUS_OAUTH_SCOPE,
                "access_token_secret": NOUS_OAUTH_ACCESS_TOKEN_SECRET,
                "refresh_token_secret": NOUS_OAUTH_REFRESH_TOKEN_SECRET,
                "agent_key_secret": NOUS_OAUTH_AGENT_KEY_SECRET,
                "refresh_skew_seconds": NOUS_OAUTH_REFRESH_SKEW_SECONDS,
                "agent_key_min_ttl_seconds": NOUS_OAUTH_AGENT_KEY_MIN_TTL_SECONDS,
            },
        ),
        ModelProviderSpec("deepseek", ("deepseek-v4-flash", "deepseek-v4-pro", "deepseek-chat", "deepseek-reasoner"), "DEEPSEEK_API_KEY", "https://api.deepseek.com", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("xai", ("grok-4.20-reasoning", "grok-4", "grok-4-fast"), "XAI_API_KEY", "https://api.x.ai/v1", False, True, True, False, 0.0, 0.0, 256000, "openai_compatible"),
        ModelProviderSpec("kimi", ("kimi-k2.5", "kimi-k2-turbo-preview", "kimi-k2-thinking"), "KIMI_API_KEY", "https://api.moonshot.ai/v1", False, True, True, False, 0.0, 0.0, 256000, "openai_compatible"),
        ModelProviderSpec("kimi-cn", ("kimi-k2.5", "moonshot-v1-128k", "moonshot-v1-32k"), "KIMI_CN_API_KEY", "https://api.moonshot.cn/v1", False, True, True, False, 0.0, 0.0, 256000, "openai_compatible", metadata={"hermes_provider": "kimi-coding-cn"}),
        ModelProviderSpec("arcee", ("auto", "*"), "ARCEEAI_API_KEY", "https://api.arcee.ai/api/v1", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("gmi", ("*",), "GMI_API_KEY", "https://api.gmi-serving.com/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("minimax", ("MiniMax-M2.7", "MiniMax-M2.5", "MiniMax-M2"), "MINIMAX_API_KEY", "https://api.minimax.io/v1", False, True, False, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec(
            "minimax-cn",
            ("MiniMax-M2.7", "MiniMax-M2.5", "MiniMax-M2"),
            "MINIMAX_CN_API_KEY",
            "https://api.minimaxi.com/anthropic",
            False,
            True,
            False,
            False,
            0.0,
            0.0,
            204800,
            "anthropic",
            metadata={"compatibility": "anthropic_messages", "invocation_bridge": "minimax_cn_anthropic_compatible"},
        ),
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
        ModelProviderSpec("alibaba-coding-plan", ("qwen3-coder-plus", "qwen3-coder-flash", "*"), "ALIBABA_CODING_PLAN_API_KEY", "https://coding-intl.dashscope.aliyuncs.com/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("stepfun", ("step-3", "step-2-16k", "step-1-256k"), "STEPFUN_API_KEY", "https://api.stepfun.ai/step_plan/v1", False, True, True, False, 0.0, 0.0, 256000, "openai_compatible"),
        ModelProviderSpec("huggingface", ("Qwen/Qwen3-235B-A22B-Instruct-2507", "deepseek-ai/DeepSeek-V3.1", "moonshotai/Kimi-K2-Instruct", "*"), "HF_TOKEN", "https://router.huggingface.co/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("nvidia", ("nvidia/llama-3.1-nemotron-70b-instruct", "nvidia/llama-3.3-nemotron-super-49b-v1", "*"), "NVIDIA_API_KEY", "https://integrate.api.nvidia.com/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("ai-gateway", ("*",), "AI_GATEWAY_API_KEY", "https://ai-gateway.vercel.sh/v1", False, True, True, True, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("opencode-zen", ("*",), "OPENCODE_ZEN_API_KEY", "https://opencode.ai/zen/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("opencode-go", ("*",), "OPENCODE_GO_API_KEY", "https://opencode.ai/zen/go/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible", metadata={"mixed_api_surface": "openai_for_glm_kimi_anthropic_for_minimax"}),
        ModelProviderSpec("kilocode", ("*",), "KILOCODE_API_KEY", "https://api.kilo.ai/api/gateway", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("xiaomi", ("mimo-vl-7b-rl", "*"), "XIAOMI_API_KEY", "https://api.xiaomimimo.com/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("tencent-tokenhub", ("*",), "TOKENHUB_API_KEY", "https://tokenhub.tencentmaas.com/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("ollama-cloud", ("gpt-oss:120b", "llama3.3", "qwen3", "*"), "OLLAMA_API_KEY", "https://ollama.com/v1", False, True, True, False, 0.0, 0.0, 128000, "openai_compatible"),
        ModelProviderSpec("azure-foundry", ("*",), "AZURE_OPENAI_API_KEY", azure_foundry_base_url, False, True, True, True, 0.0, 0.0, 128000, "openai_compatible", "cloud_identity"),
        ModelProviderSpec("aws-bedrock", ("*",), None, None, False, True, True, False, 0.0, 0.0, 200000, "bedrock_converse", "cloud_identity"),
        ModelProviderSpec("github-copilot", ("gpt-5.1-codex", "gpt-5.1", "gpt-4.1"), None, None, False, True, False, False, 0.0, 0.0, 200000, "openai_compatible", "oauth_device"),
        ModelProviderSpec("ollama", ("llama3", "llama3.1", "mistral", "mixtral", "phi3", "gemma2", "codellama", "deepseek-coder"), None, "http://localhost:11434", True, False, context_window_tokens=8192, tokenizer_profile="llama"),
        ModelProviderSpec("lmstudio", ("local",), None, "http://localhost:1234/v1", True, False, context_window_tokens=8192, tokenizer_profile="openai_compatible"),
        ModelProviderSpec("custom", ("*",), "CUSTOM_API_KEY", custom_base_url, False, True, context_window_tokens=8192, tokenizer_profile="openai_compatible"),
    )
    return {provider.provider: provider for provider in providers}
