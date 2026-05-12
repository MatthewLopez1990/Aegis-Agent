"""Short-lived local remote-control pairing tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
import hashlib
import json
import os
from pathlib import Path
import secrets
from urllib.parse import quote, urlparse
from urllib.request import Request

from aegis.connectors.http import _open_without_redirects, _private_network_error, _validate_url


REMOTE_CONTROL_TOKEN_HEADER = "X-Aegis-Remote-Token"
DEFAULT_PAIRING_TTL_SECONDS = 600
MIN_PAIRING_TTL_SECONDS = 60
MAX_PAIRING_TTL_SECONDS = 3600
DEFAULT_ALLOWED_TASK_ACTIONS = ("status", "events", "resume", "pause", "cancel")
MAX_REMOTE_DIRECTORY_TASKS = 25
MAX_RELAY_OUTBOX_ITEMS = 100
RELAY_RECEIPT_ACCEPTED_STATES = ("accepted", "acknowledged", "delivered", "received", "ok")
REMOTE_CONTROL_RELAY_NOTIFICATION_EVENTS = (
    "pairing_ready",
    "directory_updated",
    "task_updated",
    "task_waiting",
    "approval_requested",
    "task_completed",
    "task_failed",
)
REMOTE_CONTROL_NATIVE_PUSH_PROVIDERS = ("apns", "fcm")
REMOTE_CONTROL_RELAY_REQUIRED_CONTROLS = (
    "explicit_operator_enablement",
    "brokered_relay_auth",
    "relay_origin_allowlist",
    "scoped_pairing_token_exchange",
    "relay_action_authorization",
    "push_delivery_approval",
    "audit_receipts_without_tokens",
    "revocation_and_expiry_propagation",
)
REMOTE_CONTROL_RELAY_VERIFICATION_GATES = (
    "disabled_relay_denial",
    "relay_token_redaction",
    "origin_allowlist_enforced",
    "pairing_scope_preserved",
    "relay_action_proxy_authorized",
    "revocation_blocks_relayed_actions",
)
REMOTE_CONTROL_MOBILE_GATEWAY_CONTRACT = {
    "contract_schema": "aegis.remote_control.mobile_gateway.v1",
    "transport": "https_relay_gateway",
    "payload_type": "aegis.remote_control.notification",
    "receipt_schema": "relay_delivery_receipt",
    "accepted_states": list(RELAY_RECEIPT_ACCEPTED_STATES),
    "native_push_provider": "brokered_apns_fcm_adapter",
    "native_push_providers": list(REMOTE_CONTROL_NATIVE_PUSH_PROVIDERS),
    "brokered_device_tokens_supported": True,
    "device_token_capture_supported": False,
    "raw_device_tokens_supported": False,
    "pairing_token_relayed": False,
    "relay_auth_token_included": False,
    "raw_secret_values_included": False,
}


class RemoteControlPairingRegistry:
    """Short-lived pairing registry for one local API server or CLI data dir."""

    def __init__(self, store_path: str | Path | None = None) -> None:
        self.store_path = Path(store_path).expanduser().resolve() if store_path else None
        self._pairings: dict[str, dict[str, Any]] = {}
        self._relay_outbox: list[dict[str, Any]] = []
        self._load()

    def create_pairing(
        self,
        *,
        label: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        allowed_actions: tuple[str, ...] | list[str] | None = None,
        ttl_seconds: int | None = None,
        endpoint_host: str = "127.0.0.1",
        endpoint_port: int = 8765,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        self._load()
        created_at = _utc_now(now)
        ttl = _clamp_ttl(ttl_seconds)
        token = "aegis-rc-" + secrets.token_urlsafe(32)
        pairing_id = "rc_" + secrets.token_hex(8)
        pairing = {
            "id": pairing_id,
            "label": (label or "remote control").strip()[:80],
            "session_id": session_id,
            "task_id": task_id,
            "allowed_actions": _normalize_allowed_actions(allowed_actions),
            "token_sha256": _token_hash(token),
            "created_at": created_at.isoformat(),
            "expires_at": (created_at + timedelta(seconds=ttl)).isoformat(),
            "revoked_at": None,
            "relay_registration": None,
        }
        self._pairings[pairing_id] = pairing
        self._save()
        return {
            "status": "paired",
            "pairing": self._public_pairing(pairing, now=created_at),
            "token": token,
            "token_header": REMOTE_CONTROL_TOKEN_HEADER,
            "expires_in_seconds": ttl,
            "allowed_use": "scoped_remote_task_control",
            "security_posture": [
                "short_lived_token",
                "token_returned_once",
                "host_and_origin_checks_still_apply",
                "scoped_remote_control_endpoints_only",
                "audit_receipt_without_token",
            ],
            "local_endpoints": _local_remote_control_endpoints(
                host=endpoint_host,
                port=endpoint_port,
            ),
        }

    def status(self, *, now: datetime | None = None) -> dict[str, Any]:
        self._load()
        checked_at = _utc_now(now)
        pairings = [
            self._public_pairing(pairing, now=checked_at)
            for pairing in self._pairings.values()
        ]
        active_count = sum(1 for pairing in pairings if pairing["status"] == "active")
        relay_action_count = sum(
            1
            for pairing in pairings
            if pairing["status"] == "active" and pairing.get("relay_action_proxy_enabled")
        )
        mobile_gateway_count = sum(
            1
            for pairing in pairings
            if pairing["status"] == "active" and pairing.get("relay_notification_enabled")
        )
        return {
            "status": "local_pairing_available",
            "mode": "local_or_trusted_access_layer",
            "token_header": REMOTE_CONTROL_TOKEN_HEADER,
            "default_expires_in_seconds": DEFAULT_PAIRING_TTL_SECONDS,
            "max_expires_in_seconds": MAX_PAIRING_TTL_SECONDS,
            "active_pairing_count": active_count,
            "active_relay_action_proxy_count": relay_action_count,
            "active_mobile_gateway_count": mobile_gateway_count,
            "pairings": pairings,
            "relay_outbox": self.relay_outbox(limit=20)["items"],
            "mobile_gateway_contract": _mobile_gateway_contract(configured=mobile_gateway_count > 0),
            "control_surface": [
                "scoped task directory",
                "remote task status",
                "remote task events",
                "remote task resume",
                "remote task pause",
                "remote task cancel",
                "registered relay action pull",
                "registered relay action proxy",
                "registered relay directory publish",
                "registered relay notification publish",
                "durable relay notification outbox",
                "approved native APNS/FCM notification publish",
            ],
            "blocked_until_relay": ["mobile_gateway_registration"] if mobile_gateway_count == 0 else [],
            "remaining_live_delivery_gaps": [
                "native_push_provider_lifecycle",
                "broad_cloud_relay_service",
            ],
            "relay_preflight": self.relay_preflight(),
        }

    def relay_preflight(self, *, relay_url: str | None = None) -> dict[str, Any]:
        relay_target = _redacted_relay_target(relay_url)
        blockers = [
            {"control": "explicit_operator_enablement", "detail": "approved relay registration is required before outbound relay transport is used"},
            {"control": "brokered_relay_auth", "detail": "relay credentials must use brokered handles and must not expose raw tokens"},
            {"control": "relay_origin_allowlist", "detail": "remote origins must be allowlisted before off-device access"},
            {"control": "push_delivery_approval", "detail": "native push delivery requires an approved brokered provider/device-token adapter"},
        ]
        if relay_target is None and relay_url:
            blockers.insert(0, {"control": "relay_url_validation", "detail": "relay URL must use https"})
        return {
            "status": "relay_blocked_preflight",
            "mode": "preflight_only",
            "outbound_relay_enabled": False,
            "relay_configured": relay_target is not None,
            "relay_target": relay_target,
            "relay_url_redacted": bool(relay_url),
            "mobile_push_delivery": "brokered_apns_fcm_push_available_with_active_pairing_and_approval",
            "mobile_gateway_contract": _mobile_gateway_contract(configured=relay_target is not None),
            "cloud_session_directory": "scoped_local_directory_available",
            "token_capture_supported": False,
            "token_captured": False,
            "pairing_token_relayed": False,
            "raw_secret_values_included": False,
            "required_controls": list(REMOTE_CONTROL_RELAY_REQUIRED_CONTROLS),
            "configured_controls": [
                "local_short_lived_pairing_tokens",
                "token_hash_storage_only",
                "host_and_origin_checks",
                "scoped_task_actions",
                "local_revocation",
                "approved_relay_revocation_propagation",
                "approved_relay_action_pull",
                "approved_relay_notification_publish",
                "durable_relay_notification_outbox",
                "approved_relay_directory_publish",
                "scoped_remote_directory",
                "mobile_gateway_delivery_contract",
                "approved_brokered_native_apns_fcm_push",
            ],
            "blockers": blockers,
            "verification_gates": list(REMOTE_CONTROL_RELAY_VERIFICATION_GATES),
            "allowed_local_endpoints": [
                "GET /remote-control/status",
                "GET /remote-control/directory",
                "POST /remote-control/pair",
                "POST /remote-control/revoke",
                "GET /remote-control/tasks/:id",
                "GET /remote-control/tasks/:id/events",
                "POST /remote-control/tasks/:id/resume|pause|cancel",
            ],
            "next_steps": [
                "Register an active pairing with an allowlisted relay using a brokered credential handle.",
                "Preserve local pairing scope, expiry, revocation, host checks, and audit receipts through relayed actions.",
                "Use remote-control push with brokered provider and device-token secrets for one approved APNS/FCM notification.",
            ],
        }

    def relay_pairing(
        self,
        pairing_id: str,
        *,
        relay_url: str,
        allowlist: tuple[str, ...],
        relay_auth_token: str,
        approved: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not approved:
            raise PermissionError("remote-control relay registration requires explicit approval")
        if not relay_auth_token.strip():
            raise ValueError("remote-control relay registration requires a brokered relay auth token")
        self._load()
        checked_at = _utc_now(now)
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        public_pairing = self._public_pairing(pairing, now=checked_at)
        if public_pairing["status"] != "active":
            raise ValueError("remote-control relay registration requires an active pairing")
        parsed = urlparse(str(relay_url or "").strip())
        validation_error = _validate_url(parsed)
        if validation_error:
            raise ValueError(validation_error)
        if parsed.scheme != "https":
            raise ValueError("remote-control relay URL must use https")
        domain = parsed.hostname or ""
        if not _allowed_domain(domain, allowlist):
            raise ValueError(f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            raise ValueError(private_error)
        relay_target = _redacted_relay_target(relay_url)
        payload = {
            "type": "aegis.remote_control.pairing",
            "version": 1,
            "sent_at": checked_at.isoformat(),
            "pairing": public_pairing,
            "token_header": REMOTE_CONTROL_TOKEN_HEADER,
            "allowed_actions": public_pairing["allowed_actions"],
            "pairing_token_included": False,
            "raw_secret_values_included": False,
            "required_controls": list(REMOTE_CONTROL_RELAY_REQUIRED_CONTROLS),
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        request = Request(
            str(relay_url),
            data=body,
            headers={
                "Authorization": f"Bearer {relay_auth_token}",
                "Content-Type": "application/json",
                "User-Agent": "Aegis-Agent/0.1",
            },
            method="POST",
        )
        try:
            response_context = _open_without_redirects(request, timeout=10)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ValueError("HTTP redirects are not followed for remote-control relay registration") from exc
            raise ValueError(f"remote-control relay registration failed with status {exc.code}") from exc
        except URLError as exc:
            raise ValueError(f"remote-control relay registration failed: {exc.reason}") from exc
        with response_context as response:
            response_status = response.getcode() if hasattr(response, "getcode") else None
            response_body = response.read(2048)
        pairing["relay_registration"] = {
            "relay_target": relay_target,
            "relay_auth_sha256": _token_hash(relay_auth_token),
            "registered_at": checked_at.isoformat(),
            "pairing_token_relayed": False,
            "raw_secret_values_included": False,
        }
        self._save()
        return {
            "status": "relay_registered",
            "mode": "approved_outbound_relay_registration",
            "outbound_relay_enabled": True,
            "relay_action_proxy_enabled": True,
            "relay_configured": True,
            "relay_target": relay_target,
            "relay_url_redacted": True,
            "pairing": public_pairing,
            "pairing_token_relayed": False,
            "relay_auth_secret_used": True,
            "relay_response_status": response_status,
            "relay_response_bytes": len(response_body),
            "mobile_gateway_contract": _mobile_gateway_contract(configured=True),
            "raw_secret_values_included": False,
            "configured_controls": [
                "explicit_operator_enablement",
                "brokered_relay_auth",
                "relay_origin_allowlist",
                "scoped_pairing_token_exchange",
                "relay_action_authorization",
                "audit_receipts_without_tokens",
                "local_revocation",
                "approved_relay_revocation_propagation",
                "approved_relay_action_pull",
                "approved_relay_directory_publish",
                "approved_relay_notification_publish",
                "mobile_gateway_delivery_contract",
                "approved_brokered_native_apns_fcm_push",
            ],
            "remaining_controls": [
                "native_push_provider_lifecycle",
                "broad_cloud_relay_service",
            ],
        }

    def publish_relay_directory(
        self,
        pairing_id: str,
        *,
        directory: dict[str, Any],
        relay_auth_token: str,
        allowlist: tuple[str, ...],
        approved: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not approved:
            raise PermissionError("remote-control relay directory publish requires explicit approval")
        self._load()
        checked_at = _utc_now(now)
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        relay_registration = pairing.get("relay_registration")
        if not isinstance(relay_registration, dict):
            raise ValueError("remote-control relay directory publish requires a registered relay")
        if not relay_auth_token.strip():
            raise ValueError("remote-control relay directory publish requires a brokered relay auth token")
        stored_hash = str(relay_registration.get("relay_auth_sha256") or "")
        if not stored_hash or not secrets.compare_digest(stored_hash, _token_hash(relay_auth_token)):
            raise PermissionError("remote-control relay directory publish auth does not match registration")
        public_pairing = self._public_pairing(pairing, now=checked_at)
        if public_pairing["status"] != "active":
            raise ValueError("remote-control relay directory publish requires an active pairing")
        if not isinstance(directory, dict) or directory.get("status") != "remote_directory_available":
            raise ValueError("remote-control relay directory publish requires a sanitized directory payload")
        directory_pairing = directory.get("pairing")
        if isinstance(directory_pairing, dict) and str(directory_pairing.get("id") or "") != pairing["id"]:
            raise ValueError("remote-control relay directory pairing does not match registration")
        if directory.get("pairing_token_relayed") or directory.get("raw_secret_values_included") or directory.get("user_request_included") or directory.get("plan_receipt_included"):
            raise ValueError("remote-control relay directory publish requires redacted metadata-only directory state")
        sanitized_directory = _sanitize_remote_directory_for_relay(directory, pairing=public_pairing)
        relay_target = str(relay_registration.get("relay_target") or "")
        parsed = urlparse(relay_target)
        validation_error = _validate_url(parsed)
        if validation_error:
            raise ValueError(validation_error)
        if parsed.scheme != "https":
            raise ValueError("remote-control relay URL must use https")
        domain = parsed.hostname or ""
        if not _allowed_domain(domain, allowlist):
            raise ValueError(f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            raise ValueError(private_error)
        payload = {
            "type": "aegis.remote_control.directory",
            "version": 1,
            "sent_at": checked_at.isoformat(),
            "pairing_id": pairing["id"],
            "pairing": public_pairing,
            "directory": sanitized_directory,
            "pairing_token_included": False,
            "user_request_included": False,
            "plan_receipt_included": False,
            "relay_auth_token_included": False,
            "raw_secret_values_included": False,
            "required_controls": ["scoped_remote_directory", "audit_receipts_without_tokens"],
        }
        request = Request(
            relay_target,
            data=json.dumps(payload, sort_keys=True).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {relay_auth_token}",
                "Content-Type": "application/json",
                "User-Agent": "Aegis-Agent/0.1",
            },
            method="POST",
        )
        try:
            response_context = _open_without_redirects(request, timeout=10)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ValueError("HTTP redirects are not followed for remote-control relay directory publish") from exc
            raise ValueError(f"remote-control relay directory publish failed with status {exc.code}") from exc
        except URLError as exc:
            raise ValueError(f"remote-control relay directory publish failed: {exc.reason}") from exc
        with response_context as response:
            response_status = response.getcode() if hasattr(response, "getcode") else None
            response_body = response.read(2048)
        relay_registration["last_directory_publish_at"] = checked_at.isoformat()
        relay_registration["last_directory_publish_response_status"] = response_status
        relay_registration["last_directory_publish_task_count"] = int(sanitized_directory.get("task_count") or 0)
        relay_registration["pairing_token_relayed"] = False
        relay_registration["raw_secret_values_included"] = False
        self._save()
        return {
            "status": "relay_directory_published",
            "mode": "approved_relay_directory_snapshot",
            "pairing": public_pairing,
            "relay_target": relay_target,
            "relay_response_status": response_status,
            "relay_response_bytes": len(response_body),
            "directory_scope": sanitized_directory.get("scope", {}),
            "directory_task_count": int(sanitized_directory.get("task_count") or 0),
            "directory": sanitized_directory,
            "pairing_token_relayed": False,
            "relay_auth_secret_used": True,
            "relay_auth_token_captured": False,
            "user_request_included": False,
            "plan_receipt_included": False,
            "raw_secret_values_included": False,
        }

    def publish_relay_notification(
        self,
        pairing_id: str,
        *,
        notification: dict[str, Any],
        relay_auth_token: str,
        allowlist: tuple[str, ...],
        approved: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not approved:
            raise PermissionError("remote-control relay notification publish requires explicit approval")
        self._load()
        checked_at = _utc_now(now)
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        relay_registration = pairing.get("relay_registration")
        if not isinstance(relay_registration, dict):
            raise ValueError("remote-control relay notification publish requires a registered relay")
        if not relay_auth_token.strip():
            raise ValueError("remote-control relay notification publish requires a brokered relay auth token")
        stored_hash = str(relay_registration.get("relay_auth_sha256") or "")
        if not stored_hash or not secrets.compare_digest(stored_hash, _token_hash(relay_auth_token)):
            raise PermissionError("remote-control relay notification publish auth does not match registration")
        public_pairing = self._public_pairing(pairing, now=checked_at)
        if public_pairing["status"] != "active":
            raise ValueError("remote-control relay notification publish requires an active pairing")
        if not isinstance(notification, dict) or notification.get("status") != "remote_notification_available":
            raise ValueError("remote-control relay notification publish requires a sanitized notification payload")
        if notification.get("pairing_token_relayed") or notification.get("raw_secret_values_included") or notification.get("user_request_included") or notification.get("plan_receipt_included"):
            raise ValueError("remote-control relay notification publish requires redacted metadata-only notification state")
        notification_pairing = notification.get("pairing")
        if isinstance(notification_pairing, dict) and str(notification_pairing.get("id") or "") != pairing["id"]:
            raise ValueError("remote-control relay notification pairing does not match registration")
        sanitized_notification = _sanitize_remote_notification_for_relay(notification, pairing=public_pairing)
        relay_target = str(relay_registration.get("relay_target") or "")
        parsed = urlparse(relay_target)
        validation_error = _validate_url(parsed)
        if validation_error:
            raise ValueError(validation_error)
        if parsed.scheme != "https":
            raise ValueError("remote-control relay URL must use https")
        domain = parsed.hostname or ""
        if not _allowed_domain(domain, allowlist):
            raise ValueError(f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            raise ValueError(private_error)
        outbox_id = _new_relay_outbox_id()
        payload = {
            "type": "aegis.remote_control.notification",
            "version": 1,
            "delivery_id": outbox_id,
            "idempotency_key": outbox_id,
            "sent_at": checked_at.isoformat(),
            "pairing_id": pairing["id"],
            "pairing": public_pairing,
            "notification": sanitized_notification,
            "delivery_contract": _mobile_gateway_contract(configured=True),
            "pairing_token_included": False,
            "relay_auth_token_included": False,
            "user_request_included": False,
            "plan_receipt_included": False,
            "raw_secret_values_included": False,
            "required_controls": ["scoped_remote_notification", "audit_receipts_without_tokens"],
        }
        self._enqueue_relay_notification(
            outbox_id=outbox_id,
            pairing_id=pairing["id"],
            relay_target=relay_target,
            notification=sanitized_notification,
            payload=payload,
            now=checked_at,
        )
        self._mark_relay_outbox_attempt(outbox_id, now=checked_at)
        try:
            response_status, response_body = _post_relay_payload(relay_target, payload=payload, relay_auth_token=relay_auth_token)
        except HTTPError as exc:
            self._mark_relay_outbox_failed(outbox_id, now=checked_at, error=f"status {exc.code}", response_status=exc.code)
            if 300 <= exc.code < 400:
                raise ValueError("HTTP redirects are not followed for remote-control relay notification publish") from exc
            raise ValueError(f"remote-control relay notification publish failed with status {exc.code}") from exc
        except URLError as exc:
            self._mark_relay_outbox_failed(outbox_id, now=checked_at, error=str(exc.reason), response_status=None)
            raise ValueError(f"remote-control relay notification publish failed: {exc.reason}") from exc
        relay_receipt = _parse_relay_delivery_receipt(response_body)
        self._mark_relay_outbox_delivered(outbox_id, now=checked_at, response_status=response_status, response_bytes=len(response_body), relay_receipt=relay_receipt)
        relay_registration["last_notification_publish_at"] = checked_at.isoformat()
        relay_registration["last_notification_publish_response_status"] = response_status
        relay_registration["last_notification_publish_event"] = sanitized_notification["event"]
        relay_registration["pairing_token_relayed"] = False
        relay_registration["raw_secret_values_included"] = False
        self._save()
        return {
            "status": "relay_notification_published",
            "mode": "approved_relay_notification",
            "pairing": public_pairing,
            "relay_target": relay_target,
            "relay_response_status": response_status,
            "relay_response_bytes": len(response_body),
            "relay_receipt": self._relay_outbox_item(outbox_id).get("relay_receipt"),
            "mobile_gateway_contract": _mobile_gateway_contract(configured=True),
            "outbox_id": outbox_id,
            "outbox_status": self._relay_outbox_item(outbox_id).get("status"),
            "relay_acknowledged": self._relay_outbox_item(outbox_id).get("status") == "acknowledged",
            "notification_event": sanitized_notification["event"],
            "notification": sanitized_notification,
            "pairing_token_relayed": False,
            "relay_auth_secret_used": True,
            "relay_auth_token_captured": False,
            "user_request_included": False,
            "plan_receipt_included": False,
            "raw_secret_values_included": False,
        }

    def publish_native_push_notification(
        self,
        pairing_id: str,
        *,
        notification: dict[str, Any],
        provider: str,
        push_auth_token: str,
        device_token: str,
        allowlist: tuple[str, ...],
        approved: bool = False,
        apns_topic: str | None = None,
        fcm_project_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not approved:
            raise PermissionError("remote-control native push requires explicit approval")
        self._load()
        checked_at = _utc_now(now)
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        public_pairing = self._public_pairing(pairing, now=checked_at)
        if public_pairing["status"] != "active":
            raise ValueError("remote-control native push requires an active pairing")
        normalized_provider = _normalize_native_push_provider(provider)
        if not push_auth_token.strip():
            raise ValueError("remote-control native push requires a brokered provider auth token")
        if not device_token.strip():
            raise ValueError("remote-control native push requires a brokered device token")
        if not isinstance(notification, dict) or notification.get("status") != "remote_notification_available":
            raise ValueError("remote-control native push requires a sanitized notification payload")
        if notification.get("pairing_token_relayed") or notification.get("raw_secret_values_included") or notification.get("user_request_included") or notification.get("plan_receipt_included"):
            raise ValueError("remote-control native push requires redacted metadata-only notification state")
        notification_pairing = notification.get("pairing")
        if isinstance(notification_pairing, dict) and str(notification_pairing.get("id") or "") != pairing["id"]:
            raise ValueError("remote-control native push notification pairing does not match target pairing")
        sanitized_notification = _sanitize_remote_notification_for_relay(notification, pairing=public_pairing)
        target_url = _native_push_target_url(normalized_provider, device_token=device_token, fcm_project_id=fcm_project_id)
        parsed = urlparse(target_url)
        validation_error = _validate_url(parsed)
        if validation_error:
            raise ValueError(validation_error)
        if parsed.scheme != "https":
            raise ValueError("remote-control native push requires https")
        domain = parsed.hostname or ""
        if not _allowed_domain(domain, allowlist):
            raise ValueError(f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            raise ValueError(private_error)
        push_payload = _native_push_payload(
            normalized_provider,
            notification=sanitized_notification,
            pairing=public_pairing,
            device_token=device_token,
        )
        response_status, response_body = _post_native_push_payload(
            normalized_provider,
            target_url=target_url,
            payload=push_payload,
            push_auth_token=push_auth_token,
            apns_topic=apns_topic,
        )
        receipt = _native_push_receipt(
            provider=normalized_provider,
            response_status=response_status,
            response_body=response_body,
            device_token=device_token,
            target_url=target_url,
        )
        return {
            "status": "native_push_published",
            "mode": "approved_native_push_notification",
            "provider": normalized_provider,
            "pairing": public_pairing,
            "push_target": receipt["push_target"],
            "push_response_status": response_status,
            "push_response_bytes": len(response_body),
            "provider_accepted": receipt["delivery_state"] == "accepted",
            "native_push_receipt": receipt,
            "mobile_gateway_contract": _mobile_gateway_contract(configured=True),
            "notification_event": sanitized_notification["event"],
            "notification": sanitized_notification,
            "pairing_token_relayed": False,
            "push_auth_secret_used": True,
            "push_auth_token_captured": False,
            "device_token_secret_used": True,
            "raw_device_token_captured": False,
            "raw_device_tokens_included": False,
            "user_request_included": False,
            "plan_receipt_included": False,
            "raw_secret_values_included": False,
        }

    def relay_outbox(self, *, status: str | None = None, limit: int = 20) -> dict[str, Any]:
        self._load()
        normalized_status = _optional_clean_string(status)
        max_items = max(1, min(int(limit), MAX_RELAY_OUTBOX_ITEMS))
        rows = [
            item
            for item in self._relay_outbox
            if normalized_status is None or item.get("status") == normalized_status
        ][:max_items]
        counts: dict[str, int] = {}
        for item in self._relay_outbox:
            item_status = str(item.get("status") or "unknown")
            counts[item_status] = counts.get(item_status, 0) + 1
        return {
            "status": "relay_notification_outbox",
            "mode": "metadata_only_relay_delivery_state",
            "item_count": len(rows),
            "status_counts": counts,
            "items": [_public_relay_outbox_item(item) for item in rows],
            "pairing_token_relayed": False,
            "relay_auth_token_captured": False,
            "user_request_included": False,
            "plan_receipt_included": False,
            "raw_secret_values_included": False,
        }

    def retry_relay_notifications(
        self,
        pairing_id: str,
        *,
        relay_auth_token: str,
        allowlist: tuple[str, ...],
        approved: bool = False,
        limit: int = 10,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not approved:
            raise PermissionError("remote-control relay outbox retry requires explicit approval")
        self._load()
        checked_at = _utc_now(now)
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        relay_registration = pairing.get("relay_registration")
        if not isinstance(relay_registration, dict):
            raise ValueError("remote-control relay outbox retry requires a registered relay")
        if not relay_auth_token.strip():
            raise ValueError("remote-control relay outbox retry requires a brokered relay auth token")
        stored_hash = str(relay_registration.get("relay_auth_sha256") or "")
        if not stored_hash or not secrets.compare_digest(stored_hash, _token_hash(relay_auth_token)):
            raise PermissionError("remote-control relay outbox retry auth does not match registration")
        public_pairing = self._public_pairing(pairing, now=checked_at)
        if public_pairing["status"] != "active":
            raise ValueError("remote-control relay outbox retry requires an active pairing")
        relay_target = _validated_relay_target(str(relay_registration.get("relay_target") or ""), allowlist=allowlist)
        retry_limit = max(1, min(int(limit), 25))
        candidates = [
            item
            for item in self._relay_outbox
            if item.get("kind") == "notification"
            and item.get("pairing_id") == pairing["id"]
            and item.get("status") in {"pending", "failed", "retry_pending"}
            and _relay_retry_due(item, now=checked_at)
        ][:retry_limit]
        results: list[dict[str, Any]] = []
        for item in candidates:
            outbox_id = str(item["id"])
            payload = dict(item.get("payload") if isinstance(item.get("payload"), dict) else {})
            notification = item.get("notification") if isinstance(item.get("notification"), dict) else {}
            sanitized_notification = _sanitize_remote_notification_for_relay(notification, pairing=public_pairing)
            payload.update(
                {
                    "type": "aegis.remote_control.notification",
                    "version": 1,
                    "delivery_id": outbox_id,
                    "idempotency_key": outbox_id,
                    "sent_at": checked_at.isoformat(),
                    "pairing_id": pairing["id"],
                    "pairing": public_pairing,
                    "notification": sanitized_notification,
                    "pairing_token_included": False,
                    "relay_auth_token_included": False,
                    "user_request_included": False,
                    "plan_receipt_included": False,
                    "raw_secret_values_included": False,
                }
            )
            self._mark_relay_outbox_attempt(outbox_id, now=checked_at)
            try:
                response_status, response_body = _post_relay_payload(relay_target, payload=payload, relay_auth_token=relay_auth_token)
            except HTTPError as exc:
                self._mark_relay_outbox_failed(outbox_id, now=checked_at, error=f"status {exc.code}", response_status=exc.code)
                results.append({"outbox_id": outbox_id, "status": "failed", "error": f"status {exc.code}", "response_status": exc.code})
                continue
            except URLError as exc:
                self._mark_relay_outbox_failed(outbox_id, now=checked_at, error=str(exc.reason), response_status=None)
                results.append({"outbox_id": outbox_id, "status": "failed", "error": str(exc.reason), "response_status": None})
                continue
            relay_receipt = _parse_relay_delivery_receipt(response_body)
            self._mark_relay_outbox_delivered(outbox_id, now=checked_at, response_status=response_status, response_bytes=len(response_body), relay_receipt=relay_receipt)
            updated = self._relay_outbox_item(outbox_id)
            results.append(
                {
                    "outbox_id": outbox_id,
                    "status": updated.get("status"),
                    "response_status": response_status,
                    "response_bytes": len(response_body),
                    "relay_receipt": updated.get("relay_receipt"),
                    "relay_acknowledged": updated.get("status") == "acknowledged",
                }
            )
        relay_registration["last_notification_retry_at"] = checked_at.isoformat()
        relay_registration["last_notification_retry_count"] = len(results)
        relay_registration["pairing_token_relayed"] = False
        relay_registration["raw_secret_values_included"] = False
        self._save()
        acknowledged = sum(1 for result in results if result.get("status") == "acknowledged")
        failed = sum(1 for result in results if result.get("status") == "failed")
        return {
            "status": "relay_notification_outbox_retried",
            "mode": "approved_relay_notification_retry",
            "pairing": public_pairing,
            "relay_target": relay_target,
            "attempted_count": len(results),
            "acknowledged_count": acknowledged,
            "failed_count": failed,
            "results": results,
            "outbox": self.relay_outbox(limit=20),
            "pairing_token_relayed": False,
            "relay_auth_token_captured": False,
            "raw_secret_values_included": False,
        }

    def authorize_relay_action(
        self,
        pairing_id: str,
        relay_auth_token: str,
        *,
        action: str,
        task_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        self._load()
        checked_at = _utc_now(now)
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            return None
        relay_registration = pairing.get("relay_registration")
        if not isinstance(relay_registration, dict):
            return None
        stored_hash = str(relay_registration.get("relay_auth_sha256") or "")
        if not stored_hash or not secrets.compare_digest(stored_hash, _token_hash(relay_auth_token)):
            return None
        public_pairing = self._public_pairing(pairing, now=checked_at)
        if public_pairing["status"] != "active":
            return None
        allowed_actions = set(public_pairing.get("allowed_actions") or ())
        if action not in allowed_actions:
            return None
        scoped_task = public_pairing.get("task_id")
        if scoped_task and scoped_task != task_id:
            return None
        return {
            "pairing": public_pairing,
            "relay_target": str(relay_registration.get("relay_target") or ""),
            "relay_registered_at": relay_registration.get("registered_at"),
            "pairing_token_relayed": False,
            "raw_secret_values_included": False,
        }

    def pull_relay_actions(
        self,
        pairing_id: str,
        *,
        relay_auth_token: str,
        allowlist: tuple[str, ...],
        approved: bool = False,
        limit: int = 10,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not approved:
            raise PermissionError("remote-control relay pull requires explicit approval")
        self._load()
        checked_at = _utc_now(now)
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        relay_registration = pairing.get("relay_registration")
        if not isinstance(relay_registration, dict):
            raise ValueError("remote-control relay pull requires a registered relay")
        if not relay_auth_token.strip():
            raise ValueError("remote-control relay pull requires a brokered relay auth token")
        stored_hash = str(relay_registration.get("relay_auth_sha256") or "")
        if not stored_hash or not secrets.compare_digest(stored_hash, _token_hash(relay_auth_token)):
            raise PermissionError("remote-control relay pull auth does not match registration")
        public_pairing = self._public_pairing(pairing, now=checked_at)
        if public_pairing["status"] != "active":
            raise ValueError("remote-control relay pull requires an active pairing")
        relay_target = str(relay_registration.get("relay_target") or "")
        parsed = urlparse(relay_target)
        validation_error = _validate_url(parsed)
        if validation_error:
            raise ValueError(validation_error)
        if parsed.scheme != "https":
            raise ValueError("remote-control relay URL must use https")
        domain = parsed.hostname or ""
        if not _allowed_domain(domain, allowlist):
            raise ValueError(f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            raise ValueError(private_error)
        action_limit = max(1, min(int(limit), 25))
        payload = {
            "type": "aegis.remote_control.pull",
            "version": 1,
            "sent_at": checked_at.isoformat(),
            "pairing_id": pairing["id"],
            "action_limit": action_limit,
            "pairing_token_included": False,
            "raw_secret_values_included": False,
            "required_controls": ["relay_action_authorization", "audit_receipts_without_tokens"],
        }
        request = Request(
            relay_target,
            data=json.dumps(payload, sort_keys=True).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {relay_auth_token}",
                "Content-Type": "application/json",
                "User-Agent": "Aegis-Agent/0.1",
            },
            method="POST",
        )
        try:
            response_context = _open_without_redirects(request, timeout=10)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ValueError("HTTP redirects are not followed for remote-control relay pull") from exc
            raise ValueError(f"remote-control relay pull failed with status {exc.code}") from exc
        except URLError as exc:
            raise ValueError(f"remote-control relay pull failed: {exc.reason}") from exc
        with response_context as response:
            response_status = response.getcode() if hasattr(response, "getcode") else None
            response_body = response.read(65536)
        try:
            decoded = json.loads(response_body.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("remote-control relay pull returned invalid JSON") from exc
        actions_source = decoded.get("actions", []) if isinstance(decoded, dict) else []
        if not isinstance(actions_source, list):
            raise ValueError("remote-control relay pull actions must be a JSON array")
        actions = [
            _normalize_relay_action_envelope(action, public_pairing)
            for action in actions_source[:action_limit]
            if isinstance(action, dict)
        ]
        relay_registration["last_pull_at"] = checked_at.isoformat()
        relay_registration["last_pull_response_status"] = response_status
        relay_registration["last_pull_action_count"] = len(actions)
        relay_registration["pairing_token_relayed"] = False
        relay_registration["raw_secret_values_included"] = False
        self._save()
        executable_count = sum(1 for action in actions if action["accepted"])
        return {
            "status": "relay_actions_pulled",
            "mode": "approved_relay_action_pull",
            "pairing": public_pairing,
            "relay_target": relay_target,
            "relay_response_status": response_status,
            "relay_response_bytes": len(response_body),
            "action_count": len(actions),
            "executable_action_count": executable_count,
            "actions": actions,
            "pairing_token_relayed": False,
            "relay_auth_secret_used": True,
            "relay_auth_token_captured": False,
            "raw_secret_values_included": False,
        }

    def authorize(self, token: str, *, now: datetime | None = None) -> dict[str, Any] | None:
        if not token:
            return None
        self._load()
        checked_at = _utc_now(now)
        supplied_hash = _token_hash(token)
        for pairing in self._pairings.values():
            if not secrets.compare_digest(str(pairing["token_sha256"]), supplied_hash):
                continue
            public = self._public_pairing(pairing, now=checked_at)
            if public["status"] == "active":
                return public
            return None
        return None

    def public_pairing(self, pairing_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        self._load()
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        return self._public_pairing(pairing, now=_utc_now(now))

    def authorize_action(
        self,
        token: str,
        *,
        action: str,
        task_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        pairing = self.authorize(token, now=now)
        if pairing is None:
            return None
        allowed_actions = set(pairing.get("allowed_actions") or ())
        if action not in allowed_actions:
            return None
        scoped_task = pairing.get("task_id")
        if scoped_task and scoped_task != task_id:
            return None
        return pairing

    def revoke(
        self,
        pairing_id: str,
        *,
        now: datetime | None = None,
        relay_auth_token: str | None = None,
        notify_relay: bool = False,
    ) -> dict[str, Any]:
        self._load()
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        revoked_at = _utc_now(now)
        if pairing.get("revoked_at") is None:
            pairing["revoked_at"] = revoked_at.isoformat()
        relay_result = self._notify_relay_revocation(pairing, relay_auth_token=relay_auth_token or "", now=revoked_at) if notify_relay else {}
        self._save()
        return {
            "status": "revoked",
            "pairing": self._public_pairing(pairing, now=revoked_at),
            "relay_revocation_available": _relay_registered(pairing),
            "relay_revocation_propagated": bool(relay_result),
            **relay_result,
            "pairing_token_relayed": False,
            "raw_secret_values_included": False,
        }

    def _notify_relay_revocation(
        self,
        pairing: dict[str, Any],
        *,
        relay_auth_token: str,
        now: datetime,
    ) -> dict[str, Any]:
        relay_registration = pairing.get("relay_registration")
        if not isinstance(relay_registration, dict):
            raise ValueError("remote-control relay revocation requires a registered relay")
        if not relay_auth_token.strip():
            raise ValueError("remote-control relay revocation requires a brokered relay auth token")
        stored_hash = str(relay_registration.get("relay_auth_sha256") or "")
        if not stored_hash or not secrets.compare_digest(stored_hash, _token_hash(relay_auth_token)):
            raise PermissionError("remote-control relay revocation auth does not match registration")
        relay_target = str(relay_registration.get("relay_target") or "")
        payload = {
            "type": "aegis.remote_control.revocation",
            "version": 1,
            "sent_at": now.isoformat(),
            "pairing_id": pairing["id"],
            "revoked_at": pairing.get("revoked_at") or now.isoformat(),
            "pairing_token_included": False,
            "raw_secret_values_included": False,
            "required_controls": ["revocation_and_expiry_propagation", "audit_receipts_without_tokens"],
        }
        request = Request(
            relay_target,
            data=json.dumps(payload, sort_keys=True).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {relay_auth_token}",
                "Content-Type": "application/json",
                "User-Agent": "Aegis-Agent/0.1",
            },
            method="POST",
        )
        try:
            response_context = _open_without_redirects(request, timeout=10)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ValueError("HTTP redirects are not followed for remote-control relay revocation") from exc
            raise ValueError(f"remote-control relay revocation failed with status {exc.code}") from exc
        except URLError as exc:
            raise ValueError(f"remote-control relay revocation failed: {exc.reason}") from exc
        with response_context as response:
            response_status = response.getcode() if hasattr(response, "getcode") else None
            response_body = response.read(2048)
        relay_registration["revocation_relayed_at"] = now.isoformat()
        relay_registration["revocation_response_status"] = response_status
        relay_registration["pairing_token_relayed"] = False
        relay_registration["raw_secret_values_included"] = False
        return {
            "relay_target": relay_target,
            "relay_response_status": response_status,
            "relay_response_bytes": len(response_body),
            "relay_auth_secret_used": True,
        }

    def _load(self) -> None:
        if self.store_path is None or not self.store_path.exists():
            return
        with self.store_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        rows = payload.get("pairings", []) if isinstance(payload, dict) else []
        pairings: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            pairing_id = str(row.get("id") or "")
            token_hash = str(row.get("token_sha256") or "")
            if not pairing_id or not token_hash:
                continue
            allowed_source = row.get("allowed_actions")
            pairings[pairing_id] = {
                "id": pairing_id,
                "label": str(row.get("label") or "remote control")[:80],
                "session_id": _optional_clean_string(row.get("session_id")),
                "task_id": _optional_clean_string(row.get("task_id")),
                "allowed_actions": _normalize_allowed_actions(allowed_source)
                if isinstance(allowed_source, list)
                else [],
                "token_sha256": token_hash,
                "created_at": str(row.get("created_at") or _utc_now(None).isoformat()),
                "expires_at": str(row.get("expires_at") or _utc_now(None).isoformat()),
                "revoked_at": _optional_clean_string(row.get("revoked_at")),
                "relay_registration": _normalize_relay_registration(row.get("relay_registration")),
            }
        self._pairings = pairings
        self._relay_outbox = _normalize_relay_outbox(payload.get("relay_outbox") if isinstance(payload, dict) else None)

    def _save(self) -> None:
        if self.store_path is None:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "pairings": list(self._pairings.values()),
            "relay_outbox": self._relay_outbox[:MAX_RELAY_OUTBOX_ITEMS],
            "raw_secret_values_included": False,
        }
        temp_path = self.store_path.with_suffix(self.store_path.suffix + ".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, self.store_path)
        os.chmod(self.store_path, 0o600)

    def _public_pairing(self, pairing: dict[str, Any], *, now: datetime) -> dict[str, Any]:
        expires_at = datetime.fromisoformat(str(pairing["expires_at"]))
        revoked_at = pairing.get("revoked_at")
        if revoked_at:
            status = "revoked"
        elif expires_at <= now:
            status = "expired"
        else:
            status = "active"
        relay_registration = pairing.get("relay_registration")
        relay_registered = isinstance(relay_registration, dict) and bool(relay_registration.get("relay_auth_sha256"))
        relay_revocation_relayed_at = str(relay_registration.get("revocation_relayed_at") or "") if isinstance(relay_registration, dict) else ""
        relay_last_pull_at = str(relay_registration.get("last_pull_at") or "") if isinstance(relay_registration, dict) else ""
        relay_last_directory_publish_at = str(relay_registration.get("last_directory_publish_at") or "") if isinstance(relay_registration, dict) else ""
        relay_last_notification_publish_at = str(relay_registration.get("last_notification_publish_at") or "") if isinstance(relay_registration, dict) else ""
        return {
            "id": pairing["id"],
            "label": pairing["label"],
            "session_id": pairing.get("session_id"),
            "task_id": pairing.get("task_id"),
            "allowed_actions": list(pairing.get("allowed_actions") or ()),
            "created_at": pairing["created_at"],
            "expires_at": pairing["expires_at"],
            "revoked_at": revoked_at,
            "status": status,
            "relay_registered": relay_registered,
            "relay_target": str(relay_registration.get("relay_target") or "") if isinstance(relay_registration, dict) else None,
            "relay_action_proxy_enabled": bool(status == "active" and relay_registered),
            "relay_action_pull_enabled": bool(status == "active" and relay_registered),
            "relay_directory_publish_enabled": bool(status == "active" and relay_registered),
            "relay_notification_enabled": bool(status == "active" and relay_registered),
            "relay_last_pull_at": relay_last_pull_at or None,
            "relay_last_directory_publish_at": relay_last_directory_publish_at or None,
            "relay_last_notification_publish_at": relay_last_notification_publish_at or None,
            "relay_notification_outbox_count": sum(1 for item in self._relay_outbox if item.get("pairing_id") == pairing["id"] and item.get("status") in {"pending", "failed", "retry_pending"}),
            "relay_revocation_propagated": bool(relay_revocation_relayed_at),
            "relay_revocation_relayed_at": relay_revocation_relayed_at or None,
        }

    def _enqueue_relay_notification(
        self,
        *,
        outbox_id: str,
        pairing_id: str,
        relay_target: str,
        notification: dict[str, Any],
        payload: dict[str, Any],
        now: datetime,
    ) -> str:
        item = {
            "id": outbox_id,
            "kind": "notification",
            "status": "pending",
            "pairing_id": pairing_id,
            "relay_target": relay_target,
            "event": str(notification.get("event") or ""),
            "task_id": _optional_clean_string(notification.get("task_id")),
            "session_id": _optional_clean_string(notification.get("session_id")),
            "notification": notification,
            "payload": payload,
            "attempt_count": 0,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "last_attempt_at": None,
            "delivered_at": None,
            "acknowledged_at": None,
            "response_status": None,
            "response_bytes": 0,
            "relay_receipt": {
                "receipt_present": False,
                "raw_response_body_included": False,
            },
            "last_error": None,
            "pairing_token_relayed": False,
            "relay_auth_token_captured": False,
            "user_request_included": False,
            "plan_receipt_included": False,
            "raw_secret_values_included": False,
        }
        self._relay_outbox.insert(0, item)
        self._relay_outbox = self._relay_outbox[:MAX_RELAY_OUTBOX_ITEMS]
        self._save()
        return outbox_id

    def _relay_outbox_item(self, outbox_id: str) -> dict[str, Any]:
        for item in self._relay_outbox:
            if item.get("id") == outbox_id:
                return item
        raise KeyError(outbox_id)

    def _mark_relay_outbox_attempt(self, outbox_id: str, *, now: datetime) -> None:
        item = self._relay_outbox_item(outbox_id)
        item["status"] = "retry_pending" if int(item.get("attempt_count") or 0) else "pending"
        item["attempt_count"] = int(item.get("attempt_count") or 0) + 1
        item["last_attempt_at"] = now.isoformat()
        item["updated_at"] = now.isoformat()
        item["last_error"] = None
        self._save()

    def _mark_relay_outbox_delivered(self, outbox_id: str, *, now: datetime, response_status: int | None, response_bytes: int, relay_receipt: dict[str, Any]) -> None:
        item = self._relay_outbox_item(outbox_id)
        receipt_accepted = _relay_receipt_accepted(relay_receipt)
        item["status"] = "acknowledged" if response_status is not None and 200 <= int(response_status) < 300 and receipt_accepted else "delivered"
        item["delivered_at"] = now.isoformat()
        item["acknowledged_at"] = now.isoformat() if item["status"] == "acknowledged" else None
        item["updated_at"] = now.isoformat()
        item["response_status"] = response_status
        item["response_bytes"] = int(response_bytes)
        item["relay_receipt"] = relay_receipt
        item["last_error"] = None if item["status"] == "acknowledged" else "relay receipt not accepted"
        item.pop("next_retry_after", None)
        self._save()

    def _mark_relay_outbox_failed(self, outbox_id: str, *, now: datetime, error: str, response_status: int | None) -> None:
        item = self._relay_outbox_item(outbox_id)
        item["status"] = "failed"
        item["updated_at"] = now.isoformat()
        item["response_status"] = response_status
        item["last_error"] = str(error)[:240]
        item["next_retry_after"] = (now + timedelta(seconds=min(300, 30 * max(1, int(item.get("attempt_count") or 1))))).isoformat()
        self._save()


def build_remote_control_directory(
    pairing: dict[str, Any],
    *,
    store: Any,
    limit: int = 10,
    now: datetime | None = None,
) -> dict[str, Any]:
    checked_at = _utc_now(now)
    task_limit = _clamp_directory_limit(limit)
    scope = _remote_directory_scope(pairing)
    if pairing.get("status") != "active":
        raise ValueError("remote-control directory requires an active pairing")
    rows = _scoped_directory_task_rows(pairing, store=store, limit=task_limit)
    tasks = [_remote_directory_task(row, pairing) for row in rows]
    return {
        "status": "remote_directory_available",
        "mode": "scoped_remote_directory",
        "checked_at": checked_at.isoformat(),
        "pairing": pairing,
        "scope": scope,
        "task_count": len(tasks),
        "task_limit": task_limit,
        "tasks": tasks,
        "broad_task_listing": False,
        "pairing_token_relayed": False,
        "raw_secret_values_included": False,
        "user_request_included": False,
        "plan_receipt_included": False,
        "directory_controls": [
            "active_pairing_required",
            "task_or_session_scope_required_for_task_listing",
            "sanitized_task_metadata_only",
            "no_user_request_plan_or_receipt",
        ],
    }


def build_remote_control_notification(
    pairing: dict[str, Any],
    *,
    store: Any,
    event: str = "directory-updated",
    task_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    checked_at = _utc_now(now)
    if pairing.get("status") != "active":
        raise ValueError("remote-control notification requires an active pairing")
    normalized_event = _normalize_relay_notification_event(event)
    scoped_task = _optional_clean_string(pairing.get("task_id"))
    requested_task = _optional_clean_string(task_id)
    if scoped_task and requested_task and scoped_task != requested_task:
        raise ValueError("remote-control notification task is outside pairing scope")
    selected_task = requested_task or scoped_task
    task: dict[str, Any] | None = None
    if selected_task:
        row = store.get_task(selected_task)
        if row:
            task = _remote_directory_task(row, pairing)
    return {
        "status": "remote_notification_available",
        "mode": "scoped_remote_notification",
        "checked_at": checked_at.isoformat(),
        "pairing": pairing,
        "event": normalized_event,
        "task_id": selected_task,
        "session_id": _optional_clean_string(pairing.get("session_id")) or (task or {}).get("session_id"),
        "task": task,
        "pairing_token_relayed": False,
        "raw_secret_values_included": False,
        "user_request_included": False,
        "plan_receipt_included": False,
        "notification_controls": [
            "active_pairing_required",
            "metadata_only",
            "no_user_request_plan_or_receipt",
        ],
    }


def _sanitize_remote_directory_for_relay(directory: dict[str, Any], *, pairing: dict[str, Any]) -> dict[str, Any]:
    scope_source = directory.get("scope") if isinstance(directory.get("scope"), dict) else {}
    scope = {
        "type": str(scope_source.get("type") or "unknown")[:40],
        "task_id": _optional_clean_string(scope_source.get("task_id")),
        "session_id": _optional_clean_string(scope_source.get("session_id")),
        "task_listing": str(scope_source.get("task_listing") or "")[:80],
    }
    tasks = []
    task_source = directory.get("tasks", [])
    if isinstance(task_source, list):
        for item in task_source[:MAX_REMOTE_DIRECTORY_TASKS]:
            task = _sanitize_remote_directory_task(item)
            if task:
                tasks.append(task)
    return {
        "status": "remote_directory_available",
        "mode": "scoped_remote_directory",
        "checked_at": str(directory.get("checked_at") or _utc_now(None).isoformat()),
        "pairing": pairing,
        "scope": scope,
        "task_count": len(tasks),
        "task_limit": _clamp_directory_limit(_safe_int(directory.get("task_limit"), default=MAX_REMOTE_DIRECTORY_TASKS)),
        "tasks": tasks,
        "broad_task_listing": False,
        "pairing_token_relayed": False,
        "raw_secret_values_included": False,
        "user_request_included": False,
        "plan_receipt_included": False,
        "directory_controls": [
            "active_pairing_required",
            "task_or_session_scope_required_for_task_listing",
            "sanitized_task_metadata_only",
            "no_user_request_plan_or_receipt",
        ],
    }


def _sanitize_remote_notification_for_relay(notification: dict[str, Any], *, pairing: dict[str, Any]) -> dict[str, Any]:
    event = _normalize_relay_notification_event(str(notification.get("event") or "directory_updated"))
    task_source = notification.get("task") if isinstance(notification.get("task"), dict) else None
    task = _sanitize_remote_directory_task(task_source) if task_source else None
    task_id = _optional_clean_string(notification.get("task_id")) or (task or {}).get("id")
    scoped_task = _optional_clean_string(pairing.get("task_id"))
    if scoped_task and task_id and scoped_task != task_id:
        raise ValueError("remote-control relay notification task does not match pairing scope")
    session_id = _optional_clean_string(notification.get("session_id")) or (task or {}).get("session_id")
    scoped_session = _optional_clean_string(pairing.get("session_id"))
    if scoped_session and session_id and scoped_session != session_id:
        raise ValueError("remote-control relay notification session does not match pairing scope")
    return {
        "status": "remote_notification_available",
        "mode": "scoped_remote_notification",
        "checked_at": str(notification.get("checked_at") or _utc_now(None).isoformat()),
        "event": event,
        "pairing": pairing,
        "task_id": task_id,
        "session_id": session_id,
        "task": task,
        "metadata_only": True,
        "pairing_token_relayed": False,
        "raw_secret_values_included": False,
        "user_request_included": False,
        "plan_receipt_included": False,
        "notification_controls": [
            "active_pairing_required",
            "scoped_remote_notification",
            "no_user_request_plan_or_receipt",
        ],
    }


def _sanitize_remote_directory_task(item: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    task_id = _optional_clean_string(item.get("id")) or ""
    allowed_source = item.get("allowed_actions", [])
    if not isinstance(allowed_source, list):
        allowed_source = []
    requested_actions = {str(candidate) for candidate in allowed_source if isinstance(candidate, str)}
    allowed_actions = [
        action
        for action in DEFAULT_ALLOWED_TASK_ACTIONS
        if action in requested_actions
    ]
    links = _remote_directory_links(task_id, allowed_actions) if task_id else {}
    return {
        "id": task_id,
        "status": str(item.get("status") or "unknown")[:80],
        "risk_level": str(item.get("risk_level") or "unknown")[:80],
        "session_id": _optional_clean_string(item.get("session_id")),
        "created_at": str(item.get("created_at") or "")[:80],
        "updated_at": str(item.get("updated_at") or "")[:80],
        "allowed_actions": allowed_actions,
        "links": links,
        "metadata_only": True,
    }


def _clamp_directory_limit(limit: int) -> int:
    return max(1, min(int(limit), MAX_REMOTE_DIRECTORY_TASKS))


def _safe_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_relay_notification_event(event: str) -> str:
    normalized = str(event or "").strip().lower().replace("-", "_")
    if normalized not in REMOTE_CONTROL_RELAY_NOTIFICATION_EVENTS:
        allowed = ", ".join(REMOTE_CONTROL_RELAY_NOTIFICATION_EVENTS)
        raise ValueError(f"unsupported remote-control relay notification event {event!r}; allowed: {allowed}")
    return normalized


def _remote_directory_scope(pairing: dict[str, Any]) -> dict[str, Any]:
    task_id = _optional_clean_string(pairing.get("task_id"))
    session_id = _optional_clean_string(pairing.get("session_id"))
    if task_id:
        return {
            "type": "task",
            "task_id": task_id,
            "session_id": session_id,
            "task_listing": "single_task",
        }
    if session_id:
        return {
            "type": "session",
            "task_id": None,
            "session_id": session_id,
            "task_listing": "session_tasks",
        }
    return {
        "type": "pairing",
        "task_id": None,
        "session_id": None,
        "task_listing": "unavailable_without_task_or_session_scope",
    }


def _scoped_directory_task_rows(pairing: dict[str, Any], *, store: Any, limit: int) -> list[dict[str, Any]]:
    task_id = _optional_clean_string(pairing.get("task_id"))
    if task_id:
        task = store.get_task(task_id)
        return [task] if task else []
    session_id = _optional_clean_string(pairing.get("session_id"))
    if session_id:
        return store.list_tasks(limit=limit, session_id=session_id)
    return []


def _remote_directory_task(row: dict[str, Any], pairing: dict[str, Any]) -> dict[str, Any]:
    task_id = str(row.get("id") or "")
    allowed_actions = _directory_allowed_actions(pairing, task_id=task_id)
    return {
        "id": task_id,
        "status": str(row.get("status") or "unknown"),
        "risk_level": str(row.get("risk_level") or "unknown"),
        "session_id": _optional_clean_string(row.get("session_id")),
        "created_at": str(row.get("created_at") or ""),
        "updated_at": str(row.get("updated_at") or ""),
        "allowed_actions": allowed_actions,
        "links": _remote_directory_links(task_id, allowed_actions),
        "metadata_only": True,
    }


def _directory_allowed_actions(pairing: dict[str, Any], *, task_id: str) -> list[str]:
    scoped_task = _optional_clean_string(pairing.get("task_id"))
    if scoped_task and scoped_task != task_id:
        return []
    allowed = [
        action
        for action in DEFAULT_ALLOWED_TASK_ACTIONS
        if action in set(pairing.get("allowed_actions") or ())
    ]
    return allowed


def _remote_directory_links(task_id: str, allowed_actions: list[str]) -> dict[str, str]:
    links: dict[str, str] = {}
    if "status" in allowed_actions:
        links["status"] = f"/remote-control/tasks/{task_id}"
    if "events" in allowed_actions:
        links["events"] = f"/remote-control/tasks/{task_id}/events"
    for action in ("resume", "pause", "cancel"):
        if action in allowed_actions:
            links[action] = f"/remote-control/tasks/{task_id}/{action}"
    return links


def _clamp_ttl(ttl_seconds: int | None) -> int:
    if ttl_seconds is None:
        return DEFAULT_PAIRING_TTL_SECONDS
    return max(MIN_PAIRING_TTL_SECONDS, min(int(ttl_seconds), MAX_PAIRING_TTL_SECONDS))


def _normalize_allowed_actions(allowed_actions: tuple[str, ...] | list[str] | None) -> list[str]:
    if allowed_actions is None:
        return list(DEFAULT_ALLOWED_TASK_ACTIONS)
    allowed = {
        str(action).strip().lower().replace("-", "_")
        for action in allowed_actions
        if str(action).strip()
    }
    return sorted(allowed.intersection(DEFAULT_ALLOWED_TASK_ACTIONS))


def _optional_clean_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_relay_registration(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    relay_target = _optional_clean_string(value.get("relay_target"))
    relay_auth_sha256 = _optional_clean_string(value.get("relay_auth_sha256"))
    if not relay_target or not relay_auth_sha256:
        return None
    normalized = {
        "relay_target": relay_target,
        "relay_auth_sha256": relay_auth_sha256,
        "registered_at": str(value.get("registered_at") or _utc_now(None).isoformat()),
        "pairing_token_relayed": False,
        "raw_secret_values_included": False,
    }
    if value.get("revocation_relayed_at"):
        normalized["revocation_relayed_at"] = str(value["revocation_relayed_at"])
    if value.get("revocation_response_status") is not None:
        normalized["revocation_response_status"] = int(value["revocation_response_status"])
    if value.get("last_pull_at"):
        normalized["last_pull_at"] = str(value["last_pull_at"])
    if value.get("last_pull_response_status") is not None:
        normalized["last_pull_response_status"] = int(value["last_pull_response_status"])
    if value.get("last_pull_action_count") is not None:
        normalized["last_pull_action_count"] = int(value["last_pull_action_count"])
    if value.get("last_directory_publish_at"):
        normalized["last_directory_publish_at"] = str(value["last_directory_publish_at"])
    if value.get("last_directory_publish_response_status") is not None:
        normalized["last_directory_publish_response_status"] = int(value["last_directory_publish_response_status"])
    if value.get("last_directory_publish_task_count") is not None:
        normalized["last_directory_publish_task_count"] = int(value["last_directory_publish_task_count"])
    if value.get("last_notification_publish_at"):
        normalized["last_notification_publish_at"] = str(value["last_notification_publish_at"])
    if value.get("last_notification_publish_response_status") is not None:
        normalized["last_notification_publish_response_status"] = int(value["last_notification_publish_response_status"])
    if value.get("last_notification_publish_event"):
        normalized["last_notification_publish_event"] = str(value["last_notification_publish_event"])
    if value.get("last_notification_retry_at"):
        normalized["last_notification_retry_at"] = str(value["last_notification_retry_at"])
    if value.get("last_notification_retry_count") is not None:
        normalized["last_notification_retry_count"] = int(value["last_notification_retry_count"])
    return normalized


def _normalize_relay_outbox(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for row in value[:MAX_RELAY_OUTBOX_ITEMS]:
        if not isinstance(row, dict):
            continue
        outbox_id = _optional_clean_string(row.get("id"))
        pairing_id = _optional_clean_string(row.get("pairing_id"))
        relay_target = _optional_clean_string(row.get("relay_target"))
        notification = row.get("notification") if isinstance(row.get("notification"), dict) else {}
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        if not outbox_id or not pairing_id or not relay_target:
            continue
        status = str(row.get("status") or "pending")
        if status not in {"pending", "retry_pending", "failed", "delivered", "acknowledged"}:
            status = "pending"
        items.append(
            {
                "id": outbox_id,
                "kind": "notification",
                "status": status,
                "pairing_id": pairing_id,
                "relay_target": relay_target,
                "event": str(row.get("event") or notification.get("event") or "")[:80],
                "task_id": _optional_clean_string(row.get("task_id") or notification.get("task_id")),
                "session_id": _optional_clean_string(row.get("session_id") or notification.get("session_id")),
                "notification": _persisted_notification(notification),
                "payload": _persisted_payload(payload),
                "attempt_count": _safe_int(row.get("attempt_count"), default=0),
                "created_at": str(row.get("created_at") or _utc_now(None).isoformat()),
                "updated_at": str(row.get("updated_at") or _utc_now(None).isoformat()),
                "last_attempt_at": _optional_clean_string(row.get("last_attempt_at")),
                "delivered_at": _optional_clean_string(row.get("delivered_at")),
                "acknowledged_at": _optional_clean_string(row.get("acknowledged_at")),
                "response_status": _safe_optional_int(row.get("response_status")),
                "response_bytes": _safe_int(row.get("response_bytes"), default=0),
                "relay_receipt": _sanitize_relay_delivery_receipt(row.get("relay_receipt")),
                "last_error": _optional_clean_string(row.get("last_error")),
                "next_retry_after": _optional_clean_string(row.get("next_retry_after")),
                "pairing_token_relayed": False,
                "relay_auth_token_captured": False,
                "user_request_included": False,
                "plan_receipt_included": False,
                "raw_secret_values_included": False,
            }
        )
    return items


def _persisted_notification(notification: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "remote_notification_available",
        "mode": "scoped_remote_notification",
        "checked_at": str(notification.get("checked_at") or _utc_now(None).isoformat()),
        "event": str(notification.get("event") or "")[:80],
        "pairing": notification.get("pairing") if isinstance(notification.get("pairing"), dict) else {},
        "task_id": _optional_clean_string(notification.get("task_id")),
        "session_id": _optional_clean_string(notification.get("session_id")),
        "task": _sanitize_remote_directory_task(notification.get("task") if isinstance(notification.get("task"), dict) else None),
        "metadata_only": True,
        "pairing_token_relayed": False,
        "raw_secret_values_included": False,
        "user_request_included": False,
        "plan_receipt_included": False,
    }


def _persisted_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "aegis.remote_control.notification",
        "version": 1,
        "delivery_id": _optional_clean_string(payload.get("delivery_id")),
        "idempotency_key": _optional_clean_string(payload.get("idempotency_key")),
        "sent_at": str(payload.get("sent_at") or _utc_now(None).isoformat()),
        "pairing_id": _optional_clean_string(payload.get("pairing_id")),
        "pairing": payload.get("pairing") if isinstance(payload.get("pairing"), dict) else {},
        "notification": _persisted_notification(payload.get("notification") if isinstance(payload.get("notification"), dict) else {}),
        "pairing_token_included": False,
        "relay_auth_token_included": False,
        "user_request_included": False,
        "plan_receipt_included": False,
        "raw_secret_values_included": False,
        "required_controls": ["scoped_remote_notification", "audit_receipts_without_tokens"],
    }


def _public_relay_outbox_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "kind": "notification",
        "status": item.get("status"),
        "pairing_id": item.get("pairing_id"),
        "relay_target": item.get("relay_target"),
        "event": item.get("event"),
        "task_id": item.get("task_id"),
        "session_id": item.get("session_id"),
        "attempt_count": int(item.get("attempt_count") or 0),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "last_attempt_at": item.get("last_attempt_at"),
        "delivered_at": item.get("delivered_at"),
        "acknowledged_at": item.get("acknowledged_at"),
        "response_status": item.get("response_status"),
        "response_bytes": item.get("response_bytes"),
        "relay_receipt": _sanitize_relay_delivery_receipt(item.get("relay_receipt")),
        "last_error": item.get("last_error"),
        "next_retry_after": item.get("next_retry_after"),
        "metadata_only": True,
        "pairing_token_relayed": False,
        "relay_auth_token_captured": False,
        "user_request_included": False,
        "plan_receipt_included": False,
        "raw_secret_values_included": False,
    }


def _relay_registered(pairing: dict[str, Any]) -> bool:
    relay_registration = pairing.get("relay_registration")
    return isinstance(relay_registration, dict) and bool(relay_registration.get("relay_auth_sha256"))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _mobile_gateway_contract(*, configured: bool) -> dict[str, Any]:
    return {
        **REMOTE_CONTROL_MOBILE_GATEWAY_CONTRACT,
        "status": "configured" if configured else "available_after_relay_registration",
        "native_push_delivery": "brokered_apns_fcm_adapter_available" if configured else "available_with_brokered_push_tokens",
        "broad_cloud_relay_delivery": "not_a_cloud_relay_service",
    }


def _normalize_native_push_provider(provider: str) -> str:
    normalized = str(provider or "").strip().lower().replace("-", "_")
    if normalized in {"apple", "apn", "apns"}:
        return "apns"
    if normalized in {"firebase", "google_fcm", "fcm"}:
        return "fcm"
    raise ValueError("remote-control native push provider must be apns or fcm")


def _native_push_target_url(provider: str, *, device_token: str, fcm_project_id: str | None) -> str:
    if provider == "apns":
        return f"https://api.push.apple.com/3/device/{quote(device_token.strip(), safe='')}"
    project_id = _clean_fcm_project_id(fcm_project_id)
    return f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"


def _clean_fcm_project_id(value: str | None) -> str:
    project_id = str(value or "").strip()
    if not project_id:
        raise ValueError("remote-control FCM push requires --fcm-project-id")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:")
    if any(char not in allowed for char in project_id) or len(project_id) > 160:
        raise ValueError("remote-control FCM project id contains unsupported characters")
    return project_id


def _native_push_payload(provider: str, *, notification: dict[str, Any], pairing: dict[str, Any], device_token: str) -> dict[str, Any]:
    title, body = _native_push_alert_text(notification)
    data = {
        "payload_type": "aegis.remote_control.notification",
        "event": str(notification.get("event") or ""),
        "pairing_id": str(pairing.get("id") or ""),
        "task_id": str(notification.get("task_id") or ""),
        "session_id": str(notification.get("session_id") or ""),
    }
    if provider == "apns":
        return {
            "aps": {
                "alert": {
                    "title": title,
                    "body": body,
                },
                "sound": "default",
            },
            "aegis": data,
        }
    return {
        "message": {
            "token": device_token,
            "notification": {
                "title": title,
                "body": body,
            },
            "data": {key: value for key, value in data.items() if value},
        }
    }


def _native_push_alert_text(notification: dict[str, Any]) -> tuple[str, str]:
    event = str(notification.get("event") or "task_updated").replace("_", " ").strip()[:80]
    task_id = str(notification.get("task_id") or "").strip()
    task = notification.get("task") if isinstance(notification.get("task"), dict) else {}
    task_status = str(task.get("status") or "").strip()
    title = "Aegis remote control"
    if task_id:
        body = f"{event}: {task_id}"
    else:
        body = event or "remote control update"
    if task_status:
        body = f"{body} ({task_status[:40]})"
    return title, body[:180]


def _post_native_push_payload(
    provider: str,
    *,
    target_url: str,
    payload: dict[str, Any],
    push_auth_token: str,
    apns_topic: str | None,
) -> tuple[int | None, bytes]:
    headers = {
        "Authorization": f"Bearer {push_auth_token}",
        "Content-Type": "application/json",
        "User-Agent": "Aegis-Agent/0.1",
    }
    if provider == "apns":
        topic = str(apns_topic or "").strip()
        if not topic:
            raise ValueError("remote-control APNS push requires --apns-topic")
        headers.update(
            {
                "apns-topic": topic,
                "apns-push-type": "alert",
                "apns-priority": "10",
            }
        )
    request = Request(
        target_url,
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        response_context = _open_without_redirects(request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("HTTP redirects are not followed for remote-control native push") from exc
        raise ValueError(f"remote-control native push failed with status {exc.code}") from exc
    except URLError as exc:
        raise ValueError(f"remote-control native push failed: {exc.reason}") from exc
    with response_context as response:
        response_status = response.getcode() if hasattr(response, "getcode") else None
        response_body = response.read(2048)
    return response_status, response_body


def _native_push_receipt(*, provider: str, response_status: int | None, response_body: bytes, device_token: str, target_url: str) -> dict[str, Any]:
    delivery_state = "accepted" if response_status is not None and 200 <= int(response_status) < 300 else "rejected"
    receipt_id = _native_push_receipt_id(response_body)
    return {
        "receipt_schema": "aegis.remote_control.native_push_receipt_v1",
        "provider": provider,
        "delivery_state": delivery_state,
        "response_status": response_status,
        "response_bytes": len(response_body),
        "receipt_id": receipt_id,
        "device_ref_hash": _token_hash(device_token),
        "push_target": _redacted_native_push_target(provider, target_url),
        "raw_response_body_included": False,
        "raw_device_token_included": False,
        "raw_secret_values_included": False,
    }


def _native_push_receipt_id(response_body: bytes) -> str | None:
    if not response_body:
        return None
    try:
        decoded = json.loads(response_body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    value = decoded.get("name") or decoded.get("apns-id") or decoded.get("id")
    cleaned = _optional_clean_string(value)
    return cleaned[:160] if cleaned else None


def _redacted_native_push_target(provider: str, target_url: str) -> str:
    parsed = urlparse(target_url)
    if provider == "apns":
        return f"{parsed.scheme}://{parsed.netloc}/3/device/[REDACTED_DEVICE_TOKEN]"
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _redacted_relay_target(relay_url: str | None) -> str | None:
    raw = str(relay_url or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        return None
    path = parsed.path or ""
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _allowed_domain(domain: str, allowlist: tuple[str, ...]) -> bool:
    return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowlist)


def _validated_relay_target(relay_target: str, *, allowlist: tuple[str, ...]) -> str:
    parsed = urlparse(relay_target)
    validation_error = _validate_url(parsed)
    if validation_error:
        raise ValueError(validation_error)
    if parsed.scheme != "https":
        raise ValueError("remote-control relay URL must use https")
    domain = parsed.hostname or ""
    if not _allowed_domain(domain, allowlist):
        raise ValueError(f"domain {domain!r} is not allowlisted")
    private_error = _private_network_error(domain)
    if private_error:
        raise ValueError(private_error)
    return relay_target


def _new_relay_outbox_id() -> str:
    return "rco_" + secrets.token_hex(8)


def _sanitize_relay_delivery_receipt(value: Any) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "receipt_present": False,
        "raw_response_body_included": False,
    }
    if not isinstance(value, dict):
        return receipt
    receipt_id = _optional_clean_string(value.get("receipt_id") or value.get("id"))
    delivery_state = _optional_clean_string(value.get("delivery_state") or value.get("state") or value.get("status"))
    if delivery_state is None and value.get("ok") is True:
        delivery_state = "ok"
    accepted_at = _optional_clean_string(value.get("accepted_at") or value.get("acknowledged_at") or value.get("delivered_at"))
    message = _optional_clean_string(value.get("message") or value.get("detail"))
    if receipt_id:
        receipt["receipt_id"] = receipt_id[:120]
    if delivery_state:
        receipt["delivery_state"] = delivery_state.lower().replace(" ", "_")[:40]
    if accepted_at:
        receipt["accepted_at"] = accepted_at[:80]
    if message:
        receipt["message"] = message[:160]
    receipt["receipt_present"] = bool(receipt_id or delivery_state or accepted_at or message or value.get("receipt_present"))
    return receipt


def _parse_relay_delivery_receipt(response_body: bytes) -> dict[str, Any]:
    if not response_body:
        return _sanitize_relay_delivery_receipt(None)
    try:
        decoded = json.loads(response_body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {
            "receipt_present": False,
            "message": "relay response was not valid JSON",
            "raw_response_body_included": False,
        }
    return _sanitize_relay_delivery_receipt(decoded)


def _relay_receipt_accepted(receipt: dict[str, Any]) -> bool:
    state = str(receipt.get("delivery_state") or "").lower()
    return bool(receipt.get("receipt_present")) and state in RELAY_RECEIPT_ACCEPTED_STATES


def _relay_retry_due(item: dict[str, Any], *, now: datetime) -> bool:
    next_retry = _optional_clean_string(item.get("next_retry_after"))
    if not next_retry:
        return True
    try:
        due_at = datetime.fromisoformat(next_retry)
    except ValueError:
        return True
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    return due_at <= now


def _post_relay_payload(relay_target: str, *, payload: dict[str, Any], relay_auth_token: str) -> tuple[int | None, bytes]:
    request = Request(
        relay_target,
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {relay_auth_token}",
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Agent/0.1",
        },
        method="POST",
    )
    response_context = _open_without_redirects(request, timeout=10)
    with response_context as response:
        response_status = response.getcode() if hasattr(response, "getcode") else None
        response_body = response.read(2048)
    return response_status, response_body


def _safe_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_relay_action_envelope(raw: dict[str, Any], public_pairing: dict[str, Any]) -> dict[str, Any]:
    request_id = _optional_clean_string(raw.get("request_id") or raw.get("id"))
    action = str(raw.get("action") or "").strip().lower().replace("-", "_")
    task_id = _optional_clean_string(raw.get("task_id"))
    session_id = _optional_clean_string(raw.get("session_id"))
    reason = str(raw.get("reason") or "").strip()[:500]
    rejection_reason = None
    allowed_actions = set(public_pairing.get("allowed_actions") or ())
    if action not in DEFAULT_ALLOWED_TASK_ACTIONS:
        rejection_reason = "action is not supported"
    elif action not in allowed_actions:
        rejection_reason = "action is outside pairing scope"
    elif not task_id:
        rejection_reason = "task_id is required"
    elif public_pairing.get("task_id") and public_pairing["task_id"] != task_id:
        rejection_reason = "task_id is outside pairing scope"
    return {
        "request_id": request_id,
        "action": action,
        "task_id": task_id,
        "session_id": session_id,
        "reason": reason,
        "accepted": rejection_reason is None,
        "rejection_reason": rejection_reason,
        "pairing_token_relayed": False,
        "raw_secret_values_included": False,
    }


def _local_remote_control_endpoints(*, host: str = "127.0.0.1", port: int = 8765) -> dict[str, str]:
    base = f"http://{host}:{port}"
    return {
        "status": f"{base}/remote-control/status",
        "directory": f"{base}/remote-control/directory",
        "relay": f"{base}/remote-control/relay",
        "pair": f"{base}/remote-control/pair",
        "revoke": f"{base}/remote-control/revoke",
        "task_status": f"{base}/remote-control/tasks/:id",
        "task_events": f"{base}/remote-control/tasks/:id/events",
        "task_resume": f"{base}/remote-control/tasks/:id/resume",
        "task_pause": f"{base}/remote-control/tasks/:id/pause",
        "task_cancel": f"{base}/remote-control/tasks/:id/cancel",
    }
