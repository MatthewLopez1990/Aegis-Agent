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
from urllib.parse import urlparse
from urllib.request import Request

from aegis.connectors.http import _open_without_redirects, _private_network_error, _validate_url


REMOTE_CONTROL_TOKEN_HEADER = "X-Aegis-Remote-Token"
DEFAULT_PAIRING_TTL_SECONDS = 600
MIN_PAIRING_TTL_SECONDS = 60
MAX_PAIRING_TTL_SECONDS = 3600
DEFAULT_ALLOWED_TASK_ACTIONS = ("status", "events", "resume", "pause", "cancel")
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


class RemoteControlPairingRegistry:
    """Short-lived pairing registry for one local API server or CLI data dir."""

    def __init__(self, store_path: str | Path | None = None) -> None:
        self.store_path = Path(store_path).expanduser().resolve() if store_path else None
        self._pairings: dict[str, dict[str, Any]] = {}
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
        return {
            "status": "local_pairing_available",
            "mode": "local_or_trusted_access_layer",
            "token_header": REMOTE_CONTROL_TOKEN_HEADER,
            "default_expires_in_seconds": DEFAULT_PAIRING_TTL_SECONDS,
            "max_expires_in_seconds": MAX_PAIRING_TTL_SECONDS,
            "active_pairing_count": active_count,
            "active_relay_action_proxy_count": relay_action_count,
            "pairings": pairings,
            "control_surface": [
                "remote task status",
                "remote task events",
                "remote task resume",
                "remote task pause",
                "remote task cancel",
                "registered relay action proxy",
            ],
            "blocked_until_relay": [
                "mobile_push_delivery",
                "cloud_session_directory",
            ],
            "relay_preflight": self.relay_preflight(),
        }

    def relay_preflight(self, *, relay_url: str | None = None) -> dict[str, Any]:
        relay_target = _redacted_relay_target(relay_url)
        blockers = [
            {"control": "explicit_operator_enablement", "detail": "approved relay registration is required before outbound relay transport is used"},
            {"control": "brokered_relay_auth", "detail": "relay credentials must use brokered handles and must not expose raw tokens"},
            {"control": "relay_origin_allowlist", "detail": "remote origins must be allowlisted before off-device access"},
            {"control": "push_delivery_approval", "detail": "mobile push delivery requires an approved channel adapter"},
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
            "mobile_push_delivery": "blocked",
            "cloud_session_directory": "blocked",
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
            ],
            "blockers": blockers,
            "verification_gates": list(REMOTE_CONTROL_RELAY_VERIFICATION_GATES),
            "allowed_local_endpoints": [
                "GET /remote-control/status",
                "POST /remote-control/pair",
                "POST /remote-control/revoke",
                "GET /remote-control/tasks/:id",
                "GET /remote-control/tasks/:id/events",
                "POST /remote-control/tasks/:id/resume|pause|cancel",
            ],
            "next_steps": [
                "Register an active pairing with an allowlisted relay using a brokered credential handle.",
                "Preserve local pairing scope, expiry, revocation, host checks, and audit receipts through relayed actions.",
                "Add mobile push delivery and cloud directory tests before broad off-device delivery.",
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
            ],
            "remaining_controls": [
                "mobile_push_delivery_approval",
                "cloud_session_directory",
            ],
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

    def _save(self) -> None:
        if self.store_path is None:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "pairings": list(self._pairings.values()),
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
            "relay_revocation_propagated": bool(relay_revocation_relayed_at),
            "relay_revocation_relayed_at": relay_revocation_relayed_at or None,
        }


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
    return normalized


def _relay_registered(pairing: dict[str, Any]) -> bool:
    relay_registration = pairing.get("relay_registration")
    return isinstance(relay_registration, dict) and bool(relay_registration.get("relay_auth_sha256"))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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


def _local_remote_control_endpoints(*, host: str = "127.0.0.1", port: int = 8765) -> dict[str, str]:
    base = f"http://{host}:{port}"
    return {
        "status": f"{base}/remote-control/status",
        "relay": f"{base}/remote-control/relay",
        "pair": f"{base}/remote-control/pair",
        "revoke": f"{base}/remote-control/revoke",
        "task_status": f"{base}/remote-control/tasks/:id",
        "task_events": f"{base}/remote-control/tasks/:id/events",
        "task_resume": f"{base}/remote-control/tasks/:id/resume",
        "task_pause": f"{base}/remote-control/tasks/:id/pause",
        "task_cancel": f"{base}/remote-control/tasks/:id/cancel",
    }
