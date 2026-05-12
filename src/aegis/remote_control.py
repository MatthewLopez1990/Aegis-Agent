"""Short-lived local remote-control pairing tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
import hashlib
import secrets


REMOTE_CONTROL_TOKEN_HEADER = "X-Aegis-Remote-Token"
DEFAULT_PAIRING_TTL_SECONDS = 600
MIN_PAIRING_TTL_SECONDS = 60
MAX_PAIRING_TTL_SECONDS = 3600
DEFAULT_ALLOWED_TASK_ACTIONS = ("status", "events", "resume", "pause", "cancel")


class RemoteControlPairingRegistry:
    """In-memory pairing registry for one running local API server."""

    def __init__(self) -> None:
        self._pairings: dict[str, dict[str, Any]] = {}

    def create_pairing(
        self,
        *,
        label: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        allowed_actions: tuple[str, ...] | list[str] | None = None,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
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
        }
        self._pairings[pairing_id] = pairing
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
        }

    def status(self, *, now: datetime | None = None) -> dict[str, Any]:
        checked_at = _utc_now(now)
        pairings = [self._public_pairing(pairing, now=checked_at) for pairing in self._pairings.values()]
        active_count = sum(1 for pairing in pairings if pairing["status"] == "active")
        return {
            "status": "local_pairing_available",
            "mode": "local_or_trusted_access_layer",
            "token_header": REMOTE_CONTROL_TOKEN_HEADER,
            "default_expires_in_seconds": DEFAULT_PAIRING_TTL_SECONDS,
            "max_expires_in_seconds": MAX_PAIRING_TTL_SECONDS,
            "active_pairing_count": active_count,
            "pairings": pairings,
            "control_surface": [
                "remote task status",
                "remote task events",
                "remote task resume",
                "remote task pause",
                "remote task cancel",
            ],
            "blocked_until_relay": [
                "off_device_outbound_relay",
                "mobile_push_delivery",
                "cloud_session_directory",
            ],
        }

    def authorize(self, token: str, *, now: datetime | None = None) -> dict[str, Any] | None:
        if not token:
            return None
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

    def authorize_action(self, token: str, *, action: str, task_id: str, now: datetime | None = None) -> dict[str, Any] | None:
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

    def revoke(self, pairing_id: str, *, now: datetime | None = None) -> dict[str, Any]:
        pairing = self._pairings.get(pairing_id)
        if pairing is None:
            raise KeyError(pairing_id)
        revoked_at = _utc_now(now)
        if pairing.get("revoked_at") is None:
            pairing["revoked_at"] = revoked_at.isoformat()
        return {"status": "revoked", "pairing": self._public_pairing(pairing, now=revoked_at)}

    def _public_pairing(self, pairing: dict[str, Any], *, now: datetime) -> dict[str, Any]:
        expires_at = datetime.fromisoformat(str(pairing["expires_at"]))
        revoked_at = pairing.get("revoked_at")
        if revoked_at:
            status = "revoked"
        elif expires_at <= now:
            status = "expired"
        else:
            status = "active"
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
        }


def _clamp_ttl(ttl_seconds: int | None) -> int:
    if ttl_seconds is None:
        return DEFAULT_PAIRING_TTL_SECONDS
    return max(MIN_PAIRING_TTL_SECONDS, min(int(ttl_seconds), MAX_PAIRING_TTL_SECONDS))


def _normalize_allowed_actions(allowed_actions: tuple[str, ...] | list[str] | None) -> list[str]:
    if allowed_actions is None:
        return list(DEFAULT_ALLOWED_TASK_ACTIONS)
    allowed = {str(action).strip().lower().replace("-", "_") for action in allowed_actions if str(action).strip()}
    return sorted(allowed.intersection(DEFAULT_ALLOWED_TASK_ACTIONS))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utc_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)
