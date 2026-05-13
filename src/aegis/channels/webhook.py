"""Signed inbound webhook gateway helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import time
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aegis.channels.base import ChannelMessage
from aegis.security.network import private_network_error, response_private_network_error
from aegis.security.taint import now_utc


@dataclass(frozen=True)
class VerifiedWebhook:
    delivery_id: str
    message: ChannelMessage
    storage_payload: dict[str, Any]


def verify_signed_webhook(
    *,
    headers: Mapping[str, str],
    body: bytes,
    secret: str,
    max_body_bytes: int,
    timestamp_tolerance_seconds: int,
    now_seconds: int | None = None,
) -> VerifiedWebhook:
    if len(body) > max_body_bytes:
        raise ValueError("webhook body exceeds configured maximum")
    content_type = _header(headers, "content-type")
    if content_type and "application/json" not in content_type.lower():
        raise ValueError("webhook content type must be application/json")
    delivery_id = _required_header(headers, "x-aegis-delivery")
    timestamp_raw = _required_header(headers, "x-aegis-timestamp")
    signature = _required_header(headers, "x-aegis-signature")
    try:
        timestamp = int(timestamp_raw)
    except ValueError as exc:
        raise ValueError("webhook timestamp must be a unix epoch integer") from exc
    current = int(now_seconds if now_seconds is not None else time.time())
    if abs(current - timestamp) > timestamp_tolerance_seconds:
        raise ValueError("webhook timestamp is outside the allowed tolerance")
    expected = _signature(secret, timestamp_raw, body)
    if not hmac.compare_digest(signature, expected):
        raise PermissionError("webhook signature verification failed")
    try:
        decoded = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("webhook body must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("webhook body must be a JSON object")
    raw_keys = sorted(str(key) for key in decoded)
    payload_hash = hashlib.sha256(body).hexdigest()
    sender = str(decoded.get("sender") or decoded.get("user") or decoded.get("source") or "webhook")
    text = _text_from_payload(decoded)
    message = ChannelMessage(
        channel="webhook",
        sender=sender,
        text=text[:4000],
        session_id=decoded.get("session_id") if isinstance(decoded.get("session_id"), str) else None,
        metadata={"delivery_id": delivery_id, "payload_hash": payload_hash, "raw_keys": raw_keys},
    )
    storage_payload = {
        "delivery_id": delivery_id,
        "payload_hash": payload_hash,
        "raw_keys": raw_keys,
        "body_bytes": len(body),
        "sender": sender,
        "verified_at": now_utc(),
    }
    return VerifiedWebhook(delivery_id=delivery_id, message=message, storage_payload=storage_payload)


def sign_webhook_body(secret: str, timestamp: str, body: bytes) -> str:
    return _signature(secret, timestamp, body)


def deliver_signed_webhook(
    *,
    url: str,
    secret: str,
    payload: dict[str, Any],
    delivery_id: str,
    allowlist: tuple[str, ...],
    timeout_seconds: float = 10,
) -> dict[str, Any]:
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    validation_error = _validate_delivery_url(parsed, allowlist=allowlist)
    if validation_error:
        raise ValueError(validation_error)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    signature = sign_webhook_body(secret, timestamp, body)
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Agent/0.1",
            "X-Aegis-Delivery": delivery_id,
            "X-Aegis-Timestamp": timestamp,
            "X-Aegis-Signature": signature,
        },
    )
    try:
        response_context = _open_without_redirects(request, timeout=timeout_seconds)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("HTTP redirects are not followed by the governed webhook adapter") from exc
        raise RuntimeError(f"webhook delivery failed with status {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"webhook delivery failed: {exc.reason}") from exc
    with response_context as response:
        peer_error = response_private_network_error(response, target="webhook delivery")
        if peer_error:
            raise ValueError(peer_error)
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response.read(4096)
    return {
        "ok": 200 <= status < 300,
        "status": "delivered" if 200 <= status < 300 else "delivery_failed",
        "http_status": status,
        "domain": domain,
        "delivery_id": delivery_id,
        "payload_hash": hashlib.sha256(body).hexdigest(),
        "signed": True,
    }


def _signature(secret: str, timestamp: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), timestamp.encode("utf-8") + b"." + body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _text_from_payload(payload: dict[str, Any]) -> str:
    for key in ("text", "message", "content", "body"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    return json.dumps({key: payload[key] for key in sorted(payload)}, sort_keys=True)[:4000]


def _required_header(headers: Mapping[str, str], name: str) -> str:
    value = _header(headers, name)
    if not value:
        raise ValueError(f"missing required webhook header: {name}")
    return value


def _header(headers: Mapping[str, str], name: str) -> str | None:
    value = headers.get(name)
    if value is not None:
        return str(value)
    lower = name.lower()
    for key, candidate in headers.items():
        if str(key).lower() == lower:
            return str(candidate)
    return None


def _validate_delivery_url(parsed, *, allowlist: tuple[str, ...]) -> str | None:  # noqa: ANN001
    if parsed.scheme != "https":
        return "webhook delivery requires https"
    if parsed.username or parsed.password:
        return "credentials in webhook URLs are not allowed"
    domain = parsed.hostname or ""
    if not domain:
        return "webhook URL hostname is required"
    if not any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowlist):
        return f"webhook domain {domain!r} is not allowlisted"
    return _private_network_error(domain)


def _private_network_error(hostname: str) -> str | None:
    return private_network_error(hostname, target="webhook delivery")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _open_without_redirects(request: Request, *, timeout: float):
    opener = build_opener(_NoRedirectHandler)
    return opener.open(request, timeout=timeout)
