"""Governed outbound chat webhook helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from aegis.channels.webhook import _open_without_redirects, _validate_delivery_url


def deliver_chat_webhook(
    *,
    url: str,
    text: str,
    payload_format: str,
    delivery_id: str,
    allowlist: tuple[str, ...],
    session_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    timeout_seconds: float = 10,
) -> dict[str, Any]:
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    validation_error = _validate_delivery_url(parsed, allowlist=allowlist)
    if validation_error:
        raise ValueError(validation_error.replace("webhook", "chat webhook", 1))
    body_payload = _format_payload(
        text=text,
        payload_format=payload_format,
        delivery_id=delivery_id,
        session_id=session_id,
        metadata=metadata or {},
    )
    body = json.dumps(body_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Aegis-Agent/0.1"},
    )
    try:
        response_context = _open_without_redirects(request, timeout=timeout_seconds)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("HTTP redirects are not followed by the governed chat webhook adapter") from exc
        raise RuntimeError(f"chat webhook delivery failed with status {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"chat webhook delivery failed: {exc.reason}") from exc
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response.read(4096)
    return {
        "ok": 200 <= status < 300,
        "status": "delivered" if 200 <= status < 300 else "delivery_failed",
        "http_status": status,
        "domain": domain,
        "delivery_id": delivery_id,
        "payload_hash": hashlib.sha256(body).hexdigest(),
        "payload_format": _normalized_format(payload_format),
        "signed": False,
    }


def _format_payload(
    *,
    text: str,
    payload_format: str,
    delivery_id: str,
    session_id: str | None,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    normalized = _normalized_format(payload_format)
    if normalized == "slack":
        return {"text": text}
    if normalized == "discord":
        return {"content": text}
    if normalized == "teams":
        return {"text": text}
    return {
        "text": text,
        "session_id": session_id,
        "metadata": metadata,
        "delivery_id": delivery_id,
    }


def _normalized_format(payload_format: str) -> str:
    normalized = payload_format.strip().lower().replace("-", "_")
    if normalized not in {"generic", "slack", "discord", "teams"}:
        raise ValueError("chat webhook format must be one of: generic, slack, discord, teams")
    return normalized
