"""Mock Slack/Teams-style messaging connector with optional governed live writes."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec, live_connector_activation, require_scope
from aegis.connectors.http import _open_without_redirects, _private_network_error, _validate_url
from aegis.connectors.mock_service import MockServiceConnector, _summarize_params
from aegis.connectors.rate_limit import InMemoryRateLimiter
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import RiskLevel, Sensitivity


class MockMessagingConnector(MockServiceConnector):
    def __init__(
        self,
        *,
        allowlist: tuple[str, ...] = ("example.com",),
        live_writes: bool = False,
        secrets_broker: SecretsBroker | None = None,
        rate_limits: dict[str, Any] | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
    ) -> None:
        super().__init__(
            name="mock_messaging",
            operations=("read_channel", "draft_message"),
            write_operations=("send_message", "rollback_message"),
            sample_data={"channels": [{"id": "general", "name": "general"}]},
        )
        self.allowlist = allowlist
        self.live_writes = live_writes
        self.secrets_broker = secrets_broker or SecretsBroker()
        self._rate_limiter = rate_limiter or InMemoryRateLimiter()
        configured_rate_limits = rate_limits or self.spec.rate_limits
        self.spec = ConnectorSpec(
            name="mock_messaging",
            version="0.4.0",
            auth_type="brokered_token",
            required_scopes=("read",),
            optional_scopes=("write",),
            supported_operations=self.spec.supported_operations,
            risk_by_operation={
                "read_channel": RiskLevel.LOW,
                "draft_message": RiskLevel.LOW,
                "send_message": RiskLevel.HIGH,
                "rollback_message": RiskLevel.HIGH,
                "dry_run": RiskLevel.MEDIUM,
            },
            rate_limits=configured_rate_limits,
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="mock_read_only",
            approval_required=("send_message", "rollback_message"),
            operation_scopes=self.spec.operation_scopes,
        )

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        if request.operation == "rollback_message":
            return self.rollback(request)
        if not self._is_live_write_request(request):
            return super().write(request)
        require_scope(request, "write", connector=self.spec.name)
        url = str(request.params.get("api_url") or request.params.get("provider_url") or request.params.get("webhook_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if request.operation not in self.write_operations:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"unsupported messaging write operation: {request.operation}")
        if not request.approved:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=self.live_writes, approved=False, allowlist=self.allowlist, domain=domain)},
                error="messaging live write requires approval",
            )
        if not self.live_writes:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=False, approved=True, allowlist=self.allowlist, domain=domain)},
                error="messaging live writes are disabled",
            )
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=validation_error)
        if parsed.scheme != "https":
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="messaging live writes require https")
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=private_error)
        token_secret = str(request.params.get("token_secret") or "MESSAGING_TOKEN")
        handle = self.secrets_broker.request_handle(
            name=token_secret,
            requester="mock_messaging_connector",
            reason=f"Messaging {request.operation}",
            scopes=("messaging:write",),
        )
        if not handle.present:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=True, approved=True, allowlist=self.allowlist, domain=domain, token_present=False)},
                error=f"secret {token_secret!r} is not configured",
            )
        try:
            token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="mock_messaging_connector")
        except KeyError as exc:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=str(exc))
        try:
            payload = _message_payload(request.params)
        except ValueError as exc:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=str(exc))
        rate_limit = self._check_live_rate_limit(domain=domain, operation=request.operation)
        if not rate_limit["allowed"]:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"mode": "live_write", "domain": domain, "rate_limit": rate_limit},
                rollback="no action performed",
                error="messaging live write rate limit exceeded",
            )
        live_result = _send_messaging_write(url=url, token=token, payload=payload)
        accepted = _summarize_params({"url": url, "payload": payload, "token_secret": token_secret})
        rollback_receipt = _rollback_offer_receipt(payload=payload, provider_message_ref=live_result.get("message_ref", {}))
        return ConnectorResult(
            self.spec.name,
            request.operation,
            live_result["ok"],
            {
                "url": url,
                "domain": domain,
                "status": live_result["http_status"],
                "mode": "live_write",
                "accepted": accepted,
                "rate_limit": rate_limit,
                "rollback_receipt": rollback_receipt,
            },
            rollback="rollback_message available with approval" if rollback_receipt["rollback_available"] else "provider-specific messaging rollback required",
            error=live_result.get("error"),
        )

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        if request.operation != "rollback_message" or not self._is_live_write_request(request):
            return super().rollback(request)
        require_scope(request, "write", connector=self.spec.name)
        url = str(request.params.get("api_url") or request.params.get("provider_url") or request.params.get("webhook_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        operation = "rollback_message"
        if not request.approved:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=operation, enabled=self.live_writes, approved=False, allowlist=self.allowlist, domain=domain)},
                rollback="no action performed",
                error="messaging rollback requires approval",
            )
        if not self.live_writes:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=operation, enabled=False, approved=True, allowlist=self.allowlist, domain=domain)},
                rollback="no action performed",
                error="messaging live writes are disabled",
            )
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=validation_error)
        if parsed.scheme != "https":
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error="messaging rollback requires https")
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=private_error)
        token_secret = str(request.params.get("token_secret") or "MESSAGING_TOKEN")
        handle = self.secrets_broker.request_handle(
            name=token_secret,
            requester="mock_messaging_connector",
            reason="Messaging rollback_message",
            scopes=("messaging:write",),
        )
        if not handle.present:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=operation, enabled=True, approved=True, allowlist=self.allowlist, domain=domain, token_present=False)},
                rollback="no action performed",
                error=f"secret {token_secret!r} is not configured",
            )
        try:
            token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="mock_messaging_connector")
            payload = _rollback_message_payload(request.params)
        except (KeyError, ValueError) as exc:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=str(exc))
        rate_limit = self._check_live_rate_limit(domain=domain, operation=operation)
        if not rate_limit["allowed"]:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"mode": "live_rollback", "domain": domain, "rate_limit": rate_limit},
                rollback="no action performed",
                error="messaging rollback rate limit exceeded",
            )
        live_result = _send_messaging_rollback(url=url, token=token, payload=payload, method=str(request.params.get("rollback_method") or request.params.get("method") or "DELETE"))
        receipt = {
            "receipt_schema": "messaging_rollback_receipt_v1",
            "rollback_operation": operation,
            "message_ref_hash": _message_ref_hash(payload),
            "channel_ref_hash": _channel_ref_hash(payload),
            "http_status": live_result["http_status"],
            "rate_limit": rate_limit,
            "raw_secret_values_included": False,
            "raw_response_body_included": False,
        }
        return ConnectorResult(
            self.spec.name,
            operation,
            live_result["ok"],
            {
                "url": url,
                "domain": domain,
                "status": live_result["http_status"],
                "mode": "live_rollback",
                "accepted": _summarize_params({"url": url, "payload": payload, "token_secret": token_secret}),
                "rollback_receipt": receipt,
                "rate_limit": rate_limit,
            },
            rollback="rollback executed" if live_result["ok"] else "rollback attempted but provider rejected it",
            error=live_result.get("error"),
        )

    def health_check(self) -> dict[str, Any]:
        return {**super().health_check(), "live_writes": self.live_writes, "allowlist": list(self.allowlist)}

    def _allowed(self, domain: str) -> bool:
        return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in self.allowlist)

    def _check_live_rate_limit(self, *, domain: str, operation: str) -> dict[str, int | bool]:
        per_minute = _positive_int(self.spec.rate_limits.get("per_minute"))
        if per_minute is None:
            return {"allowed": True, "limit": 0, "window_seconds": 60, "remaining": 0, "retry_after_seconds": 0}
        decision = self._rate_limiter.check(f"{self.spec.name}:{domain}:{operation}", limit=per_minute, window_seconds=60)
        return decision.to_dict()

    @staticmethod
    def _is_live_write_request(request: ConnectorRequest) -> bool:
        return bool(request.params.get("api_url") or request.params.get("provider_url") or request.params.get("webhook_url"))


def _message_payload(params: dict[str, Any]) -> dict[str, Any]:
    message = params.get("message") if isinstance(params.get("message"), dict) else {}
    text = str(params.get("text") or message.get("text") or "").strip()
    if not text:
        raise ValueError("messaging live write requires text")
    payload = {"text": text[:4000]}
    channel = params.get("channel") or message.get("channel")
    if channel is not None:
        payload["channel"] = str(channel)[:200]
    thread_id = params.get("thread_id") or message.get("thread_id")
    if thread_id is not None:
        payload["thread_id"] = str(thread_id)[:200]
    return payload


def _rollback_message_payload(params: dict[str, Any]) -> dict[str, Any]:
    message = params.get("message") if isinstance(params.get("message"), dict) else {}
    message_ref = str(
        params.get("message_id")
        or params.get("message_ts")
        or params.get("ts")
        or params.get("id")
        or message.get("message_id")
        or message.get("message_ts")
        or message.get("ts")
        or message.get("id")
        or ""
    ).strip()
    if not message_ref:
        raise ValueError("messaging rollback requires message_id, message_ts, ts, or id")
    payload = {"message_id": message_ref[:300], "rollback_reason": "Aegis rollback_message approved by local operator"}
    channel = params.get("channel") or message.get("channel")
    if channel is not None:
        payload["channel"] = str(channel)[:200]
    thread_id = params.get("thread_id") or message.get("thread_id")
    if thread_id is not None:
        payload["thread_id"] = str(thread_id)[:200]
    return payload


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _send_messaging_write(*, url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    http_request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(http_request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed messaging connector"}
        return {"ok": False, "http_status": exc.code, "error": f"messaging write failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"messaging write failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response_body = response.read(4096)
    return {
        "ok": 200 <= status < 300,
        "http_status": status,
        "message_ref": _message_ref_from_body(response_body),
        "error": None if 200 <= status < 300 else f"messaging write failed with status {status}",
    }


def _send_messaging_rollback(*, url: str, token: str, payload: dict[str, Any], method: str) -> dict[str, Any]:
    normalized_method = method.upper()
    if normalized_method not in {"DELETE", "POST"}:
        return {"ok": False, "http_status": 0, "error": "messaging rollback method must be DELETE or POST"}
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    http_request = Request(
        url,
        data=body,
        method=normalized_method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(http_request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed messaging connector"}
        return {"ok": False, "http_status": exc.code, "error": f"messaging rollback failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"messaging rollback failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response.read(4096)
    return {"ok": 200 <= status < 300, "http_status": status, "error": None if 200 <= status < 300 else f"messaging rollback failed with status {status}"}


def _rollback_offer_receipt(*, payload: dict[str, Any], provider_message_ref: Any) -> dict[str, Any]:
    message_ref = provider_message_ref if isinstance(provider_message_ref, dict) else {}
    merged = {**payload, **message_ref}
    message_ref_hash = _message_ref_hash(merged)
    return {
        "receipt_schema": "messaging_rollback_offer_v1",
        "rollback_available": bool(message_ref_hash),
        "rollback_operation": "rollback_message" if message_ref_hash else None,
        "message_ref_hash": message_ref_hash or None,
        "channel_ref_hash": _channel_ref_hash(merged) or None,
        "requires_approval": True,
        "raw_secret_values_included": False,
        "raw_response_body_included": False,
    }


def _message_ref_from_body(body: bytes) -> dict[str, str]:
    if not body:
        return {}
    try:
        decoded = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(decoded, dict):
        return {}
    nested_message = decoded.get("message") if isinstance(decoded.get("message"), dict) else {}
    message_id = str(
        decoded.get("message_id")
        or decoded.get("id")
        or decoded.get("ts")
        or nested_message.get("message_id")
        or nested_message.get("id")
        or nested_message.get("ts")
        or ""
    ).strip()
    channel = str(decoded.get("channel") or nested_message.get("channel") or "").strip()
    result: dict[str, str] = {}
    if message_id:
        result["message_id"] = message_id[:300]
    if channel:
        result["channel"] = channel[:200]
    return result


def _message_ref_hash(payload: dict[str, Any]) -> str:
    for key in ("message_id", "message_ts", "ts", "id"):
        value = str(payload.get(key) or "").strip()
        if value:
            return hashlib.sha256(value.encode("utf-8")).hexdigest()
    return ""


def _channel_ref_hash(payload: dict[str, Any]) -> str:
    value = str(payload.get("channel") or "").strip()
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""
