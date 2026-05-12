"""Mock Slack/Teams-style messaging connector with optional governed live writes."""

from __future__ import annotations

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
            write_operations=("send_message",),
            sample_data={"channels": [{"id": "general", "name": "general"}]},
        )
        self.allowlist = allowlist
        self.live_writes = live_writes
        self.secrets_broker = secrets_broker or SecretsBroker()
        self._rate_limiter = rate_limiter or InMemoryRateLimiter()
        configured_rate_limits = rate_limits or self.spec.rate_limits
        self.spec = ConnectorSpec(
            name="mock_messaging",
            version="0.3.0",
            auth_type="brokered_token",
            required_scopes=("read",),
            optional_scopes=("write",),
            supported_operations=self.spec.supported_operations,
            risk_by_operation={"read_channel": RiskLevel.LOW, "draft_message": RiskLevel.LOW, "send_message": RiskLevel.HIGH, "dry_run": RiskLevel.MEDIUM},
            rate_limits=configured_rate_limits,
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="mock_read_only",
            approval_required=("send_message",),
            operation_scopes=self.spec.operation_scopes,
        )

    def write(self, request: ConnectorRequest) -> ConnectorResult:
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
        return ConnectorResult(
            self.spec.name,
            request.operation,
            live_result["ok"],
            {"url": url, "domain": domain, "status": live_result["http_status"], "mode": "live_write", "accepted": accepted, "rate_limit": rate_limit},
            rollback="provider-specific messaging rollback required",
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
        response.read(4096)
    return {"ok": 200 <= status < 300, "http_status": status, "error": None if 200 <= status < 300 else f"messaging write failed with status {status}"}
