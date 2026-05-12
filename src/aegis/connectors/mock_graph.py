"""Microsoft Graph-style connector with mock defaults and optional governed live writes."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from aegis.audit.logger import redact
from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec, live_connector_activation, require_scope
from aegis.connectors.http import _open_without_redirects, _private_network_error, _validate_url
from aegis.connectors.mock_service import MockServiceConnector
from aegis.connectors.rate_limit import InMemoryRateLimiter
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import RiskLevel, Sensitivity


class MockGraphConnector(MockServiceConnector):
    def __init__(
        self,
        *,
        allowlist: tuple[str, ...] = ("graph.microsoft.com",),
        live_calendar_writes: bool = False,
        live_email_writes: bool | None = None,
        live_contact_writes: bool | None = None,
        secrets_broker: SecretsBroker | None = None,
        rate_limits: dict[str, Any] | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
    ) -> None:
        super().__init__(
            name="mock_graph",
            operations=("read_profile", "read_calendar", "search_contacts"),
            write_operations=("draft_email", "send_email", "create_event", "create_contact", "update_contact", "rollback_event", "rollback_contact"),
            sample_data={
                "tenant": "mock",
                "profile": {"displayName": "Local User"},
                "events": [{"id": "mock-event", "subject": "Local planning", "start": "mock"}],
                "contacts": [{"id": "mock-contact", "displayName": "Local User", "email": "local@example.test"}],
            },
        )
        self.allowlist = allowlist
        self.live_calendar_writes = live_calendar_writes
        self.live_email_writes = live_calendar_writes if live_email_writes is None else live_email_writes
        self.live_contact_writes = live_calendar_writes if live_contact_writes is None else live_contact_writes
        self.secrets_broker = secrets_broker or SecretsBroker()
        self._rate_limiter = rate_limiter or InMemoryRateLimiter()
        configured_rate_limits = rate_limits or self.spec.rate_limits
        self.spec = ConnectorSpec(
            name="mock_graph",
            version="0.3.0",
            auth_type="brokered_token",
            required_scopes=("read",),
            optional_scopes=("write",),
            supported_operations=self.spec.supported_operations,
            risk_by_operation={
                "read_profile": RiskLevel.LOW,
                "read_calendar": RiskLevel.LOW,
                "search_contacts": RiskLevel.LOW,
                "draft_email": RiskLevel.HIGH,
                "send_email": RiskLevel.HIGH,
                "create_event": RiskLevel.HIGH,
                "create_contact": RiskLevel.HIGH,
                "update_contact": RiskLevel.HIGH,
                "rollback_event": RiskLevel.HIGH,
                "rollback_contact": RiskLevel.HIGH,
                "dry_run": RiskLevel.MEDIUM,
            },
            rate_limits=configured_rate_limits,
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="mock_read_only",
            approval_required=("draft_email", "send_email", "create_event", "create_contact", "update_contact", "rollback_event", "rollback_contact"),
            operation_scopes=self.spec.operation_scopes,
        )

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        if request.operation in {"rollback_event", "rollback_contact"}:
            return self.rollback(request)
        if not self._is_live_write_request(request):
            return super().write(request)
        require_scope(request, "write", connector=self.spec.name)
        url = str(request.params.get("api_url") or request.params.get("provider_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        enabled = self._live_enabled_for_operation(request.operation)
        if not request.approved:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=enabled, approved=False, allowlist=self.allowlist, domain=domain)},
                error=f"{_write_label(request.operation)} live write requires approval",
            )
        if not enabled:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=False, approved=True, allowlist=self.allowlist, domain=domain)},
                error=f"{_write_label(request.operation)} live writes are disabled",
            )
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=validation_error)
        if parsed.scheme != "https":
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"{_write_label(request.operation)} live writes require https")
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=private_error)
        token_secret = str(request.params.get("token_secret") or "GRAPH_TOKEN")
        scope = _write_scope(request.operation)
        handle = self.secrets_broker.request_handle(
            name=token_secret,
            requester="graph_connector",
            reason=f"{_write_label(request.operation)} {request.operation}",
            scopes=(scope,),
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
            token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="graph_connector")
            if request.operation == "create_event":
                payload = _calendar_event_payload(request.params)
            elif request.operation in {"draft_email", "send_email"}:
                payload = _email_message_payload(request.operation, request.params)
            else:
                payload = _contact_payload(request.operation, request.params)
        except (KeyError, ValueError) as exc:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=str(exc))
        rate_limit = self._check_live_rate_limit(domain=domain, operation=request.operation)
        if not rate_limit["allowed"]:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"mode": "live_write", "domain": domain, "rate_limit": rate_limit},
                rollback="no action performed",
                error=f"{_write_label(request.operation)} live write rate limit exceeded",
            )
        live_result = _send_graph_write(operation=request.operation, url=url, token=token, payload=payload)
        accepted = _summarize_params({"url": url, "payload": payload, "token_secret": token_secret})
        rollback_receipt = _rollback_offer_receipt(request.operation, payload)
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
            rollback=f"{rollback_receipt['rollback_operation']} available with approval" if rollback_receipt["rollback_available"] else f"provider-specific {_write_label(request.operation)} rollback required",
            error=live_result.get("error"),
        )

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        require_scope(request, "write", connector=self.spec.name)
        operation = _rollback_operation_for(request.operation)
        if operation is None:
            return ConnectorResult(self.spec.name, "rollback", False, {}, rollback="no action performed", error=f"graph rollback is not available for {request.operation}")
        url = str(request.params.get("api_url") or request.params.get("provider_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        enabled = self._live_enabled_for_operation(operation)
        if not request.approved:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=operation, enabled=enabled, approved=False, allowlist=self.allowlist, domain=domain)},
                rollback="no action performed",
                error=f"{_write_label(operation)} rollback requires approval",
            )
        if not enabled:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=operation, enabled=False, approved=True, allowlist=self.allowlist, domain=domain)},
                rollback="no action performed",
                error=f"{_write_label(operation)} live writes are disabled",
            )
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=validation_error)
        if parsed.scheme != "https":
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=f"{_write_label(operation)} rollback requires https")
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=private_error)
        token_secret = str(request.params.get("token_secret") or "GRAPH_TOKEN")
        scope = _write_scope(operation)
        handle = self.secrets_broker.request_handle(
            name=token_secret,
            requester="graph_connector",
            reason=f"{_write_label(operation)} {operation}",
            scopes=(scope,),
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
            token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="graph_connector")
            payload = _rollback_payload(operation, request.params)
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
                error=f"{_write_label(operation)} rollback rate limit exceeded",
            )
        live_result = _send_graph_write(operation=operation, url=url, token=token, payload=payload)
        receipt = {
            "receipt_schema": "graph_rollback_receipt_v1",
            "rollback_operation": operation,
            "resource_type": "calendar_event" if operation == "rollback_event" else "contact",
            "resource_ref_hash": _resource_ref_hash(payload),
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
        return {
            **super().health_check(),
            "live_calendar_writes": self.live_calendar_writes,
            "live_email_writes": self.live_email_writes,
            "live_contact_writes": self.live_contact_writes,
            "allowlist": list(self.allowlist),
        }

    def _allowed(self, domain: str) -> bool:
        return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in self.allowlist)

    def _live_enabled_for_operation(self, operation: str) -> bool:
        if operation in {"create_event", "rollback_event"}:
            return self.live_calendar_writes
        if operation in {"draft_email", "send_email"}:
            return self.live_email_writes
        if operation in {"create_contact", "update_contact", "rollback_contact"}:
            return self.live_contact_writes
        return False

    def _check_live_rate_limit(self, *, domain: str, operation: str) -> dict[str, int | bool]:
        per_minute = _positive_int(self.spec.rate_limits.get("per_minute"))
        if per_minute is None:
            return {"allowed": True, "limit": 0, "window_seconds": 60, "remaining": 0, "retry_after_seconds": 0}
        decision = self._rate_limiter.check(f"{self.spec.name}:{domain}:{operation}", limit=per_minute, window_seconds=60)
        return decision.to_dict()

    @staticmethod
    def _is_live_write_request(request: ConnectorRequest) -> bool:
        return request.operation in {"create_event", "draft_email", "send_email", "create_contact", "update_contact"} and bool(
            request.params.get("api_url") or request.params.get("provider_url")
        )


def _calendar_event_payload(params: dict[str, Any]) -> dict[str, Any]:
    event = params.get("event", {})
    if not isinstance(event, dict):
        raise ValueError("calendar event payload must be an object")
    payload = dict(event)
    for key, value in params.items():
        if key not in {"event", "api_url", "provider_url", "token_secret"} and key not in payload:
            payload[key] = value
    subject = str(payload.get("subject") or payload.get("summary") or payload.get("title") or "").strip()
    if not subject:
        raise ValueError("calendar event creation requires subject, summary, or title")
    if "subject" not in payload:
        payload["subject"] = subject
    return payload


def _email_message_payload(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    message = params.get("message", {})
    if not isinstance(message, dict):
        raise ValueError("email message payload must be an object")
    payload = dict(message)
    for key, value in params.items():
        if key not in {"message", "api_url", "provider_url", "token_secret"} and key not in payload:
            payload[key] = value
    subject = str(payload.get("subject") or "").strip()
    if operation == "send_email" and not subject:
        raise ValueError("email send requires subject")
    if not any(payload.get(key) for key in ("to", "toRecipients", "recipients")) and operation == "send_email":
        raise ValueError("email send requires to, toRecipients, or recipients")
    return payload


def _contact_payload(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    contact = params.get("contact", {})
    if not isinstance(contact, dict):
        raise ValueError("contact payload must be an object")
    payload = dict(contact)
    for key, value in params.items():
        if key not in {"operation", "contact", "api_url", "provider_url", "token_secret"} and key not in payload:
            payload[key] = value
    if operation == "create_contact" and not any(payload.get(key) for key in ("displayName", "givenName", "surname", "email", "emailAddresses")):
        raise ValueError("contact creation requires displayName, name, or email")
    if operation == "update_contact" and not any(payload.get(key) for key in ("id", "contact_id", "email", "emailAddresses")):
        raise ValueError("contact update requires id, contact_id, or email")
    return payload


def _rollback_operation_for(operation: str) -> str | None:
    if operation in {"create_event", "rollback_event"}:
        return "rollback_event"
    if operation in {"create_contact", "rollback_contact"}:
        return "rollback_contact"
    return None


def _rollback_payload(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    resource = params.get("event" if operation == "rollback_event" else "contact", {})
    if not isinstance(resource, dict):
        raise ValueError(f"{_write_label(operation)} rollback payload must be an object")
    payload = {key: resource[key] for key in ("id", "event_id", "contact_id", "email") if key in resource}
    for key in ("id", "event_id", "contact_id", "email"):
        if key in params and key not in payload:
            payload[key] = params[key]
    if not payload:
        raise ValueError(f"{_write_label(operation)} rollback requires id, event_id, contact_id, or email")
    payload["rollback_reason"] = "Aegis rollback approved by local operator"
    return payload


def _rollback_offer_receipt(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    rollback_operation = _rollback_operation_for(operation)
    available = rollback_operation is not None and bool(_resource_ref_hash(payload))
    return {
        "receipt_schema": "graph_rollback_offer_v1",
        "rollback_available": available,
        "rollback_operation": rollback_operation if available else None,
        "resource_type": "calendar_event" if rollback_operation == "rollback_event" else "contact" if rollback_operation == "rollback_contact" else None,
        "resource_ref_hash": _resource_ref_hash(payload) if available else None,
        "requires_approval": True,
        "raw_secret_values_included": False,
        "raw_response_body_included": False,
    }


def _resource_ref_hash(payload: dict[str, Any]) -> str:
    for key in ("id", "event_id", "contact_id", "email"):
        value = str(payload.get(key) or "").strip()
        if value:
            return hashlib.sha256(value.encode("utf-8")).hexdigest()
    return ""


def _send_graph_write(*, operation: str, url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    method = _method_for_operation(operation)
    body = None if method == "DELETE" else json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    http_request = Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(http_request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": f"HTTP redirects are not followed by the governed {_write_label(operation)} connector"}
        return {"ok": False, "http_status": exc.code, "error": f"{_write_label(operation)} write failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"{_write_label(operation)} write failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response.read(4096)
    return {"ok": 200 <= status < 300, "http_status": status, "error": None if 200 <= status < 300 else f"{_write_label(operation)} write failed with status {status}"}


def _write_label(operation: str) -> str:
    if operation in {"draft_email", "send_email"}:
        return "email"
    if operation in {"create_contact", "update_contact", "rollback_contact"}:
        return "contact"
    return "calendar"


def _write_scope(operation: str) -> str:
    if operation in {"draft_email", "send_email"}:
        return "mail:write"
    if operation in {"create_contact", "update_contact", "rollback_contact"}:
        return "contacts:write"
    return "calendar:write"


def _method_for_operation(operation: str) -> str:
    if operation in {"rollback_event", "rollback_contact"}:
        return "DELETE"
    return "PATCH" if operation == "update_contact" else "POST"


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _summarize_params(params: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(params, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return {
        "receipt_schema": "redacted_param_summary_v1",
        "param_sha256": hashlib.sha256(encoded).hexdigest(),
        "param_bytes": len(encoded),
        "param_keys": sorted(str(key) for key in params),
        "raw_secret_values_included": False,
        "raw_response_body_included": False,
        "redacted_preview": _preview(redact(params)),
    }


def _preview(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _preview(item) for key, item in value.items()}
    if isinstance(value, list):
        return {"type": "list", "items": len(value), "preview": [_preview(item) for item in value[:10]]}
    if isinstance(value, str):
        return {"type": "string", "chars": len(value), "redacted": value == "[REDACTED]" or "[REDACTED_VALUE]" in value}
    return value
