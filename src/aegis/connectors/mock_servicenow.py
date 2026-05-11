"""Service-desk connector with mock defaults and optional governed live writes."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from aegis.audit.logger import redact
from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec, require_scope
from aegis.connectors.http import _open_without_redirects, _private_network_error, _validate_url
from aegis.connectors.mock_service import MockServiceConnector
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import RiskLevel, Sensitivity


class MockServiceNowConnector(MockServiceConnector):
    def __init__(
        self,
        *,
        allowlist: tuple[str, ...] = ("api.service-now.com",),
        live_writes: bool = False,
        secrets_broker: SecretsBroker | None = None,
    ) -> None:
        super().__init__(
            name="mock_servicenow",
            operations=("read_ticket", "search_tickets"),
            write_operations=("create_ticket", "update_ticket", "close_ticket"),
            sample_data={"tickets": [{"id": "INC000001", "state": "new", "summary": "Mock incident"}]},
        )
        self.allowlist = allowlist
        self.live_writes = live_writes
        self.secrets_broker = secrets_broker or SecretsBroker()
        self.spec = ConnectorSpec(
            name="mock_servicenow",
            version="0.2.0",
            auth_type="brokered_token",
            required_scopes=("read",),
            optional_scopes=("write",),
            supported_operations=self.spec.supported_operations,
            risk_by_operation={
                "read_ticket": RiskLevel.LOW,
                "search_tickets": RiskLevel.LOW,
                "create_ticket": RiskLevel.HIGH,
                "update_ticket": RiskLevel.HIGH,
                "close_ticket": RiskLevel.HIGH,
                "dry_run": RiskLevel.MEDIUM,
            },
            rate_limits=self.spec.rate_limits,
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="mock_read_only",
            approval_required=("create_ticket", "update_ticket", "close_ticket"),
            operation_scopes=self.spec.operation_scopes,
        )

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        if not self._is_live_write_request(request):
            return super().write(request)
        require_scope(request, "write", connector=self.spec.name)
        if not request.approved:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="service-desk live write requires approval")
        if request.operation not in self.write_operations:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"unsupported service-desk write operation: {request.operation}")
        if not self.live_writes:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="service-desk live writes are disabled")
        url = str(request.params.get("api_url") or request.params.get("provider_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=validation_error)
        if parsed.scheme != "https":
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="service-desk live writes require https")
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=private_error)
        token_secret = str(request.params.get("token_secret") or "SERVICE_DESK_TOKEN")
        handle = self.secrets_broker.request_handle(
            name=token_secret,
            requester="service_desk_connector",
            reason=f"service-desk {request.operation}",
            scopes=("service_desk:write",),
        )
        if not handle.present:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"secret {token_secret!r} is not configured")
        try:
            token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="service_desk_connector")
            payload = _ticket_payload(request.operation, request.params)
        except (KeyError, ValueError) as exc:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=str(exc))
        live_result = _send_service_desk_write(operation=request.operation, url=url, token=token, payload=payload)
        accepted = _summarize_params({"url": url, "payload": payload, "token_secret": token_secret})
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
            },
            rollback="provider-specific service-desk rollback required",
            error=live_result.get("error"),
        )

    def health_check(self) -> dict[str, Any]:
        return {**super().health_check(), "live_writes": self.live_writes, "allowlist": list(self.allowlist)}

    def _allowed(self, domain: str) -> bool:
        return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in self.allowlist)

    @staticmethod
    def _is_live_write_request(request: ConnectorRequest) -> bool:
        return bool(request.params.get("api_url") or request.params.get("provider_url"))


def _ticket_payload(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    ticket = params.get("ticket", {})
    if not isinstance(ticket, dict):
        raise ValueError("service-desk ticket payload must be an object")
    payload = dict(ticket)
    for key, value in params.items():
        if key not in {"operation", "ticket", "api_url", "provider_url", "token_secret"} and key not in payload:
            payload[key] = value
    if operation == "create_ticket" and not any(payload.get(key) for key in ("summary", "short_description", "title", "description")):
        raise ValueError("service-desk ticket creation requires summary, title, or description")
    if operation in {"update_ticket", "close_ticket"} and not any(payload.get(key) for key in ("id", "number", "key", "sys_id")):
        raise ValueError("service-desk ticket update or close requires id, number, key, or sys_id")
    if operation == "close_ticket" and not any(payload.get(key) for key in ("state", "status", "resolution_code")):
        payload["state"] = "closed"
    return payload


def _send_service_desk_write(*, operation: str, url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    http_request = Request(
        url,
        data=body,
        method=_method_for_operation(operation),
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
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed service-desk connector"}
        return {"ok": False, "http_status": exc.code, "error": f"service-desk write failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"service-desk write failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response.read(4096)
    return {"ok": 200 <= status < 300, "http_status": status, "error": None if 200 <= status < 300 else f"service-desk write failed with status {status}"}


def _method_for_operation(operation: str) -> str:
    if operation == "create_ticket":
        return "POST"
    return "PATCH"


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
