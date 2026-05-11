"""Generic REST connector stub built on the HTTP allowlist model."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from aegis.connectors.base import ConnectorRequest, ConnectorResult, require_scope
from aegis.connectors.http import HttpConnector, _open_without_redirects, _private_network_error, _validate_url


class GenericRestConnector(HttpConnector):
    def __init__(self, *, allowlist: tuple[str, ...], live_writes: bool = False) -> None:
        super().__init__(allowlist=allowlist, live_network=False)
        self.live_writes = live_writes
        self.spec = self.spec.__class__(
            name="generic_rest",
            version=self.spec.version,
            auth_type="brokered",
            required_scopes=self.spec.required_scopes,
            optional_scopes=("write",),
            supported_operations=("read", "dry_run", "write"),
            risk_by_operation=self.spec.risk_by_operation,
            rate_limits=self.spec.rate_limits,
            data_sensitivity=self.spec.data_sensitivity,
            default_mode="mock",
            approval_required=("write",),
        )

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        require_scope(request, "write", connector=self.spec.name)
        if not request.approved:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="REST write requires approval")
        url = str(request.params["url"])
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=validation_error)
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"domain {domain!r} is not allowlisted")
        payload = request.params.get("payload", {})
        summary = _summarize_payload(payload)
        if self.live_writes:
            live_error = _validate_live_write_target(parsed, domain)
            if live_error:
                return ConnectorResult(self.spec.name, request.operation, False, {}, error=live_error)
            live_result = _send_live_rest_write(method=_method_for_operation(request.operation), url=url, payload=payload)
            return ConnectorResult(
                self.spec.name,
                request.operation,
                live_result["ok"],
                {
                    "url": url,
                    "domain": domain,
                    "status": live_result["http_status"],
                    "mode": "live_write",
                    "accepted": summary,
                },
                rollback="provider-specific rollback required for REST writes",
                error=live_result.get("error"),
            )
        return ConnectorResult(
            self.spec.name,
            request.operation,
            True,
            {
                "url": url,
                "domain": domain,
                "status": 202,
                "mode": "mock_write",
                "accepted": summary,
            },
            rollback="provider-specific rollback required for REST writes",
        )

    def health_check(self) -> dict[str, Any]:
        return {**super().health_check(), "live_writes": self.live_writes}


def _summarize_payload(payload: Any) -> dict[str, Any]:
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    keys = sorted(str(key) for key in payload.keys()) if isinstance(payload, dict) else []
    return {
        "receipt_schema": "redacted_payload_summary_v1",
        "payload_sha256": hashlib.sha256(encoded).hexdigest(),
        "payload_keys": keys,
        "payload_bytes": len(encoded),
        "raw_secret_values_included": False,
        "raw_response_body_included": False,
    }


def _method_for_operation(operation: str) -> str:
    method = operation.upper()
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return method
    if operation == "webhook_call":
        return "POST"
    return "POST"


def _validate_live_write_target(parsed, domain: str) -> str | None:  # noqa: ANN001
    if parsed.scheme != "https":
        return "live REST writes require https"
    return _private_network_error(domain)


def _send_live_rest_write(*, method: str, url: str, payload: Any) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    http_request = Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json", "User-Agent": "Aegis-Agent/0.1"},
    )
    try:
        response_context = _open_without_redirects(http_request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed REST connector"}
        return {"ok": False, "http_status": exc.code, "error": f"REST write failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"REST write failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response.read(4096)
    return {"ok": 200 <= status < 300, "http_status": status, "error": None if 200 <= status < 300 else f"REST write failed with status {status}"}
