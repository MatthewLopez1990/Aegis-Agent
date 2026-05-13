"""GitLab connector with mock defaults and optional governed live writes."""

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


class GitLabConnectorStub(MockServiceConnector):
    def __init__(
        self,
        *,
        allowlist: tuple[str, ...] = ("gitlab.com",),
        live_writes: bool = False,
        secrets_broker: SecretsBroker | None = None,
        rate_limits: dict[str, Any] | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
    ) -> None:
        super().__init__(
            name="gitlab",
            operations=("read_project", "read_issue", "read_merge_request"),
            write_operations=("create_issue", "comment_on_merge_request", "rollback_issue", "rollback_merge_request_note"),
            sample_data={
                "projects": [{"path": "example/aegis", "default_branch": "main"}],
                "issues": [{"iid": 1, "title": "Mock GitLab issue", "state": "opened"}],
            },
        )
        self.allowlist = allowlist
        self.live_writes = live_writes
        self.secrets_broker = secrets_broker or SecretsBroker()
        self._rate_limiter = rate_limiter or InMemoryRateLimiter()
        configured_rate_limits = rate_limits or self.spec.rate_limits
        self.spec = ConnectorSpec(
            name="gitlab",
            version="0.3.0",
            auth_type="brokered_token",
            required_scopes=("read",),
            optional_scopes=("write",),
            supported_operations=self.spec.supported_operations,
            risk_by_operation={
                "read_project": RiskLevel.LOW,
                "read_issue": RiskLevel.LOW,
                "read_merge_request": RiskLevel.LOW,
                "create_issue": RiskLevel.HIGH,
                "comment_on_merge_request": RiskLevel.HIGH,
                "rollback_issue": RiskLevel.HIGH,
                "rollback_merge_request_note": RiskLevel.HIGH,
                "dry_run": RiskLevel.MEDIUM,
            },
            rate_limits=configured_rate_limits,
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="mock_read_only",
            approval_required=("create_issue", "comment_on_merge_request", "rollback_issue", "rollback_merge_request_note"),
            operation_scopes=self.spec.operation_scopes,
        )

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        if request.operation in {"rollback_issue", "rollback_merge_request_note"}:
            return self.rollback(request)
        if not self._is_live_write_request(request):
            return super().write(request)
        require_scope(request, "write", connector=self.spec.name)
        url = str(request.params.get("api_url") or request.params.get("provider_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if request.operation not in self.write_operations:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"unsupported GitLab write operation: {request.operation}")
        if not request.approved:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=self.live_writes, approved=False, allowlist=self.allowlist, domain=domain)},
                error="GitLab live write requires approval",
            )
        if not self.live_writes:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=False, approved=True, allowlist=self.allowlist, domain=domain)},
                error="GitLab live writes are disabled",
            )
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=validation_error)
        if parsed.scheme != "https":
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="GitLab live writes require https")
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=private_error)
        token_secret = str(request.params.get("token_secret") or "GITLAB_TOKEN")
        handle = self.secrets_broker.request_handle(
            name=token_secret,
            requester="gitlab_connector",
            reason=f"GitLab {request.operation}",
            scopes=("gitlab:write",),
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
            token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="gitlab_connector")
        except KeyError as exc:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=str(exc))
        try:
            payload = _gitlab_payload(request.operation, request.params)
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
                error="GitLab live write rate limit exceeded",
            )
        live_result = _send_gitlab_write(url=url, token=token, payload=payload)
        accepted = _summarize_params({"url": url, "payload": payload, "token_secret": token_secret})
        rollback_receipt = _rollback_offer_receipt(request.operation, live_result.get("response_json"))
        rollback = (
            f"{rollback_receipt['rollback_operation']} available with approval"
            if rollback_receipt["rollback_available"]
            else "provider-specific GitLab rollback required"
        )
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
            rollback=rollback,
            error=live_result.get("error"),
        )

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        if not self._is_live_write_request(request):
            return super().rollback(request)
        require_scope(request, "write", connector=self.spec.name)
        operation = request.operation
        if operation not in {"rollback_issue", "rollback_merge_request_note"}:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=f"unsupported GitLab rollback operation: {operation}")
        url = str(request.params.get("rollback_url") or request.params.get("api_url") or request.params.get("provider_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if not request.approved:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=operation, enabled=self.live_writes, approved=False, allowlist=self.allowlist, domain=domain)},
                rollback="no action performed",
                error="GitLab rollback requires approval",
            )
        if not self.live_writes:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=operation, enabled=False, approved=True, allowlist=self.allowlist, domain=domain)},
                rollback="no action performed",
                error="GitLab live writes are disabled",
            )
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=validation_error)
        if parsed.scheme != "https":
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error="GitLab rollback requires https")
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=private_error)
        token_secret = str(request.params.get("token_secret") or "GITLAB_TOKEN")
        handle = self.secrets_broker.request_handle(
            name=token_secret,
            requester="gitlab_connector",
            reason=f"GitLab {operation}",
            scopes=("gitlab:write",),
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
            token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="gitlab_connector")
        except KeyError as exc:
            return ConnectorResult(self.spec.name, operation, False, {}, rollback="no action performed", error=str(exc))
        method, payload = _gitlab_rollback_request(operation, request.params)
        rate_limit = self._check_live_rate_limit(domain=domain, operation=operation)
        if not rate_limit["allowed"]:
            return ConnectorResult(
                self.spec.name,
                operation,
                False,
                {"mode": "live_rollback", "domain": domain, "rate_limit": rate_limit},
                rollback="no action performed",
                error="GitLab rollback rate limit exceeded",
            )
        live_result = _send_gitlab_rollback(method=method, url=url, token=token, payload=payload)
        receipt = {
            "receipt_schema": "gitlab_rollback_receipt_v1",
            "rollback_operation": operation,
            "resource_ref_hash": _resource_ref_hash(url),
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
        return bool(request.params.get("api_url") or request.params.get("provider_url"))


def _gitlab_payload(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    if operation == "create_issue":
        title = str(params.get("title") or params.get("issue", {}).get("title") or "").strip()
        if not title:
            raise ValueError("GitLab issue creation requires title")
        payload = {"title": title}
        description = params.get("description") or params.get("body") or params.get("issue", {}).get("description")
        if description is not None:
            payload["description"] = str(description)
        labels = params.get("labels") or params.get("issue", {}).get("labels")
        if isinstance(labels, list):
            payload["labels"] = ",".join(str(label) for label in labels[:25])
        return payload
    body = str(params.get("body") or params.get("comment") or params.get("note") or "").strip()
    if not body:
        raise ValueError("GitLab merge-request comment requires body, comment, or note")
    return {"body": body}


def _gitlab_rollback_request(operation: str, params: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    if operation == "rollback_issue":
        return "PUT", {"state_event": "close"}
    return "DELETE", None


def _send_gitlab_write(*, url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    http_request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Private-Token": token,
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(http_request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed GitLab connector"}
        return {"ok": False, "http_status": exc.code, "error": f"GitLab write failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"GitLab write failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response_body = response.read(4096)
    return {
        "ok": 200 <= status < 300,
        "http_status": status,
        "response_json": _decoded_json_object(response_body),
        "error": None if 200 <= status < 300 else f"GitLab write failed with status {status}",
    }


def _send_gitlab_rollback(*, method: str, url: str, token: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    http_request = Request(
        url,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Private-Token": token,
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(http_request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed GitLab connector"}
        return {"ok": False, "http_status": exc.code, "error": f"GitLab rollback failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"GitLab rollback failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response.read(4096)
    return {"ok": 200 <= status < 300, "http_status": status, "error": None if 200 <= status < 300 else f"GitLab rollback failed with status {status}"}


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


def _rollback_offer_receipt(operation: str, response_json: Any) -> dict[str, Any]:
    response = response_json if isinstance(response_json, dict) else {}
    if operation == "create_issue":
        rollback_operation = "rollback_issue"
        resource_ref = response.get("web_url") or response.get("url") or response.get("iid") or response.get("id")
        resource_iid = _optional_int(response.get("iid"))
        resource_id = _optional_int(response.get("id"))
    elif operation == "comment_on_merge_request":
        rollback_operation = "rollback_merge_request_note"
        resource_ref = response.get("url") or response.get("web_url") or response.get("id")
        resource_iid = None
        resource_id = _optional_int(response.get("id"))
    else:
        rollback_operation = None
        resource_ref = None
        resource_iid = None
        resource_id = None
    resource_hash = _resource_ref_hash(resource_ref)
    return {
        "receipt_schema": "gitlab_rollback_offer_v1",
        "rollback_available": bool(rollback_operation and resource_hash),
        "rollback_operation": rollback_operation if resource_hash else None,
        "resource_ref_hash": resource_hash or None,
        "resource_iid": resource_iid,
        "resource_id": resource_id,
        "requires_approval": True,
        "raw_secret_values_included": False,
        "raw_response_body_included": False,
    }


def _decoded_json_object(response_body: bytes) -> dict[str, Any]:
    if not response_body:
        return {}
    try:
        decoded = json.loads(response_body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _resource_ref_hash(value: Any) -> str:
    rendered = str(value or "").strip()
    if not rendered:
        return ""
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _preview(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _preview(item) for key, item in value.items()}
    if isinstance(value, list):
        return {"type": "list", "items": len(value), "preview": [_preview(item) for item in value[:10]]}
    if isinstance(value, str):
        return {"type": "string", "chars": len(value), "redacted": value == "[REDACTED]" or "[REDACTED_VALUE]" in value}
    return value
