"""GitHub connector with mock defaults and optional governed live writes."""

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


class GitHubConnectorStub(MockServiceConnector):
    def __init__(
        self,
        *,
        allowlist: tuple[str, ...] = ("api.github.com",),
        live_writes: bool = False,
        secrets_broker: SecretsBroker | None = None,
        rate_limits: dict[str, Any] | None = None,
        rate_limiter: InMemoryRateLimiter | None = None,
    ) -> None:
        super().__init__(
            name="github",
            operations=("read_repo", "read_issue", "read_pull_request", "read_pull_request_comments"),
            write_operations=("create_issue", "comment_on_pull_request"),
            sample_data={
                "repositories": [{"name": "mock-repo", "default_branch": "main"}],
                "issues": [{"number": 1, "title": "Mock issue", "state": "open"}],
                "pull_request_comments": [
                    {
                        "id": 101,
                        "path": "src/aegis/example.py",
                        "line": 12,
                        "body": "Mock review comment",
                        "user": "reviewer",
                    }
                ],
            },
        )
        self.allowlist = allowlist
        self.live_writes = live_writes
        self.secrets_broker = secrets_broker or SecretsBroker()
        self._rate_limiter = rate_limiter or InMemoryRateLimiter()
        configured_rate_limits = rate_limits or self.spec.rate_limits
        self.spec = ConnectorSpec(
            name="github",
            version="0.4.0",
            auth_type="brokered_token",
            required_scopes=("read",),
            optional_scopes=("write",),
            supported_operations=self.spec.supported_operations,
            risk_by_operation={
                "read_repo": RiskLevel.LOW,
                "read_issue": RiskLevel.LOW,
                "read_pull_request": RiskLevel.LOW,
                "read_pull_request_comments": RiskLevel.LOW,
                "create_issue": RiskLevel.HIGH,
                "comment_on_pull_request": RiskLevel.HIGH,
                "dry_run": RiskLevel.MEDIUM,
            },
            rate_limits=configured_rate_limits,
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="mock_read_only",
            approval_required=("create_issue", "comment_on_pull_request"),
            operation_scopes=self.spec.operation_scopes,
        )

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        if not self._is_live_write_request(request):
            return super().write(request)
        require_scope(request, "write", connector=self.spec.name)
        url = str(request.params.get("api_url") or request.params.get("provider_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if not request.approved:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=self.live_writes, approved=False, allowlist=self.allowlist, domain=domain)},
                error="GitHub live write requires approval",
            )
        if request.operation not in self.write_operations:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"unsupported GitHub write operation: {request.operation}")
        if not self.live_writes:
            return ConnectorResult(
                self.spec.name,
                request.operation,
                False,
                {"activation": live_connector_activation(connector=self.spec.name, operation=request.operation, enabled=False, approved=True, allowlist=self.allowlist, domain=domain)},
                error="GitHub live writes are disabled",
            )
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=validation_error)
        if parsed.scheme != "https":
            return ConnectorResult(self.spec.name, request.operation, False, {}, error="GitHub live writes require https")
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=private_error)
        token_secret = str(request.params.get("token_secret") or "GITHUB_TOKEN")
        handle = self.secrets_broker.request_handle(
            name=token_secret,
            requester="github_connector",
            reason=f"GitHub {request.operation}",
            scopes=("github:write",),
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
            token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="github_connector")
        except KeyError as exc:
            return ConnectorResult(self.spec.name, request.operation, False, {}, error=str(exc))
        try:
            payload = _github_payload(request.operation, request.params)
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
                error="GitHub live write rate limit exceeded",
            )
        live_result = _send_github_write(url=url, token=token, payload=payload)
        accepted = _summarize_params({"url": url, "payload": payload, "token_secret": token_secret})
        rollback_receipt = _rollback_offer_receipt(request.operation, live_result.get("response_json"))
        rollback = (
            f"{rollback_receipt['rollback_operation']} available with approval"
            if rollback_receipt["rollback_available"]
            else "provider-specific GitHub rollback required"
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


def _github_payload(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    if operation == "create_issue":
        title = str(params.get("title") or params.get("issue", {}).get("title") or "").strip()
        if not title:
            raise ValueError("GitHub issue creation requires title")
        payload = {"title": title}
        body = params.get("body") or params.get("issue", {}).get("body")
        if body is not None:
            payload["body"] = str(body)
        labels = params.get("labels") or params.get("issue", {}).get("labels")
        if isinstance(labels, list):
            payload["labels"] = [str(label) for label in labels[:25]]
        return payload
    body = str(params.get("body") or params.get("comment") or "").strip()
    if not body:
        raise ValueError("GitHub pull-request comment requires body or comment")
    return {"body": body}


def _send_github_write(*, url: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    http_request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Agent/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        response_context = _open_without_redirects(http_request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed GitHub connector"}
        return {"ok": False, "http_status": exc.code, "error": f"GitHub write failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"GitHub write failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        response_body = response.read(4096)
    return {
        "ok": 200 <= status < 300,
        "http_status": status,
        "response_json": _decoded_json_object(response_body),
        "error": None if 200 <= status < 300 else f"GitHub write failed with status {status}",
    }


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
        resource_ref = response.get("url") or response.get("html_url") or response.get("number") or response.get("id")
        resource_number = _optional_int(response.get("number"))
        resource_id = _optional_int(response.get("id"))
    elif operation == "comment_on_pull_request":
        rollback_operation = "rollback_pull_request_comment"
        resource_ref = response.get("url") or response.get("html_url") or response.get("id")
        resource_number = None
        resource_id = _optional_int(response.get("id"))
    else:
        rollback_operation = None
        resource_ref = None
        resource_number = None
        resource_id = None
    resource_hash = _resource_ref_hash(resource_ref)
    return {
        "receipt_schema": "github_rollback_offer_v1",
        "rollback_available": bool(rollback_operation and resource_hash),
        "rollback_operation": rollback_operation if resource_hash else None,
        "resource_ref_hash": resource_hash or None,
        "resource_number": resource_number,
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
