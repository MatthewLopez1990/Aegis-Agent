"""HTTP connector stub with network allowlist enforcement."""

from __future__ import annotations

from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec, require_scope
from aegis.security.network import private_network_error, response_private_network_error
from aegis.security.taint import RiskLevel, Sensitivity


class HttpConnector:
    def __init__(self, *, allowlist: tuple[str, ...], live_network: bool = False) -> None:
        self.allowlist = allowlist
        self.live_network = live_network
        self.spec = ConnectorSpec(
            name="http",
            version="0.1.0",
            auth_type="none",
            required_scopes=("read",),
            optional_scopes=(),
            supported_operations=("read", "dry_run"),
            risk_by_operation={"read": RiskLevel.MEDIUM, "dry_run": RiskLevel.LOW},
            rate_limits={"per_minute": 30},
            data_sensitivity=Sensitivity.INTERNAL,
            default_mode="mock",
            approval_required=("read_unapproved_domain",),
        )

    def connect(self) -> bool:
        return True

    def health_check(self) -> dict[str, Any]:
        return {"name": self.spec.name, "allowlist": list(self.allowlist), "live_network": self.live_network}

    def list_scopes(self) -> tuple[str, ...]:
        return self.spec.required_scopes

    def request_scope(self, scope: str) -> bool:
        return scope == "read"

    def read(self, request: ConnectorRequest) -> ConnectorResult:
        require_scope(request, "read", connector=self.spec.name)
        url = str(request.params["url"])
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed)
        if validation_error:
            return ConnectorResult(self.spec.name, "read", False, {}, error=validation_error)
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, "read", False, {}, error=f"domain {domain!r} is not allowlisted")
        if not self.live_network:
            return ConnectorResult(self.spec.name, "read", True, {"url": url, "domain": domain, "content": "[mock http content]"})
        private_error = _private_network_error(domain)
        if private_error:
            return ConnectorResult(self.spec.name, "read", False, {}, error=private_error)
        http_request = Request(url, headers={"User-Agent": "Aegis-Agent/0.1"})
        try:
            response_context = _open_without_redirects(http_request, timeout=10)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                location = exc.headers.get("Location", "")
                target_url = urljoin(url, location)
                target_domain = urlparse(target_url).hostname or ""
                if target_domain and not self._allowed(target_domain):
                    return ConnectorResult(self.spec.name, "read", False, {}, error=f"redirect target domain {target_domain!r} is not allowlisted")
                return ConnectorResult(self.spec.name, "read", False, {}, error="HTTP redirects are not followed by the governed connector")
            return ConnectorResult(self.spec.name, "read", False, {}, error=f"HTTP request failed with status {exc.code}")
        except URLError as exc:
            return ConnectorResult(self.spec.name, "read", False, {}, error=f"HTTP request failed: {exc.reason}")
        with response_context as response:
            peer_error = response_private_network_error(response, target="live HTTP reads")
            if peer_error:
                return ConnectorResult(self.spec.name, "read", False, {}, error=peer_error)
            final_url = response.geturl() if hasattr(response, "geturl") else url
            final_domain = urlparse(final_url).hostname or ""
            if final_domain and not self._allowed(final_domain):
                return ConnectorResult(self.spec.name, "read", False, {}, error=f"response domain {final_domain!r} is not allowlisted")
            content = response.read(20000).decode("utf-8", errors="replace")
        return ConnectorResult(self.spec.name, "read", True, {"url": url, "domain": domain, "final_url": final_url, "content": content})

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "write", False, {}, error="http write is not implemented in the current governed runtime")

    def dry_run(self, request: ConnectorRequest) -> ConnectorResult:
        require_scope(request, "read", connector=self.spec.name)
        url = str(request.params.get("url", ""))
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed)
        return ConnectorResult(self.spec.name, "dry_run", True, {"url": url, "domain": domain, "allowed": validation_error is None and self._allowed(domain), "error": validation_error})

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "rollback", False, {}, error="http rollback is not available")

    def audit(self) -> dict[str, Any]:
        return self.health_check()

    def disconnect(self) -> bool:
        return True

    def _allowed(self, domain: str) -> bool:
        return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in self.allowlist)


def _validate_url(parsed) -> str | None:
    if parsed.scheme not in {"http", "https"}:
        return "only http and https URLs are supported"
    if parsed.username or parsed.password:
        return "credentials in URLs are not allowed"
    if not parsed.hostname:
        return "URL hostname is required"
    return None


def _private_network_error(hostname: str) -> str | None:
    return private_network_error(hostname, target="live HTTP reads")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _open_without_redirects(request: Request, *, timeout: float):
    opener = build_opener(_NoRedirectHandler)
    return opener.open(request, timeout=timeout)
