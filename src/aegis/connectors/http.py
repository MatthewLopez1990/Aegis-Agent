"""HTTP connector stub with network allowlist enforcement."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from aegis.connectors.base import ConnectorRequest, ConnectorResult, ConnectorSpec
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
        url = str(request.params["url"])
        domain = urlparse(url).hostname or ""
        if not self._allowed(domain):
            return ConnectorResult(self.spec.name, "read", False, {}, error=f"domain {domain!r} is not allowlisted")
        if not self.live_network:
            return ConnectorResult(self.spec.name, "read", True, {"url": url, "domain": domain, "content": "[mock http content]"})
        http_request = Request(url, headers={"User-Agent": "Aegis-Agent/0.1"})
        with urlopen(http_request, timeout=10) as response:
            content = response.read(20000).decode("utf-8", errors="replace")
        return ConnectorResult(self.spec.name, "read", True, {"url": url, "domain": domain, "content": content})

    def write(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "write", False, {}, error="http write is not implemented in the current governed runtime")

    def dry_run(self, request: ConnectorRequest) -> ConnectorResult:
        url = str(request.params.get("url", ""))
        domain = urlparse(url).hostname or ""
        return ConnectorResult(self.spec.name, "dry_run", True, {"url": url, "domain": domain, "allowed": self._allowed(domain)})

    def rollback(self, request: ConnectorRequest) -> ConnectorResult:
        return ConnectorResult(self.spec.name, "rollback", False, {}, error="http rollback is not available")

    def audit(self) -> dict[str, Any]:
        return self.health_check()

    def disconnect(self) -> bool:
        return True

    def _allowed(self, domain: str) -> bool:
        return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in self.allowlist)
