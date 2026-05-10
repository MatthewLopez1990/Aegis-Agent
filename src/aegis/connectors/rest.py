"""Generic REST connector stub built on the HTTP allowlist model."""

from __future__ import annotations

from aegis.connectors.http import HttpConnector


class GenericRestConnector(HttpConnector):
    def __init__(self, *, allowlist: tuple[str, ...]) -> None:
        super().__init__(allowlist=allowlist, live_network=False)
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
