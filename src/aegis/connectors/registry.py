"""Connector registry and reference connector factory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.config.loader import AegisConfig
from aegis.connectors.base import Connector
from aegis.connectors.filesystem import LocalFilesystemConnector
from aegis.connectors.github import GitHubConnectorStub
from aegis.connectors.gitlab import GitLabConnectorStub
from aegis.connectors.http import HttpConnector
from aegis.connectors.mock_graph import MockGraphConnector
from aegis.connectors.mock_messaging import MockMessagingConnector
from aegis.connectors.mock_servicenow import MockServiceNowConnector
from aegis.connectors.rest import GenericRestConnector
from aegis.connectors.shell import ShellConnector
from aegis.security.secrets_broker import SecretsBroker


class ConnectorRegistry:
    def __init__(self, audit_logger: AuditLogger) -> None:
        self.audit_logger = audit_logger
        self._connectors: dict[str, Connector] = {}

    def register(self, connector: Connector) -> None:
        self._connectors[connector.spec.name] = connector
        self.audit_logger.append("connector.registered", {"name": connector.spec.name, "version": connector.spec.version})

    def get(self, name: str) -> Connector:
        try:
            return self._connectors[name]
        except KeyError as exc:
            raise KeyError(f"unknown connector {name!r}") from exc

    def list(self) -> list[dict[str, Any]]:
        return [
            {
                "name": connector.spec.name,
                "version": connector.spec.version,
                "auth_type": connector.spec.auth_type,
                "default_mode": connector.spec.default_mode,
                "required_scopes": list(connector.spec.required_scopes),
                "optional_scopes": list(connector.spec.optional_scopes),
                "supported_operations": list(connector.spec.supported_operations),
                "approval_required": list(connector.spec.approval_required),
                "operation_scopes": {operation: list(scopes) for operation, scopes in connector.spec.operation_scopes.items()},
                "risk_by_operation": {operation: risk.value for operation, risk in connector.spec.risk_by_operation.items()},
                "rate_limits": dict(connector.spec.rate_limits),
                "data_sensitivity": connector.spec.data_sensitivity.value,
            }
            for connector in self._connectors.values()
        ]

    def status(self) -> list[dict[str, Any]]:
        return [connector.health_check() for connector in self._connectors.values()]


def build_default_registry(config: AegisConfig, audit_logger: AuditLogger, *, workspace: str | Path = ".") -> ConnectorRegistry:
    registry = ConnectorRegistry(audit_logger)
    registry.register(LocalFilesystemConnector(workspace, allow_write=not config.default_read_only))
    registry.register(ShellConnector(workspace, allowed_commands=config.allowed_shell_commands))
    registry.register(HttpConnector(allowlist=config.network_allowlist, live_network=config.live_http_reads))
    registry.register(
        GitHubConnectorStub(
            allowlist=config.network_allowlist,
            live_writes=config.live_github_writes,
            secrets_broker=SecretsBroker(config.secrets_path),
        )
    )
    registry.register(
        GitLabConnectorStub(
            allowlist=config.network_allowlist,
            live_writes=config.live_gitlab_writes,
            secrets_broker=SecretsBroker(config.secrets_path),
        )
    )
    registry.register(GenericRestConnector(allowlist=config.network_allowlist, live_writes=config.live_rest_writes))
    registry.register(
        MockGraphConnector(
            allowlist=config.network_allowlist,
            live_calendar_writes=config.live_graph_calendar_writes,
            live_email_writes=config.live_graph_email_writes,
            live_contact_writes=config.live_graph_contact_writes,
            secrets_broker=SecretsBroker(config.secrets_path),
        )
    )
    registry.register(
        MockServiceNowConnector(
            allowlist=config.network_allowlist,
            live_writes=config.live_service_desk_writes,
            secrets_broker=SecretsBroker(config.secrets_path),
        )
    )
    registry.register(
        MockMessagingConnector(
            allowlist=config.network_allowlist,
            live_writes=config.live_messaging_writes,
            secrets_broker=SecretsBroker(config.secrets_path),
        )
    )
    return registry
