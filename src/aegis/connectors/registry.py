"""Connector registry and reference connector factory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.config.loader import AegisConfig
from aegis.connectors.base import Connector
from aegis.connectors.filesystem import LocalFilesystemConnector
from aegis.connectors.github import GitHubConnectorStub
from aegis.connectors.http import HttpConnector
from aegis.connectors.mock_graph import MockGraphConnector
from aegis.connectors.mock_messaging import MockMessagingConnector
from aegis.connectors.mock_servicenow import MockServiceNowConnector
from aegis.connectors.rest import GenericRestConnector
from aegis.connectors.shell import ShellConnector


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
                "supported_operations": list(connector.spec.supported_operations),
                "approval_required": list(connector.spec.approval_required),
            }
            for connector in self._connectors.values()
        ]

    def status(self) -> list[dict[str, Any]]:
        return [connector.health_check() for connector in self._connectors.values()]


def build_default_registry(config: AegisConfig, audit_logger: AuditLogger, *, workspace: str | Path = ".") -> ConnectorRegistry:
    registry = ConnectorRegistry(audit_logger)
    registry.register(LocalFilesystemConnector(workspace, allow_write=not config.default_read_only))
    registry.register(ShellConnector(workspace, allowed_commands=config.allowed_shell_commands))
    registry.register(HttpConnector(allowlist=config.network_allowlist, live_network=False))
    registry.register(GitHubConnectorStub())
    registry.register(GenericRestConnector(allowlist=config.network_allowlist))
    registry.register(MockGraphConnector())
    registry.register(MockServiceNowConnector())
    registry.register(MockMessagingConnector())
    return registry
