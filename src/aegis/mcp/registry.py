"""Governed MCP server registry."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.security.taint import now_utc


class McpRegistry:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def register_server(
        self,
        *,
        name: str,
        command: str,
        allowed_tools: tuple[str, ...],
        enabled: bool = False,
        approval_required: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        row = {
            "id": str(uuid4()),
            "name": name,
            "command": command,
            "allowed_tools": list(allowed_tools),
            "enabled": enabled,
            "approval_required": approval_required,
            "created_at": now_utc(),
            "updated_at": now_utc(),
            "metadata": metadata or {},
        }
        self.store.insert_mcp_server(row)
        self.audit_logger.append("mcp.server_registered", {"id": row["id"], "name": name, "enabled": enabled, "approval_required": approval_required})
        return row

    def list_servers(self) -> list[dict[str, Any]]:
        servers = []
        for row in self.store.list_mcp_servers():
            decoded = dict(row)
            decoded["allowed_tools"] = json.loads(decoded.pop("allowed_tools_json", "[]"))
            decoded["metadata"] = json.loads(decoded.pop("metadata_json", "{}"))
            decoded["enabled"] = bool(decoded["enabled"])
            decoded["approval_required"] = bool(decoded["approval_required"])
            servers.append(decoded)
        return servers
