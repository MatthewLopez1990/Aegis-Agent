"""Governed MCP server registry."""

from __future__ import annotations

import json
from pathlib import Path
import shlex
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.mcp.client import McpStdioClient, McpToolCallResult
from aegis.security.context_firewall import ContextFirewall
from aegis.security.policy_engine import PolicyDecisionType, PolicyEngine, PolicyRequest
from aegis.security.taint import RiskLevel, Sensitivity, TrustClass, now_utc


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

    def get_server(self, server: str) -> dict[str, Any]:
        for row in self.list_servers():
            if row["id"] == server or row["name"] == server:
                return row
        raise KeyError(server)

    def call_tool(
        self,
        *,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        approved: bool = False,
        task_id: str | None = None,
        policy_engine: PolicyEngine | None = None,
        allowed_executables: tuple[str, ...] = (),
    ) -> McpToolCallResult:
        row = self.get_server(server)
        if not row["enabled"]:
            self.audit_logger.append("mcp.call_blocked", {"server": row["name"], "tool": tool, "reason": "server disabled"}, task_id=task_id)
            raise PermissionError("MCP server is disabled")
        if tool not in row["allowed_tools"]:
            self.audit_logger.append("mcp.call_blocked", {"server": row["name"], "tool": tool, "reason": "tool not allowlisted"}, task_id=task_id)
            raise PermissionError("MCP tool is not allowlisted for this server")
        if row["approval_required"] and not approved:
            self.audit_logger.append("mcp.call_blocked", {"server": row["name"], "tool": tool, "reason": "approval required"}, task_id=task_id)
            raise PermissionError("MCP tool call requires approval")
        decision = (policy_engine or PolicyEngine()).evaluate(
            PolicyRequest(
                user_role="local-user",
                workspace="local",
                task_type="mcp tool call",
                risk_level=RiskLevel.HIGH,
                connector="mcp",
                operation="write",
                requested_scopes=("write",),
                approval_state="approved" if approved else None,
                data_sensitivity=Sensitivity.INTERNAL,
            )
        )
        if decision.decision != PolicyDecisionType.ALLOW:
            self.audit_logger.append("mcp.call_blocked", {"server": row["name"], "tool": tool, "decision": decision.decision.value, "reason": "; ".join(decision.reasons)}, task_id=task_id)
            raise PermissionError("; ".join(decision.reasons))
        argv = _parse_allowed_command(str(row["command"]), allowed_executables)
        result = McpStdioClient(argv).call_tool(tool, arguments)
        context_item = ContextFirewall().label_content(
            json.dumps(result, sort_keys=True),
            source=f"mcp:{row['name']}:{tool}",
            trust_class=TrustClass.TOOL_OUTPUT,
            connector_or_tool="mcp",
        )
        sanitized_context = ContextFirewall().process([context_item]).model_context[0]
        call = McpToolCallResult(row["id"], row["name"], tool, result, sanitized_context)
        self.audit_logger.append(
            "mcp.tool_called",
            {"server": row["name"], "tool": tool, "argument_keys": sorted(arguments), "result_keys": sorted(result)},
            task_id=task_id,
        )
        return call


def _parse_allowed_command(command: str, allowed_executables: tuple[str, ...]) -> list[str]:
    argv = shlex.split(command)
    if not argv:
        raise ValueError("empty MCP server command")
    executable = Path(argv[0]).name
    if not allowed_executables:
        raise PermissionError("no MCP executable allowlist is configured")
    if executable not in allowed_executables:
        raise PermissionError(f"MCP server command {executable!r} is not allowlisted")
    return argv
