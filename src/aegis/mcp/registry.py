"""Governed MCP server registry."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
from typing import Any
from uuid import uuid4

from aegis.audit.logger import AuditLogger, redact
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

    def discover_tools(
        self,
        *,
        command: str,
        allowed_executables: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        argv = _parse_allowed_command(command, allowed_executables)
        raw_tools = McpStdioClient(argv).list_tools()
        tools: list[dict[str, Any]] = []
        for raw_tool in raw_tools:
            name = str(raw_tool.get("name") or "").strip()
            if not name:
                continue
            input_schema = raw_tool.get("inputSchema")
            tools.append(
                {
                    "name": name,
                    "description": str(raw_tool.get("description") or "")[:500],
                    "input_schema": input_schema if isinstance(input_schema, dict) else {},
                }
            )
        self.audit_logger.append(
            "mcp.tools_discovered",
            {
                "executable": Path(argv[0]).name,
                "tool_count": len(tools),
                "tool_names": [redact({"name": tool["name"]})["name"] for tool in tools[:50]],
            },
        )
        return tools

    def register_discovered_server(
        self,
        *,
        name: str,
        command: str,
        allowed_executables: tuple[str, ...],
        include_tools: tuple[str, ...] = (),
        exclude_tools: tuple[str, ...] = (),
        enabled: bool = False,
        approval_required: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        discovered = self.discover_tools(command=command, allowed_executables=allowed_executables)
        by_name = {tool["name"]: tool for tool in discovered}
        includes = tuple(tool.strip() for tool in include_tools if tool.strip())
        excludes = {tool.strip() for tool in exclude_tools if tool.strip()}
        if includes:
            missing = sorted(tool for tool in includes if tool not in by_name)
            if missing:
                raise ValueError(f"MCP discovery did not expose requested tools: {', '.join(missing)}")
            selected = [by_name[tool] for tool in includes]
        else:
            selected = [tool for tool in discovered if tool["name"] not in excludes]
        if not selected:
            raise ValueError("MCP discovery produced no allowlisted tools")
        discovery_metadata = {
            "discovered": True,
            "tool_count": len(discovered),
            "selected_tool_count": len(selected),
            "virtual_tools": [
                {
                    "name": tool["name"],
                    "virtual_name": mcp_virtual_tool_name(name, tool["name"]),
                    "description": redact(tool.get("description", "")),
                    "input_schema": tool.get("input_schema", {}),
                }
                for tool in selected
            ],
        }
        return self.register_server(
            name=name,
            command=command,
            allowed_tools=tuple(tool["name"] for tool in selected),
            enabled=enabled,
            approval_required=approval_required,
            metadata={**(metadata or {}), "discovery": discovery_metadata},
        )

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

    def set_enabled(self, server: str, enabled: bool) -> dict[str, Any]:
        row = self.get_server(server)
        self.store.set_mcp_server_enabled(row["id"], enabled)
        updated = self.get_server(row["id"])
        self.audit_logger.append("mcp.server_enabled" if enabled else "mcp.server_disabled", {"id": row["id"], "name": row["name"], "enabled": enabled})
        return updated

    def remove_server(self, server: str) -> dict[str, Any]:
        row = self.get_server(server)
        self.store.delete_mcp_server(row["id"])
        self.audit_logger.append("mcp.server_removed", {"id": row["id"], "name": row["name"]})
        return row

    def virtual_tools(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for server in self.list_servers():
            metadata_tools = _metadata_virtual_tools(server.get("metadata", {}))
            for tool in server.get("allowed_tools", []):
                tool_name = str(tool)
                metadata = metadata_tools.get(tool_name, {})
                virtual_name = str(metadata.get("virtual_name") or mcp_virtual_tool_name(str(server["name"]), tool_name))
                rows.append(
                    {
                        "name": virtual_name,
                        "server_id": server["id"],
                        "server_name": server["name"],
                        "tool": tool_name,
                        "toolset": f"mcp-{_sanitize_identifier(str(server['name'])).replace('_', '-')}",
                        "enabled": bool(server["enabled"]),
                        "approval_required": bool(server["approval_required"]),
                        "description": str(metadata.get("description") or f"MCP tool {tool_name} from {server['name']}"),
                        "input_schema": metadata.get("input_schema", {}) if isinstance(metadata.get("input_schema", {}), dict) else {},
                    }
                )
        return sorted(rows, key=lambda row: row["name"])

    def virtual_tool_specs(self) -> list[dict[str, Any]]:
        specs: list[dict[str, Any]] = []
        for tool in self.virtual_tools():
            specs.append(
                {
                    "name": tool["name"],
                    "description": tool["description"],
                    "permission": "read/write",
                    "risk_level": RiskLevel.HIGH.value,
                    "input_schema": tool["input_schema"],
                    "output_schema": {"result": "object"},
                    "implemented": bool(tool["enabled"]),
                    "implementation_status": "mcp_server_enabled" if tool["enabled"] else "mcp_server_disabled",
                    "approval_required": bool(tool["approval_required"]),
                    "categories": ["mcp", tool["toolset"]],
                    "server_name": tool["server_name"],
                    "mcp_tool": tool["tool"],
                }
            )
        return specs

    def resolve_virtual_tool(self, virtual_name: str) -> dict[str, Any] | None:
        normalized = virtual_name.strip()
        for tool in self.virtual_tools():
            if tool["name"] == normalized:
                return tool
        return None

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


def mcp_virtual_tool_name(server_name: str, tool_name: str) -> str:
    return f"mcp_{_sanitize_identifier(server_name)}_{_sanitize_identifier(tool_name)}"


def _sanitize_identifier(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_]+", "_", value.strip()).strip("_").lower()
    normalized = re.sub(r"_+", "_", normalized)
    return normalized or "tool"


def _metadata_virtual_tools(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    discovery = metadata.get("discovery") if isinstance(metadata, dict) else {}
    if not isinstance(discovery, dict):
        return {}
    tools = discovery.get("virtual_tools", [])
    if not isinstance(tools, list):
        return {}
    by_name: dict[str, dict[str, Any]] = {}
    for tool in tools:
        if isinstance(tool, dict) and tool.get("name"):
            by_name[str(tool["name"])] = tool
    return by_name
