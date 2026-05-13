"""Governed MCP server registry."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
from typing import Any
from urllib.parse import urlparse, urlunparse
from uuid import uuid4

from aegis.audit.logger import AuditLogger, redact
from aegis.connectors.http import _private_network_error, _validate_url
from aegis.memory.store import LocalStore
from aegis.mcp.client import McpHttpAuthError, McpStdioClient, McpStreamableHttpClient, McpToolCallResult
from aegis.security.context_firewall import ContextFirewall
from aegis.security.policy_engine import PolicyDecisionType, PolicyEngine, PolicyRequest
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import RiskLevel, Sensitivity, TrustClass, now_utc


class McpRegistry:
    def __init__(self, store: LocalStore, audit_logger: AuditLogger, secrets_broker: SecretsBroker | None = None) -> None:
        self.store = store
        self.audit_logger = audit_logger
        self.secrets_broker = secrets_broker or SecretsBroker()

    def register_server(
        self,
        *,
        name: str,
        command: str,
        allowed_tools: tuple[str, ...],
        transport: str = "stdio",
        enabled: bool = False,
        approval_required: bool = True,
        metadata: dict[str, Any] | None = None,
        network_allowlist: tuple[str, ...] = (),
        auth_token_secret: str | None = None,
    ) -> dict[str, Any]:
        normalized_transport = _normalize_transport(transport)
        if auth_token_secret and normalized_transport != "streamable_http":
            raise ValueError("brokered bearer-token auth is only supported for Streamable HTTP MCP servers")
        if normalized_transport == "streamable_http":
            _parse_mcp_http_endpoint(
                command,
                network_allowlist=network_allowlist,
                enforce_allowlist=bool(network_allowlist),
                verify_network=False,
            )
        row = {
            "id": str(uuid4()),
            "name": name,
            "command": command,
            "allowed_tools": list(allowed_tools),
            "enabled": enabled,
            "approval_required": approval_required,
            "created_at": now_utc(),
            "updated_at": now_utc(),
            "metadata": _server_metadata(metadata, transport=normalized_transport, auth_token_secret=auth_token_secret),
        }
        self.store.insert_mcp_server(row)
        self.audit_logger.append(
            "mcp.server_registered",
            {
                "id": row["id"],
                "name": name,
                "enabled": enabled,
                "approval_required": approval_required,
                "transport": normalized_transport,
                "auth": _auth_audit_summary(row["metadata"]),
            },
        )
        return row

    def discover_tools(
        self,
        *,
        command: str,
        allowed_executables: tuple[str, ...],
        transport: str = "stdio",
        network_allowlist: tuple[str, ...] = (),
        auth_token_secret: str | None = None,
    ) -> list[dict[str, Any]]:
        client, audit_target = _client_for_transport(
            command,
            transport=transport,
            allowed_executables=allowed_executables,
            network_allowlist=network_allowlist,
            secrets_broker=self.secrets_broker,
            auth_token_secret=auth_token_secret,
            requester="mcp:discovery",
        )
        raw_tools = client.list_tools()
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
                **audit_target,
                "tool_count": len(tools),
                "tool_names": [redact({"name": tool["name"]})["name"] for tool in tools[:50]],
            },
        )
        return tools

    def discover_capabilities(
        self,
        *,
        command: str,
        allowed_executables: tuple[str, ...],
        transport: str = "stdio",
        network_allowlist: tuple[str, ...] = (),
        auth_token_secret: str | None = None,
    ) -> dict[str, Any]:
        client, audit_target = _client_for_transport(
            command,
            transport=transport,
            allowed_executables=allowed_executables,
            network_allowlist=network_allowlist,
            secrets_broker=self.secrets_broker,
            auth_token_secret=auth_token_secret,
            requester="mcp:discovery",
        )
        capabilities = client.capabilities()
        self.audit_logger.append(
            "mcp.capabilities_discovered",
            {**audit_target, "capabilities": sorted(str(key) for key in capabilities)},
        )
        return capabilities

    def register_discovered_server(
        self,
        *,
        name: str,
        command: str,
        allowed_executables: tuple[str, ...],
        transport: str = "stdio",
        network_allowlist: tuple[str, ...] = (),
        auth_token_secret: str | None = None,
        include_tools: tuple[str, ...] = (),
        exclude_tools: tuple[str, ...] = (),
        include_resources: bool = True,
        include_prompts: bool = True,
        enabled: bool = False,
        approval_required: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_transport = _normalize_transport(transport)
        capabilities = self.discover_capabilities(
            command=command,
            allowed_executables=allowed_executables,
            transport=normalized_transport,
            network_allowlist=network_allowlist,
            auth_token_secret=auth_token_secret,
        )
        discovered = (
            self.discover_tools(
                command=command,
                allowed_executables=allowed_executables,
                transport=normalized_transport,
                network_allowlist=network_allowlist,
                auth_token_secret=auth_token_secret,
            )
            if "tools" in capabilities or not capabilities
            else []
        )
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
        utility_tools = _utility_virtual_tools(
            server_name=name,
            capabilities=capabilities,
            native_tool_names={str(tool["name"]) for tool in selected},
            include_resources=include_resources,
            include_prompts=include_prompts,
        )
        if not selected and not utility_tools:
            raise ValueError("MCP discovery produced no allowlisted tools")
        discovery_metadata = {
            "discovered": True,
            "transport": normalized_transport,
            "tool_count": len(discovered),
            "selected_tool_count": len(selected),
            "capabilities": sorted(str(key) for key in capabilities),
            "utility_tool_count": len(utility_tools),
            "virtual_tools": [
                {
                    "name": tool["name"],
                    "virtual_name": mcp_virtual_tool_name(name, tool["name"]),
                    "description": redact(tool.get("description", "")),
                    "input_schema": tool.get("input_schema", {}),
                }
                for tool in selected
            ]
            + utility_tools,
        }
        return self.register_server(
            name=name,
            command=command,
            allowed_tools=tuple(str(tool["name"]) for tool in selected) + tuple(str(tool["name"]) for tool in utility_tools),
            transport=normalized_transport,
            enabled=enabled,
            approval_required=approval_required,
            metadata={**(metadata or {}), "discovery": discovery_metadata},
            network_allowlist=network_allowlist,
            auth_token_secret=auth_token_secret,
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

    def configure_auth_token(self, server: str, *, token_secret: str) -> dict[str, Any]:
        row = self.get_server(server)
        if str(row.get("metadata", {}).get("transport") or "stdio") != "streamable_http":
            raise ValueError("brokered bearer-token auth is only supported for Streamable HTTP MCP servers")
        metadata = _server_metadata(row.get("metadata", {}), transport=str(row.get("metadata", {}).get("transport") or "stdio"), auth_token_secret=token_secret)
        updated = {**row, "metadata": metadata}
        self.store.insert_mcp_server(updated)
        self.audit_logger.append(
            "mcp.auth_configured",
            {"id": row["id"], "name": row["name"], "transport": metadata["transport"], "auth": _auth_audit_summary(metadata)},
        )
        return self.get_server(row["id"])

    def configure_oauth_authorization(
        self,
        server: str,
        *,
        resource_metadata_url: str | None = None,
        authorization_server: str | None = None,
        token_secret: str | None = None,
        scopes: tuple[str, ...] = (),
        network_allowlist: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        row = self.get_server(server)
        metadata = row.get("metadata", {}) if isinstance(row.get("metadata", {}), dict) else {}
        if str(metadata.get("transport") or "stdio") != "streamable_http":
            raise ValueError("MCP OAuth authorization is only supported for Streamable HTTP MCP servers")
        oauth = metadata.get("oauth", {}) if isinstance(metadata.get("oauth", {}), dict) else {}
        challenge = metadata.get("last_http_auth_challenge", {}) if isinstance(metadata.get("last_http_auth_challenge", {}), dict) else {}
        challenge_params = challenge.get("parameters", {}) if isinstance(challenge.get("parameters", {}), dict) else {}
        resource_url = (resource_metadata_url or str(oauth.get("resource_metadata_url") or "") or str(challenge_params.get("resource_metadata") or "")).strip()
        if resource_url:
            resource_url = _validated_oauth_metadata_url(
                resource_url,
                network_allowlist=network_allowlist,
                enforce_allowlist=bool(network_allowlist),
            )
        auth_server = (authorization_server or str(oauth.get("authorization_server") or "")).strip()
        if auth_server:
            auth_server = _validated_oauth_metadata_url(
                auth_server,
                network_allowlist=network_allowlist,
                enforce_allowlist=bool(network_allowlist),
            )
        auth = metadata.get("auth", {}) if isinstance(metadata.get("auth", {}), dict) else {}
        requested_scopes = _safe_oauth_scopes(scopes)
        if not requested_scopes and isinstance(oauth.get("requested_scopes", []), list):
            requested_scopes = _safe_oauth_scopes(tuple(str(scope) for scope in oauth.get("requested_scopes", [])))
        token_secret_configured = bool(token_secret or auth.get("token_secret"))
        updated_oauth = {
            **oauth,
            "type": "oauth2_protected_resource",
            "status": "oauth_bearer_ready" if token_secret_configured else "oauth_metadata_ready",
            "resource_metadata_url": resource_url,
            "authorization_server": auth_server,
            "requested_scopes": requested_scopes,
            "token_secret_configured": token_secret_configured,
            "raw_tokens_captured": False,
            "raw_browser_cookie_import": False,
            "updated_at": now_utc(),
        }
        updated_metadata = {**metadata, "oauth": updated_oauth}
        if token_secret:
            updated_metadata["auth"] = {
                "type": "oauth_bearer_token",
                "token_secret": token_secret,
                "source": "brokered_local_secret",
                "oauth_protected_resource": True,
                "raw_secret_values_stored_in_registry": False,
            }
        updated = {**row, "metadata": updated_metadata}
        self.store.insert_mcp_server(updated)
        self.audit_logger.append(
            "mcp.oauth_configured",
            {
                "id": row["id"],
                "name": row["name"],
                "transport": updated_metadata["transport"],
                "oauth": _oauth_audit_summary(updated_metadata),
                "auth": _auth_audit_summary(updated_metadata),
            },
        )
        return self.get_server(row["id"])

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
        network_allowlist: tuple[str, ...] = (),
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
        tool_metadata = _metadata_virtual_tools(row.get("metadata", {})).get(tool, {})
        client, audit_target = _client_for_row(
            row,
            allowed_executables=allowed_executables,
            network_allowlist=network_allowlist,
            secrets_broker=self.secrets_broker,
        )
        try:
            result = _call_mcp_utility(client, str(tool_metadata.get("utility")), arguments) if tool_metadata.get("utility") else client.call_tool(tool, arguments)
        except McpHttpAuthError as exc:
            self._record_http_auth_challenge(row, exc.challenge)
            self.audit_logger.append(
                "mcp.http_auth_required",
                {"server": row["name"], "tool": tool, **audit_target, **exc.to_dict()},
                task_id=task_id,
            )
            raise
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
            {"server": row["name"], "tool": tool, **audit_target, "argument_keys": sorted(arguments), "result_keys": sorted(result)},
            task_id=task_id,
        )
        return call

    def _record_http_auth_challenge(self, row: dict[str, Any], challenge: dict[str, Any]) -> None:
        metadata = row.get("metadata", {}) if isinstance(row.get("metadata", {}), dict) else {}
        sanitized_challenge = _sanitize_http_auth_challenge(challenge)
        oauth = metadata.get("oauth", {}) if isinstance(metadata.get("oauth", {}), dict) else {}
        params = sanitized_challenge.get("parameters", {}) if isinstance(sanitized_challenge.get("parameters", {}), dict) else {}
        resource_metadata_url = str(params.get("resource_metadata") or "").strip()
        if resource_metadata_url:
            oauth = {
                **oauth,
                "type": "oauth2_protected_resource",
                "status": "oauth_metadata_required",
                "resource_metadata_url": resource_metadata_url,
                "raw_tokens_captured": False,
                "raw_browser_cookie_import": False,
                "updated_at": now_utc(),
            }
        updated = {
            **row,
            "metadata": {
                **metadata,
                "last_http_auth_challenge": {**sanitized_challenge, "recorded_at": now_utc()},
                "oauth": oauth,
            },
        }
        self.store.insert_mcp_server(updated)


def _client_for_row(
    row: dict[str, Any],
    *,
    allowed_executables: tuple[str, ...],
    network_allowlist: tuple[str, ...],
    secrets_broker: SecretsBroker,
) -> tuple[Any, dict[str, Any]]:
    metadata = row.get("metadata", {}) if isinstance(row.get("metadata", {}), dict) else {}
    auth = metadata.get("auth", {}) if isinstance(metadata.get("auth", {}), dict) else {}
    return _client_for_transport(
        str(row["command"]),
        transport=str(metadata.get("transport") or "stdio"),
        allowed_executables=allowed_executables,
        network_allowlist=network_allowlist,
        secrets_broker=secrets_broker,
        auth_token_secret=str(auth.get("token_secret") or "") or None,
        requester=f"mcp:{row['id']}",
    )


def _client_for_transport(
    command: str,
    *,
    transport: str,
    allowed_executables: tuple[str, ...],
    network_allowlist: tuple[str, ...],
    secrets_broker: SecretsBroker,
    auth_token_secret: str | None,
    requester: str,
) -> tuple[Any, dict[str, Any]]:
    normalized = _normalize_transport(transport)
    if normalized == "stdio":
        argv = _parse_allowed_command(command, allowed_executables)
        return McpStdioClient(argv), {"transport": "stdio", "executable": Path(argv[0]).name}
    endpoint = _parse_mcp_http_endpoint(command, network_allowlist=network_allowlist, enforce_allowlist=True, verify_network=True)
    domain = urlparse(endpoint).hostname or ""
    bearer_token = _resolve_mcp_bearer_token(secrets_broker, auth_token_secret=auth_token_secret, requester=requester)
    return (
        McpStreamableHttpClient(endpoint, authorization_bearer=bearer_token),
        {"transport": "streamable_http", "domain": domain, "auth": "brokered_bearer" if auth_token_secret else "none"},
    )


def _server_metadata(metadata: dict[str, Any] | None, *, transport: str, auth_token_secret: str | None) -> dict[str, Any]:
    merged = {**(metadata or {}), "transport": transport}
    if auth_token_secret:
        merged["auth"] = {
            "type": "bearer_token",
            "token_secret": auth_token_secret,
            "source": "brokered_local_secret",
            "raw_secret_values_stored_in_registry": False,
        }
    return merged


def _auth_audit_summary(metadata: dict[str, Any]) -> dict[str, Any]:
    auth = metadata.get("auth", {}) if isinstance(metadata, dict) else {}
    if not isinstance(auth, dict) or not auth.get("type"):
        return {"type": "none", "token_secret_configured": False}
    return {"type": str(auth.get("type")), "source": str(auth.get("source") or ""), "token_secret_configured": bool(auth.get("token_secret"))}


def _oauth_audit_summary(metadata: dict[str, Any]) -> dict[str, Any]:
    oauth = metadata.get("oauth", {}) if isinstance(metadata, dict) else {}
    if not isinstance(oauth, dict) or not oauth.get("type"):
        return {"type": "none", "token_secret_configured": False}
    return {
        "type": str(oauth.get("type")),
        "status": str(oauth.get("status") or ""),
        "resource_metadata_url_configured": bool(oauth.get("resource_metadata_url")),
        "authorization_server_configured": bool(oauth.get("authorization_server")),
        "scope_count": len(oauth.get("requested_scopes", [])) if isinstance(oauth.get("requested_scopes", []), list) else 0,
        "token_secret_configured": bool(oauth.get("token_secret_configured")),
        "raw_tokens_captured": False,
    }


def _safe_oauth_scopes(scopes: tuple[str, ...]) -> list[str]:
    safe: list[str] = []
    for scope in scopes:
        normalized = re.sub(r"[^a-zA-Z0-9:._/\-]+", "", str(scope).strip())[:120]
        if normalized and normalized not in safe:
            safe.append(normalized)
    return safe[:30]


def _sanitize_http_auth_challenge(challenge: dict[str, Any]) -> dict[str, Any]:
    parameters = challenge.get("parameters", {}) if isinstance(challenge.get("parameters", {}), dict) else {}
    sanitized_parameters = redact({str(key): str(value)[:240] for key, value in parameters.items()})
    if not isinstance(sanitized_parameters, dict):
        sanitized_parameters = {}
    return {
        "present": bool(challenge.get("present", True)),
        "scheme": re.sub(r"[^A-Za-z0-9_.-]+", "", str(challenge.get("scheme") or "unknown"))[:40] or "unknown",
        "parameters": sanitized_parameters,
        "raw_header_included": False,
    }


def _resolve_mcp_bearer_token(secrets_broker: SecretsBroker, *, auth_token_secret: str | None, requester: str) -> str | None:
    if not auth_token_secret:
        return None
    handle = secrets_broker.request_handle(
        name=auth_token_secret,
        requester=requester,
        reason="authorize Streamable HTTP MCP request",
        scopes=("mcp:streamable_http",),
    )
    return secrets_broker.resolve_for_authorized_tool(handle, requester=requester)


def _normalize_transport(transport: str) -> str:
    normalized = transport.strip().lower().replace("-", "_")
    if normalized in {"", "stdio"}:
        return "stdio"
    if normalized in {"http", "streamable_http", "streamablehttp"}:
        return "streamable_http"
    raise ValueError(f"unsupported MCP transport {transport!r}")


def _parse_mcp_http_endpoint(
    endpoint_url: str,
    *,
    network_allowlist: tuple[str, ...],
    enforce_allowlist: bool,
    verify_network: bool,
) -> str:
    endpoint = endpoint_url.strip()
    parsed = urlparse(endpoint)
    validation_error = _validate_url(parsed)
    if validation_error:
        raise ValueError(validation_error)
    domain = parsed.hostname or ""
    loopback = _is_loopback_host(domain)
    if parsed.scheme != "https" and not loopback:
        raise PermissionError("MCP Streamable HTTP endpoints must use HTTPS unless they target explicit loopback hosts")
    if not enforce_allowlist:
        return endpoint
    if not _allowed_domain(domain, network_allowlist):
        raise PermissionError(f"MCP HTTP endpoint domain {domain!r} is not allowlisted")
    if verify_network and not loopback:
        private_error = _private_network_error(domain)
        if private_error:
            raise PermissionError(private_error.replace("live HTTP reads", "MCP Streamable HTTP"))
    return endpoint


def _validated_oauth_metadata_url(
    endpoint_url: str,
    *,
    network_allowlist: tuple[str, ...],
    enforce_allowlist: bool,
) -> str:
    endpoint = _parse_mcp_http_endpoint(
        endpoint_url,
        network_allowlist=network_allowlist,
        enforce_allowlist=enforce_allowlist,
        verify_network=True,
    )
    parsed = urlparse(endpoint)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def _allowed_domain(domain: str, allowlist: tuple[str, ...]) -> bool:
    return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowlist)


def _is_loopback_host(hostname: str) -> bool:
    lowered = hostname.lower()
    if lowered == "localhost":
        return True
    try:
        import ipaddress

        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def _parse_allowed_command(command: str, allowed_executables: tuple[str, ...]) -> list[str]:
    argv = shlex.split(command)
    if not argv:
        raise ValueError("empty MCP server command")
    executable = Path(argv[0]).name
    if not allowed_executables:
        raise PermissionError("no MCP executable allowlist is configured")
    if executable not in allowed_executables:
        raise PermissionError(f"MCP server command {executable!r} is not allowlisted")
    _validate_mcp_interpreter_args(executable, argv)
    return argv


def _validate_mcp_interpreter_args(executable: str, argv: list[str]) -> None:
    if executable not in {"python", "python3"}:
        return
    if len(argv) < 2:
        raise PermissionError("MCP Python server command must name a script file")
    script = argv[1]
    if script == "-" or script.startswith("-"):
        raise PermissionError("MCP Python server command must use a script path, not interpreter flags")
    if Path(script).suffix != ".py":
        raise PermissionError("MCP Python server command must use a .py script path")


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


def _utility_virtual_tools(
    *,
    server_name: str,
    capabilities: dict[str, Any],
    native_tool_names: set[str],
    include_resources: bool,
    include_prompts: bool,
) -> list[dict[str, Any]]:
    utility_tools: list[dict[str, Any]] = []
    if include_resources and "resources" in capabilities:
        utility_tools.extend(
            [
                _utility_tool_metadata(
                    server_name=server_name,
                    name="list_resources",
                    utility="list_resources",
                    description="List resources exposed by this MCP server.",
                    input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                ),
                _utility_tool_metadata(
                    server_name=server_name,
                    name="read_resource",
                    utility="read_resource",
                    description="Read one resource exposed by this MCP server by URI.",
                    input_schema={
                        "type": "object",
                        "properties": {"uri": {"type": "string"}},
                        "required": ["uri"],
                        "additionalProperties": False,
                    },
                ),
            ]
        )
    if include_prompts and "prompts" in capabilities:
        utility_tools.extend(
            [
                _utility_tool_metadata(
                    server_name=server_name,
                    name="list_prompts",
                    utility="list_prompts",
                    description="List prompts exposed by this MCP server.",
                    input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                ),
                _utility_tool_metadata(
                    server_name=server_name,
                    name="get_prompt",
                    utility="get_prompt",
                    description="Get one prompt exposed by this MCP server.",
                    input_schema={
                        "type": "object",
                        "properties": {"name": {"type": "string"}, "arguments": {"type": "object"}},
                        "required": ["name"],
                        "additionalProperties": False,
                    },
                ),
            ]
        )
    return [tool for tool in utility_tools if tool["name"] not in native_tool_names]


def _utility_tool_metadata(*, server_name: str, name: str, utility: str, description: str, input_schema: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "virtual_name": mcp_virtual_tool_name(server_name, name),
        "description": description,
        "input_schema": input_schema,
        "utility": utility,
    }


def _call_mcp_utility(client: Any, utility: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if utility == "list_resources":
        return client.list_resources()
    if utility == "read_resource":
        return client.read_resource(str(arguments["uri"]))
    if utility == "list_prompts":
        return client.list_prompts()
    if utility == "get_prompt":
        prompt_arguments = arguments.get("arguments", {})
        if not isinstance(prompt_arguments, dict):
            raise ValueError("MCP get_prompt arguments must be an object")
        return client.get_prompt(str(arguments["name"]), prompt_arguments)
    raise ValueError(f"unknown MCP utility wrapper {utility!r}")
