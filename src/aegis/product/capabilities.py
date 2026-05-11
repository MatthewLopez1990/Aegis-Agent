"""Product capability summaries derived from live runtime state."""

from __future__ import annotations

from typing import Any


def build_product_dashboard(orchestrator: Any) -> dict[str, Any]:
    """Return a product-facing dashboard without exposing raw secrets or payloads."""

    connectors = orchestrator.connectors.status()
    channels = orchestrator.channels.list_channels()
    tools = orchestrator.tool_catalog.list()
    backends = orchestrator.execution_backends.list()
    providers = orchestrator.models.list_providers()
    schedules = orchestrator.schedules.list_schedules()
    sessions = orchestrator.sessions.list_sessions()
    boards = orchestrator.kanban.list_boards()
    approvals = orchestrator.approvals.list()
    pending_approvals = [_decode_pending_approval(orchestrator, approval) for approval in approvals if approval["status"] == "pending"]
    task_rows = orchestrator.store.list_tasks(limit=12)
    tasks = [_decode_task(orchestrator, row) for row in task_rows]
    audit_chain_ok = orchestrator.audit_logger.verify_chain()

    high_risk_tools = [tool for tool in tools if tool["risk_level"] in {"high", "critical"}]
    approval_tools = [tool for tool in tools if tool["approval_required"]]
    placeholder_tools = [tool for tool in tools if str(tool.get("implementation_status", "")).startswith(("placeholder", "mock"))]
    backend_gate_tools = [tool for tool in tools if tool.get("implementation_status") == "backend_gate"]
    implementation_readiness = _tool_implementation_readiness(tools)
    limited_or_facade_tools = sum(item["count"] for item in implementation_readiness if item["state"] != "ready")
    configured_providers = [provider for provider in providers if provider["auth_configured"] or provider["local"]]
    live_connector_adapters = _live_connector_adapters(connectors, orchestrator.config)
    session_bound_recent_tasks = [task for task in task_rows if task.get("session_id")]
    competitive_targets = _competitive_targets()

    return {
        "product": {
            "name": "Aegis Agent",
            "positioning": "Local-first governed agent runtime",
            "release_stage": "product_foundation",
            "security_posture": "strict_by_default",
        },
        "runtime": {
            "audit_chain_ok": audit_chain_ok,
            "connectors": len(connectors),
            "channels": len(channels),
            "tools": len(tools),
            "high_risk_tools": len(high_risk_tools),
            "approval_gated_tools": len(approval_tools),
            "placeholder_or_mock_tools": len(placeholder_tools),
            "backend_gate_tools": len(backend_gate_tools),
            "limited_or_facade_tools": limited_or_facade_tools,
            "execution_backends": len(backends),
            "model_providers": len(providers),
            "configured_or_local_providers": len(configured_providers),
            "sessions": len(sessions),
            "session_bound_recent_tasks": len(session_bound_recent_tasks),
            "schedules": len(schedules),
            "boards": len(boards),
            "recent_tasks": len(tasks),
            "pending_approvals": len(pending_approvals),
        },
        "security_controls": [
            {
                "name": "Context firewall",
                "state": "enforced",
                "detail": "Connector, channel, file, web, tool, and skill output is labeled as untrusted data before model use.",
            },
            {
                "name": "Approval gate",
                "state": "enforced",
                "detail": f"{len(approval_tools)} tool surfaces require human approval before high-impact actions.",
            },
            {
                "name": "Secret broker",
                "state": "enforced",
                "detail": "Model and connector credentials are represented by brokered handles instead of raw values.",
            },
            {
                "name": "Audit receipts",
                "state": "healthy" if audit_chain_ok else "degraded",
                "detail": "Append-only receipts are hash-chain verified and redact sensitive fields.",
            },
            {
                "name": "Safe defaults",
                "state": "enforced",
                "detail": "Live writes, sends, shell execution, MCP calls, generated skills, and risky backends are approval-gated.",
            },
        ],
        "capability_groups": [
            {
                "name": "Gateway and channels",
                "state": "secure_interface_ready",
                "coverage": f"{len(channels)} channel adapters",
                "detail": "Inbound messages are normalized and tainted; outbound rendering remains pending approval.",
            },
            {
                "name": "Agent tools",
                "state": "secure_interface_ready",
                "coverage": f"{len(tools)} governed tool definitions",
                "detail": "Browser, web, files, shell, media, voice, documents, code, subagent, research, and MCP tools are policy-visible.",
            },
            {
                "name": "Models",
                "state": "route_ready",
                "coverage": f"{len(providers)} providers",
                "detail": "Cloud, local, OpenRouter, Ollama, LM Studio, and custom endpoints share aliases, fallbacks, auth state, and usage tracking.",
            },
            {
                "name": "Memory and skills",
                "state": "governed",
                "coverage": "Provenance, sensitivity, approval, tests, evals, rollback, and sandbox metadata",
                "detail": "Generated procedures stay disabled or approval-required until reviewed.",
            },
            {
                "name": "Scheduling and orchestration",
                "state": "durable",
                "coverage": f"{len(schedules)} schedules, {len(boards)} work boards",
                "detail": "Schedules start paused pending approval; Kanban cards provide a durable multi-agent coordination surface.",
            },
            {
                "name": "Session continuity",
                "state": "durable",
                "coverage": f"{len(sessions)} sessions, {len(session_bound_recent_tasks)} linked recent tasks",
                "detail": "Transcripts, task status, run events, approvals, and resume outcomes stay bound to the originating session.",
            },
            {
                "name": "Execution backends",
                "state": "policy_visible",
                "coverage": f"{len(backends)} backend definitions",
                "detail": "Local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox are represented for policy decisions.",
            },
        ],
        "competitive_targets": competitive_targets,
        "live_gap_backlog": _live_gap_backlog(competitive_targets, implementation_readiness, configured_providers, tools, live_connector_adapters, backends),
        "implementation_readiness": implementation_readiness,
        "recent_tasks": tasks,
        "pending_approvals": pending_approvals[:12],
    }


def _competitive_targets() -> list[dict[str, Any]]:
    return [
        {
            "platform": "Hermes Agent",
            "covered": [
                "TUI",
                "model routing",
                "gateway surface",
                "memory",
                "skills",
                "scheduler",
                "work boards",
                "subagent delegation surface",
                "terminal backends",
                "research tool surface",
                "session resume continuity",
            ],
            "security_delta": "Aegis treats all external outputs as tainted data and requires approval for high-impact actions by default.",
            "live_gap": "Provider invocation and real channel credentials still need per-service live connectors before unrestricted production rollout.",
        },
        {
            "platform": "OpenClaw",
            "covered": [
                "web control UI",
                "gateway channels",
                "browser tool surface",
                "media tool surface",
                "plugins and skills",
                "multi-agent routing primitives",
                "schedules",
                "diagnostic panels",
                "migration inspection",
                "session-bound run visibility",
            ],
            "security_delta": "Aegis defaults to mock or dry-run mode for broad-access capabilities until credentials, scopes, rollback, and approvals are explicit.",
            "live_gap": "Mobile nodes, native desktop wrappers, and live third-party channel implementations remain staged behind secure adapter work.",
        },
    ]


def _live_gap_backlog(
    competitive_targets: list[dict[str, Any]],
    readiness: list[dict[str, Any]],
    configured_providers: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    live_connector_adapters: list[dict[str, Any]],
    backends: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    readiness_by_state = {row["state"]: row for row in readiness}
    mock_write_tools = [
        str(tool.get("name", ""))
        for tool in tools
        if str(tool.get("implementation_status", "")) in {"allowlisted_live_read_write_or_mock_connector", "allowlisted_live_write_or_mock_connector"}
    ]
    live_read_connector_tools = [
        str(tool.get("name", ""))
        for tool in tools
        if str(tool.get("implementation_status", "")) == "allowlisted_live_read_or_mock_connector"
    ]
    facade_tools = readiness_by_state.get("facade", {}).get("sample_tools", [])
    backend_tools = readiness_by_state.get("backend_gate", {}).get("sample_tools", [])
    implemented_backends = _implemented_backend_adapters(backends)
    provider_channel_status = "live_connectors_partially_live" if live_connector_adapters else "live_connector_work_required"
    provider_channel_detail = (
        "Some provider or channel live adapters are configured; continue promoting remaining service integrations through scoped, allowlisted, approval-gated adapters."
        if live_connector_adapters
        else "Promote write-capable service and channel integrations from mock-default mode into configured, scoped, allowlisted, approval-gated live adapters."
    )
    return [
        {
            "area": "provider_and_channel_live_connectors",
            "platforms": [target["platform"] for target in competitive_targets],
            "status": provider_channel_status,
            "detail": provider_channel_detail,
            "sample_tools": mock_write_tools[:8],
            "live_read_surfaces": live_read_connector_tools[:8],
            "implemented_live_adapters": live_connector_adapters,
            "next_steps": [
                "Add per-provider credential handles and domain allowlists.",
                "Keep live writes approval-gated with redacted receipts.",
                "Promote each adapter only after mock, denied, approved, and audit-path tests pass.",
            ],
            "required_controls": ["human_approval", "secret_broker", "network_allowlist", "audit_receipts"],
            "verification_gates": ["mock_fallback", "denied_write", "approved_write", "receipt_redaction"],
            "evaluation_scenarios": ["connector_abuse.write_without_scope", "live_connector_receipts.redacted_write_summary"],
            "configured_provider_count": len(configured_providers),
        },
        {
            "area": "browser_and_media_depth",
            "platforms": ["OpenClaw"],
            "status": "facade_hardening_required",
            "detail": "Sanitized browser rendering is available for stored HTTP-content sessions; real page automation and media execution still require stronger sandboxing.",
            "sample_tools": facade_tools[:8],
            "next_steps": [
                "Extend rendering toward real browser automation only after network, cookie, and JavaScript boundaries are enforceable.",
                "Introduce a sandboxed media worker with no ambient workspace access.",
                "Gate any page mutation, recording, or generated media write behind approval.",
            ],
            "required_controls": ["sandbox_isolation", "taint_preservation", "artifact_hashing", "human_approval"],
            "verification_gates": ["unsupported_selector_truthfulness", "artifact_hash_stability", "approval_required_mutation", "no_raw_secret_capture"],
            "evaluation_scenarios": ["artifact_integrity.browser_media_receipts"],
            "configured_provider_count": len(configured_providers),
        },
        {
            "area": "remote_backend_activation",
            "platforms": ["Hermes Agent", "OpenClaw"],
            "status": "remote_backends_partially_live" if implemented_backends else "backend_adapter_required",
            "detail": (
                "Some nonlocal execution adapters are enabled with receipts; hosted sandbox backends still require provider-specific activation work."
                if implemented_backends
                else "Enable backend-gated execution paths only after sandbox credentials, scope limits, rollback, and receipts are implemented."
            ),
            "sample_tools": backend_tools[:8],
            "implemented_backend_adapters": implemented_backends,
            "next_steps": [
                "Add backend-specific auth checks through brokered handles.",
                "Enforce workspace, network, resource, and rollback limits before dispatch.",
                "Record activation, execution, and cleanup receipts for every remote run.",
            ],
            "required_controls": ["brokered_backend_auth", "scope_limits", "resource_limits", "rollback_receipts"],
            "verification_gates": ["disabled_backend_denial", "approved_activation", "cleanup_receipt", "scope_escape_rejection"],
            "evaluation_scenarios": ["backend_activation.remote_execution_disabled"],
            "configured_provider_count": len(configured_providers),
        },
    ]


def _live_connector_adapters(connectors: list[dict[str, Any]], config: Any) -> list[dict[str, Any]]:
    adapters: list[dict[str, Any]] = []
    for connector in connectors:
        live_flags = sorted(key for key, value in connector.items() if key.startswith("live_") and value is True)
        if live_flags:
            adapters.append(
                {
                    "kind": "connector",
                    "name": str(connector.get("name", "unknown")),
                    "status": "live_enabled",
                    "live_flags": live_flags,
                    "raw_secret_values_included": False,
                }
            )
    if getattr(config.webhook, "enabled", False) and getattr(config.webhook, "outbound_enabled", False):
        adapters.append({"kind": "channel", "name": "webhook", "status": "live_outbound_enabled", "raw_secret_values_included": False})
    if getattr(config.email, "outbound_enabled", False):
        adapters.append({"kind": "channel", "name": "email", "status": "live_outbound_enabled", "raw_secret_values_included": False})
    if getattr(config.chat_webhook, "outbound_enabled", False):
        adapters.append({"kind": "channel", "name": "chat_webhook", "status": "live_outbound_enabled", "raw_secret_values_included": False})
    return adapters


def _implemented_backend_adapters(backends: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": str(backend.get("name", "")),
            "status": "enabled",
            "local": bool(backend.get("local")),
            "raw_secret_values_included": False,
        }
        for backend in backends
        if backend.get("enabled") and backend.get("name") != "local"
    ]


def _tool_implementation_readiness(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = {
        "ready": {
            "label": "Ready local/live paths",
            "detail": "Concrete local execution or explicitly configured live-capable paths.",
            "statuses": set(),
            "tools": [],
        },
        "facade": {
            "label": "Local facades and previews",
            "detail": "Safe local substitutes such as metadata extraction, deterministic media artifacts, memory/vector facades, or virtual browser state.",
            "statuses": set(),
            "tools": [],
        },
        "mock_or_placeholder": {
            "label": "Mock or placeholder live integrations",
            "detail": "Interfaces that can run safely now but still require provider configuration for full live parity.",
            "statuses": set(),
            "tools": [],
        },
        "backend_gate": {
            "label": "Backend-gated adapters",
            "detail": "Policy-visible tools that remain blocked until a sandbox or remote backend adapter is configured.",
            "statuses": set(),
            "tools": [],
        },
    }
    for tool in tools:
        status = str(tool.get("implementation_status") or "local")
        if status == "backend_gate":
            group = groups["backend_gate"]
        elif status == "local":
            group = groups["ready"]
        elif "placeholder" in status or "mock" in status:
            group = groups["mock_or_placeholder"]
        elif status.startswith("local_") or status in {"memory_facade", "local_sandbox"}:
            group = groups["facade"]
        else:
            group = groups["ready"]
        group["statuses"].add(status)
        group["tools"].append(str(tool.get("name", "")))
    return [
        {
            "state": state,
            "label": group["label"],
            "count": len(group["tools"]),
            "statuses": sorted(group["statuses"]),
            "sample_tools": group["tools"][:8],
            "detail": group["detail"],
        }
        for state, group in groups.items()
    ]


def _decode_task(orchestrator: Any, row: dict[str, Any]) -> dict[str, Any]:
    task = {
        "id": row["id"],
        "user_request": row["user_request"],
        "interpretation": row["interpretation"],
        "status": row["status"],
        "risk_level": row["risk_level"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "action_hints": _task_action_hints(row.get("id"), row.get("session_id"), status=row.get("status")),
    }
    if row.get("session_id"):
        task["session_id"] = row["session_id"]
        session = _session_summary(orchestrator, str(row["session_id"]))
        if session:
            task["session"] = session
    return task


def _task_action_hints(task_id: Any, session_id: Any, *, status: Any) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    task_id_text = str(task_id) if task_id else ""
    if session_id:
        session_id_text = str(session_id)
        hints.extend(
            [
                {"label": "Show Session", "command": f"session show {session_id_text}", "action": "session_show", "session_id": session_id_text},
                {"label": "Session History", "command": f"session history {session_id_text}", "action": "session_history", "session_id": session_id_text},
            ]
        )
    if task_id_text and status in {"waiting_approval", "paused"}:
        hints.append({"label": "Resume", "command": f"task resume {task_id_text}", "action": "task_resume", "task_id": task_id_text})
    return hints


def _decode_pending_approval(orchestrator: Any, approval: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(approval)
    decoded["session_id"] = None
    decoded["session"] = None
    decoded["action_hints"] = []
    task_id = decoded.get("task_id")
    if task_id:
        task = orchestrator.store.get_task(str(task_id))
        if task and task.get("session_id"):
            decoded["session_id"] = task["session_id"]
            decoded["session"] = _session_summary(orchestrator, str(task["session_id"]))
        decoded["action_hints"] = _approval_action_hints(decoded.get("session_id"), task_id=task_id, approval_status=decoded.get("status"))
        return decoded
    payload = decoded.get("payload")
    if isinstance(payload, dict):
        session_id = _approval_payload_session_id(payload)
        if session_id:
            decoded["session_id"] = session_id
            decoded["session"] = _session_summary(orchestrator, session_id)
    decoded["action_hints"] = _approval_action_hints(decoded.get("session_id"), task_id=task_id, approval_status=decoded.get("status"))
    return decoded


def _approval_action_hints(session_id: Any, *, task_id: Any, approval_status: Any) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    if session_id:
        session_id_text = str(session_id)
        hints.extend(
            [
                {"label": "Show Session", "command": f"session show {session_id_text}", "action": "session_show", "session_id": session_id_text},
                {"label": "Session History", "command": f"session history {session_id_text}", "action": "session_history", "session_id": session_id_text},
            ]
        )
    if approval_status == "approved" and task_id:
        task_id_text = str(task_id)
        hints.append({"label": "Resume", "command": f"task resume {task_id_text}", "action": "task_resume", "task_id": task_id_text})
    return hints


def _approval_payload_session_id(payload: dict[str, Any]) -> str | None:
    if isinstance(payload.get("session_id"), str):
        return payload["session_id"]
    params = payload.get("params")
    if isinstance(params, dict) and isinstance(params.get("session_id"), str):
        return params["session_id"]
    arguments = payload.get("arguments")
    if isinstance(arguments, dict) and isinstance(arguments.get("session_id"), str):
        return arguments["session_id"]
    return None


def _session_summary(orchestrator: Any, session_id: str) -> dict[str, Any] | None:
    session = orchestrator.store.get_session(session_id)
    if not session:
        return None
    return {
        "id": session["id"],
        "title": session["title"],
        "channel": session["channel"],
        "status": session["status"],
    }
