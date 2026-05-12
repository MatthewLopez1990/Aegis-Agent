"""Product capability summaries derived from live runtime state."""

from __future__ import annotations

from typing import Any

from aegis.connectors.base import live_connector_activation


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
    session_task_rows = _recent_session_task_rows(orchestrator, task_rows, sessions, limit=12)
    tasks = [_decode_task(orchestrator, row) for row in task_rows]
    session_tasks = [_decode_task(orchestrator, row) for row in session_task_rows]
    audit_chain_ok = orchestrator.audit_logger.verify_chain()

    high_risk_tools = [tool for tool in tools if tool["risk_level"] in {"high", "critical"}]
    approval_tools = [tool for tool in tools if tool["approval_required"]]
    placeholder_tools = [tool for tool in tools if str(tool.get("implementation_status", "")).startswith(("placeholder", "mock"))]
    backend_gate_tools = [tool for tool in tools if tool.get("implementation_status") == "backend_gate"]
    implementation_readiness = _tool_implementation_readiness(tools)
    limited_or_facade_tools = sum(item["count"] for item in implementation_readiness if item["state"] != "ready")
    configured_providers = [provider for provider in providers if provider["auth_configured"] or provider["local"]]
    model_auth_parity = orchestrator.models.auth_targets()
    live_connector_adapters = _live_connector_adapters(connectors, orchestrator.config)
    available_live_connector_adapters = _available_live_connector_adapters(connectors, orchestrator.config)
    competitive_targets = _competitive_targets()
    memory_readiness = _memory_readiness(orchestrator)
    self_improvement_readiness = _self_improvement_readiness(orchestrator)
    enterprise_readiness = _enterprise_readiness(memory_readiness, self_improvement_readiness)

    return {
        "product": {
            "name": "Aegis Agent",
            "positioning": "Local-first governed agent runtime",
            "release_stage": "product_foundation",
            "release_stage_detail": "Governed local foundation with enterprise-ready controls where health gates are clean, mock-default integrations where credentials are absent, and backend-gated execution where remote adapters require explicit enablement.",
            "readiness_states": ["enterprise_ready", "governed_local_ready", "mock_default", "backend_gated", "not_started"],
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
            "session_bound_recent_tasks": len(session_task_rows),
            "schedules": len(schedules),
            "boards": len(boards),
            "recent_tasks": len(tasks),
            "pending_approvals": len(pending_approvals),
            "memories": memory_readiness["memory_count"],
            "memory_health_score": memory_readiness["health_score"],
            "memory_review_recommendations": memory_readiness["recommendation_count"],
            "self_improvement_blockers": self_improvement_readiness["blocker_count"],
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
                "state": "route_ready" if model_auth_parity["status"] == "target_surface_ready" else "auth_parity_gap_tracked",
                "coverage": f"{len(providers)} providers, {model_auth_parity['target_provider_count']} auth targets tracked",
                "detail": "Cloud, local, OpenRouter, Ollama, LM Studio, and custom endpoints share aliases, fallbacks, auth state, usage tracking, and a visible provider-login parity ledger.",
            },
            {
                "name": "Memory",
                "state": memory_readiness["status"],
                "coverage": f"{memory_readiness['memory_count']} memories, score {memory_readiness['health_score']}, {memory_readiness['recommendation_count']} review recommendation(s)",
                "detail": "Memory health scores provenance, confirmation freshness, duplicate candidates, conflicts, recertification, and scoped recall without exposing raw secrets.",
            },
            {
                "name": "Self improvement",
                "state": self_improvement_readiness["status"],
                "coverage": f"{self_improvement_readiness['proposal_count']} proposals, {self_improvement_readiness['candidate_counts']['total']} candidates, {self_improvement_readiness['blocker_count']} blocker(s)",
                "detail": "Repair loops require proposal review, sandboxed candidates, candidate approval, workspace-scoped application, verification receipts, and learned procedural memory.",
            },
            {
                "name": "Skills",
                "state": "governed",
                "coverage": "Signed manifests, permissions, tests, evals, rollback, and sandbox metadata",
                "detail": "Generated procedures and high-risk skills stay disabled or approval-required until reviewed.",
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
                "coverage": f"{len(sessions)} sessions, {len(session_task_rows)} linked recent session tasks",
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
        "model_provider_auth_parity": model_auth_parity,
        "live_gap_backlog": _live_gap_backlog(
            competitive_targets,
            implementation_readiness,
            model_auth_parity,
            configured_providers,
            tools,
            live_connector_adapters,
            available_live_connector_adapters,
            backends,
        ),
        "implementation_readiness": implementation_readiness,
        "enterprise_readiness": enterprise_readiness,
        "memory_readiness": memory_readiness,
        "self_improvement_readiness": self_improvement_readiness,
        "recent_tasks": tasks,
        "recent_session_tasks": session_tasks,
        "pending_approvals": pending_approvals[:12],
    }


def _memory_readiness(orchestrator: Any) -> dict[str, Any]:
    report = orchestrator.memory.health_report(limit=20, log=False)
    return {
        "status": _dashboard_memory_status(report),
        "health_score": report["health_score"],
        "memory_count": report["memory_count"],
        "confirmed_count": report["confirmed_count"],
        "unconfirmed_count": report["unconfirmed_count"],
        "issue_counts": report["issue_counts"],
        "recommendation_count": report["recommendation_count"],
        "total_recommendations": report["total_recommendations"],
        "enterprise_flags": report["enterprise_flags"],
        "next_actions": report["next_actions"],
        "audit_event": "memory.health_reported",
        "raw_memory_content_included": False,
    }


def _dashboard_memory_status(report: dict[str, Any]) -> str:
    status = str(report.get("status") or "")
    if status == "enterprise_ready":
        return "enterprise_ready"
    if report.get("memory_count", 0) == 0:
        return "governed_local_ready"
    return status or "review_recommended"


def _self_improvement_readiness(orchestrator: Any) -> dict[str, Any]:
    readiness = orchestrator.repair_readiness_summary(limit=20)
    return {
        "status": "enterprise_ready" if readiness["ready"] else "blocked",
        "ready": readiness["ready"],
        "proposal_count": readiness["proposal_count"],
        "by_status": readiness["by_status"],
        "candidate_counts": readiness["candidate_counts"],
        "attempt_count": readiness["attempt_count"],
        "blocker_count": readiness["blocker_count"],
        "blockers": readiness["blockers"][:10],
        "next_actions": readiness["next_actions"][:5],
        "state_machine": [
            "failed_task",
            "proposal",
            "sandbox_plan",
            "candidate",
            "candidate_review",
            "apply_or_rollback",
            "verification",
            "learned_procedural_memory",
        ],
    }


def _enterprise_readiness(memory_readiness: dict[str, Any], self_improvement_readiness: dict[str, Any]) -> dict[str, Any]:
    surfaces = {
        "memory": memory_readiness["status"],
        "self_improvement": self_improvement_readiness["status"],
        "tui": "enterprise_ready",
        "connectors": "mock_default",
        "remote_backends": "backend_gated",
    }
    blocked = [name for name, status in surfaces.items() if status == "blocked"]
    return {
        "status": "blocked" if blocked else "governed_local_ready",
        "surfaces": surfaces,
        "blocked_surfaces": blocked,
        "operator_gates": ["approval_required_mutation", "memory_review", "candidate_review", "verification_receipts"],
    }


def _recent_session_task_rows(orchestrator: Any, task_rows: list[dict[str, Any]], sessions: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    rows_by_id = {str(row["id"]): row for row in task_rows if row.get("session_id")}
    for session in sessions:
        session_id = str(session.get("id") or "")
        if not session_id:
            continue
        for row in orchestrator.store.list_tasks(limit=3, session_id=session_id):
            rows_by_id.setdefault(str(row["id"]), row)
    return sorted(rows_by_id.values(), key=lambda row: str(row.get("created_at", "")), reverse=True)[:limit]


def _competitive_targets() -> list[dict[str, Any]]:
    return [
        {
            "platform": "Hermes Agent",
            "covered": [
                "TUI",
                "model routing",
                "provider auth parity ledger",
                "gateway surface",
                "memory",
                "skills",
                "scheduler",
                "work boards",
                "subagent delegation surface",
                "terminal backends",
                "research tool surface",
                "session resume continuity",
                "guarded remote-control readiness",
            ],
            "security_delta": "Aegis treats all external outputs as tainted data and requires approval for high-impact actions by default.",
            "live_gap": "API-key-ready Hermes providers are routable through the brokered model registry; remaining provider-native gaps are subscription, OAuth/device, and cloud-identity bridges such as Copilot, Nous Portal OAuth, Qwen OAuth, Bedrock, and Azure.",
            "target_requirements": [
                "provider_native_oauth_and_device_flows",
                "subscription_login_bridge",
                "remote_http_mcp_oauth",
                "messaging_gateway_depth",
                "remote_control_relay",
            ],
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
            "target_requirements": [
                "native_shell_depth",
                "live_browser_automation",
                "provider_specific_media_adapters",
                "mobile_desktop_wrappers",
            ],
        },
        {
            "platform": "Claude Code",
            "covered": [
                "slash command aliases",
                "session controls",
                "MCP registry surface",
                "skills and plugin inventory",
                "model auth status",
                "remote-control readiness",
                "short-lived remote-control pairing tokens",
                "background task submission",
            ],
            "security_delta": "Aegis exposes Claude-style controls through the governed local runtime and keeps off-device relay blocked until scoped transport, approval prompts, and audit receipts exist.",
            "live_gap": "Claude Code subscription token import, outbound Remote Control relay, hooks, plugin install parity, subagent runtime depth, and PR automation remain tracked gaps instead of silent stubs.",
            "target_requirements": [
                "claude_subscription_token_bridge",
                "remote_control_outbound_relay",
                "hooks_and_plugin_lifecycle",
                "subagent_runtime_depth",
                "pr_review_and_autofix_workflows",
            ],
        },
    ]


def _live_gap_backlog(
    competitive_targets: list[dict[str, Any]],
    readiness: list[dict[str, Any]],
    model_auth_parity: dict[str, Any],
    configured_providers: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    live_connector_adapters: list[dict[str, Any]],
    available_live_connector_adapters: list[dict[str, Any]],
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
    available_backends = _available_backend_adapters(backends)
    provider_channel_status = (
        "live_connectors_partially_live"
        if live_connector_adapters
        else "live_connectors_available_unconfigured"
        if available_live_connector_adapters
        else "live_connector_work_required"
    )
    provider_channel_detail = (
        "Some provider or channel live adapters are configured; continue promoting remaining service integrations through scoped, allowlisted, approval-gated adapters."
        if live_connector_adapters
        else "Live-capable connector adapters exist but are disabled by default; configure scoped credentials, allowlists, and approvals before production use."
        if available_live_connector_adapters
        else "Promote write-capable service and channel integrations from mock-default mode into configured, scoped, allowlisted, approval-gated live adapters."
    )
    return [
        {
            "area": "model_provider_auth_login_parity",
            "platforms": ["Hermes Agent", "Claude Code"],
            "status": model_auth_parity["status"],
            "detail": (
                f"{model_auth_parity['target_provider_count']} provider/auth targets are tracked; "
                f"{model_auth_parity['api_key_ready_count']} API-key targets and {model_auth_parity['local_ready_count']} local targets are ready, "
                f"{model_auth_parity['metadata_or_bridge_pending_count']} provider-native subscription/OAuth/cloud-identity bridges remain gated."
            ),
            "target_provider_count": model_auth_parity["target_provider_count"],
            "aegis_provider_count": model_auth_parity["aegis_provider_count"],
            "sample_tools": [],
            "target_providers": model_auth_parity["targets"],
            "subscription_bridge_targets": model_auth_parity["subscription_bridge_targets"],
            "not_started_targets": model_auth_parity["not_started_targets"],
            "implemented_auth_methods": model_auth_parity["implemented_auth_methods"],
            "operator_checklist": _model_auth_operator_checklist(model_auth_parity),
            "next_steps": [
                "Implement provider-native OAuth/device/cloud-identity bridges one provider at a time with token refresh receipts.",
                "Use official CLI subscription-login handoff only until Aegis can read provider-approved token stores without browser cookie import.",
                "Add denied, approved, refresh, logout, and receipt-redaction tests for every bridge before enabling live model calls through it.",
            ],
            "required_controls": model_auth_parity["required_controls"],
            "verification_gates": model_auth_parity["verification_gates"],
            "evaluation_scenarios": [
                "model_auth.subscription_login_metadata_only",
                "model_auth.raw_token_capture_rejected",
                "model_auth.provider_native_oauth_disabled_until_bridge",
            ],
            "configured_provider_count": len(configured_providers),
        },
        {
            "area": "provider_and_channel_live_connectors",
            "platforms": [target["platform"] for target in competitive_targets],
            "status": provider_channel_status,
            "detail": provider_channel_detail,
            "sample_tools": mock_write_tools[:8],
            "live_read_surfaces": live_read_connector_tools[:8],
            "implemented_live_adapters": live_connector_adapters,
            "available_live_adapters": available_live_connector_adapters,
            "operator_checklist": _live_connector_operator_checklist(
                live_connector_adapters,
                available_live_connector_adapters,
                live_read_connector_tools,
            ),
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
            "detail": "Sanitized browser rendering is available for stored HTTP-content sessions; provider-backed media artifacts can run through allowlisted HTTPS adapters, while real page automation and provider-specific media depth still require stronger sandboxing.",
            "sample_tools": facade_tools[:8],
            "next_steps": [
                "Extend rendering toward real browser automation only after network, cookie, and JavaScript boundaries are enforceable.",
                "Extend provider-backed media execution toward provider-specific image, audio, and video adapters after redacted receipt coverage is proven.",
                "Gate any page mutation, recording, or generated media write behind approval.",
            ],
            "required_controls": ["sandbox_isolation", "taint_preservation", "artifact_hashing", "human_approval"],
            "verification_gates": [
                "unsupported_selector_truthfulness",
                "artifact_hash_stability",
                "approval_required_mutation",
                "no_raw_secret_capture",
                "disabled_live_browser_denial",
            ],
            "implemented_hardening_controls": [
                {
                    "control": "unsupported_selector_truthfulness",
                    "evidence": "table extraction reports unsupported selectors without claiming a filtered result",
                },
                {
                    "control": "artifact_hash_stability",
                    "evidence": "browser and media artifacts emit SHA-256 hashes in structured receipts",
                },
                {
                    "control": "approval_required_mutation",
                    "evidence": "browser click/fill actions and generated media writes are approval-gated",
                },
                {
                    "control": "no_raw_secret_capture",
                    "evidence": "browser/media metadata redacts secret-shaped fields and avoids raw prompt persistence",
                },
                {
                    "control": "sandboxed_media_worker_process",
                    "evidence": "deterministic local media artifacts are written by a subprocess with stdin-only payloads and a minimal environment",
                },
                {
                    "control": "os_level_media_worker_limits",
                    "evidence": "the local media worker runs in a separate process session with POSIX CPU, file-size, file-descriptor, and memory limits where supported",
                },
                {
                    "control": "provider_backed_media_artifacts",
                    "evidence": "approved image and TTS tools can call allowlisted HTTPS media providers with brokered tokens and redacted artifact receipts",
                },
                {
                    "control": "browser_automation_boundary_receipts",
                    "evidence": "browser snapshot and render evidence records cookie, storage, script, subresource, network, and mutation boundaries before live automation is enabled",
                },
                {
                    "control": "disabled_live_browser_denial",
                    "evidence": "explicit live browser automation requests fail closed with activation preflight blockers",
                },
            ],
            "remaining_depth_work": [
                "live_browser_automation_adapter",
                "stricter_platform_media_sandbox_profiles",
                "provider_specific_media_adapter_expansion",
            ],
            "evaluation_scenarios": ["artifact_integrity.browser_media_receipts"],
            "operator_checklist": _browser_media_operator_checklist(
                implemented_controls=[
                    "unsupported_selector_truthfulness",
                    "artifact_hash_stability",
                    "approval_required_mutation",
                    "no_raw_secret_capture",
                    "sandboxed_media_worker_process",
                    "os_level_media_worker_limits",
                    "provider_backed_media_artifacts",
                    "browser_automation_boundary_receipts",
                    "disabled_live_browser_denial",
                ],
                remaining_depth_work=[
                    "live_browser_automation_adapter",
                    "stricter_platform_media_sandbox_profiles",
                    "provider_specific_media_adapter_expansion",
                ],
            ),
            "configured_provider_count": len(configured_providers),
        },
        {
            "area": "remote_backend_activation",
            "platforms": ["Hermes Agent", "OpenClaw"],
            "status": (
                "remote_backends_partially_live"
                if implemented_backends
                else "backend_adapters_available_unconfigured"
                if available_backends
                else "backend_adapter_required"
            ),
            "detail": (
                "Some nonlocal execution adapters are enabled with receipts; hosted sandbox backends still require provider-specific activation work."
                if implemented_backends
                else "Nonlocal execution adapters exist but are disabled by default; configure scoped credentials, allowlists, and rollback posture before use."
                if available_backends
                else "Enable backend-gated execution paths only after sandbox credentials, scope limits, rollback, and receipts are implemented."
            ),
            "sample_tools": backend_tools[:8],
            "implemented_backend_adapters": implemented_backends,
            "available_backend_adapters": available_backends,
            "operator_checklist": _remote_backend_operator_checklist(implemented_backends, available_backends),
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


def _model_auth_operator_checklist(model_auth_parity: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "control": "api_key_secret_broker",
            "state": "enforced" if model_auth_parity["api_key_ready_count"] else "pending",
            "detail": "API-key providers use brokered local secrets and redact raw values from status, receipts, and model-facing flows.",
        },
        {
            "control": "subscription_token_bridge",
            "state": "official_cli_handoff_only" if model_auth_parity["subscription_bridge_targets"] else "not_required",
            "detail": "Codex/ChatGPT and Claude Code subscription login can launch official CLI auth flows, but Aegis does not import provider tokens until a governed bridge exists.",
        },
        {
            "control": "oauth_device_flows",
            "state": "official_cli_handoff_only" if model_auth_parity["subscription_bridge_targets"] else "ready_for_review",
            "detail": "Copilot, Qwen, Nous Portal, and cloud-identity providers are explicit local handoff targets until governed OAuth/device/cloud identity bridges exist.",
        },
        {
            "control": "raw_browser_token_capture",
            "state": "denied_by_design",
            "detail": "Aegis does not accept pasted browser cookies, session tokens, or refresh tokens as subscription auth.",
        },
        {
            "control": "provider_catalog_depth",
            "state": "partial" if model_auth_parity["status"] != "target_surface_ready" else "complete",
            "detail": f"{model_auth_parity['target_provider_count']} target providers tracked against {model_auth_parity['aegis_provider_count']} current provider routes.",
        },
        {
            "control": "provider_allowlist_before_live_call",
            "state": "enforced",
            "detail": "Live model calls still require policy-approved provider domains before credentials are used.",
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


def _browser_media_operator_checklist(implemented_controls: list[str], remaining_depth_work: list[str]) -> list[dict[str, str]]:
    implemented = set(implemented_controls)
    remaining = set(remaining_depth_work)
    return [
        {
            "control": "browser_boundary_receipts",
            "state": "available" if "browser_automation_boundary_receipts" in implemented else "pending",
            "detail": "Snapshot and render evidence records cookie, storage, script, subresource, network, and mutation boundaries.",
        },
        {
            "control": "taint_preservation",
            "state": "enforced",
            "detail": "Browser, media, file, and connector outputs remain untrusted data before model use.",
        },
        {
            "control": "artifact_hashing",
            "state": "available" if "artifact_hash_stability" in implemented else "pending",
            "detail": "Browser and media artifacts emit SHA-256 hashes in structured receipts.",
        },
        {
            "control": "human_approval",
            "state": "enforced" if "approval_required_mutation" in implemented else "pending",
            "detail": "Browser click/fill actions and generated media writes remain approval-gated.",
        },
        {
            "control": "secret_capture_boundary",
            "state": "enforced" if "no_raw_secret_capture" in implemented else "pending",
            "detail": "Browser/media metadata redacts secret-shaped fields and avoids raw prompt persistence.",
        },
        {
            "control": "media_worker_sandbox",
            "state": "available" if {"sandboxed_media_worker_process", "os_level_media_worker_limits"}.issubset(implemented) else "partial",
            "detail": "Local media artifacts run in an isolated subprocess with OS limits where supported.",
        },
        {
            "control": "live_browser_automation",
            "state": "blocked_with_preflight" if "disabled_live_browser_denial" in implemented else "not_started" if "live_browser_automation_adapter" in remaining else "ready_for_review",
            "detail": "Real page automation stays blocked with explicit activation evidence until network, cookie, JavaScript, and mutation boundaries are enforceable.",
        },
        {
            "control": "provider_media_depth",
            "state": "partial" if "provider_backed_media_artifacts" in implemented else "not_started",
            "detail": "Provider-backed image and TTS artifacts exist; provider-specific image, audio, and video adapters still need expansion.",
        },
        {
            "control": "platform_media_sandbox_profiles",
            "state": "pending" if "stricter_platform_media_sandbox_profiles" in remaining else "ready_for_review",
            "detail": "Stricter per-platform profiles are still required before broad media execution rollout.",
        },
    ]


def _available_live_connector_adapters(connectors: list[dict[str, Any]], config: Any) -> list[dict[str, Any]]:
    configured = {(adapter["kind"], adapter["name"]) for adapter in _live_connector_adapters(connectors, config)}
    adapters: list[dict[str, Any]] = []
    for connector in connectors:
        name = str(connector.get("name", ""))
        if name in _LIVE_CONNECTOR_CAPABILITIES and ("connector", name) not in configured:
            adapters.append(
                {
                    "kind": "connector",
                    "name": name,
                    "status": "available_opt_in",
                    "capabilities": list(_LIVE_CONNECTOR_CAPABILITIES[name]),
                    "required_controls": ["enable_live_writes", "network_allowlist", "human_approval", "redacted_receipts"],
                    "activation": live_connector_activation(
                        connector=name,
                        operation="live_write",
                        enabled=False,
                        approved=False,
                        allowlist=tuple(str(item) for item in connector.get("allowlist", ())),
                    ),
                    "raw_secret_values_included": False,
                }
            )
    for name in ("webhook", "email", "chat_webhook"):
        if ("channel", name) not in configured:
            adapters.append(
                {
                    "kind": "channel",
                    "name": name,
                    "status": "available_opt_in",
                    "capabilities": list(_LIVE_CHANNEL_CAPABILITIES[name]),
                    "required_controls": ["explicit_channel_config", "human_approval", "secret_broker_or_allowlist", "redacted_receipts"],
                    "activation": _live_channel_activation(name),
                    "raw_secret_values_included": False,
                }
            )
    return adapters


def _live_channel_activation(name: str) -> dict[str, Any]:
    return {
        "status": "live_channel_required",
        "preflight_status": "blocked",
        "required_controls": ["explicit_channel_config", "human_approval", "secret_broker_or_allowlist", "redacted_receipts"],
        "configured_controls": ["redacted_receipts"],
        "blockers": [
            {"control": "explicit_channel_config", "detail": f"{name} outbound channel is not fully enabled"},
            {"control": "human_approval", "detail": f"{name} outbound sends require approval before delivery"},
            {"control": "secret_broker_or_allowlist", "detail": f"{name} credentials or provider target must be brokered and allowlisted"},
        ],
        "verification_gates": ["disabled_channel_denial", "approved_send", "receipt_redaction"],
        "next_steps": [
            f"Configure only the scoped outbound {name} channel needed for the deployment.",
            "Keep sends approval-gated and store only redacted delivery receipts.",
        ],
    }


def _live_connector_operator_checklist(
    live_connector_adapters: list[dict[str, Any]],
    available_live_connector_adapters: list[dict[str, Any]],
    live_read_connector_tools: list[str],
) -> list[dict[str, str]]:
    return [
        {
            "control": "credential_handles",
            "state": "required_per_adapter",
            "detail": "Use brokered secret handles for each live connector or outbound channel credential.",
        },
        {
            "control": "network_allowlist",
            "state": "required_per_domain",
            "detail": "Allowlist each provider host before live reads, writes, or webhook sends leave the local runtime.",
        },
        {
            "control": "live_enablement_flag",
            "state": "required_per_adapter",
            "detail": "Enable only the specific live write or outbound channel flag needed for the adapter under review.",
        },
        {
            "control": "human_approval",
            "state": "enforced",
            "detail": "High-impact live writes and sends remain approval-gated before execution.",
        },
        {
            "control": "receipt_redaction",
            "state": "enforced",
            "detail": "Live connector receipts expose operation summaries and hashes, not raw secret values.",
        },
        {
            "control": "mock_fallback",
            "state": "available",
            "detail": "Adapters retain mock or dry-run paths while credentials, allowlists, or approvals are absent.",
        },
        {
            "control": "read_surface_inventory",
            "state": "available" if live_read_connector_tools else "pending",
            "detail": f"{len(live_read_connector_tools)} live-read-capable tool surfaces are visible before write promotion.",
        },
        {
            "control": "promotion_scope",
            "state": "partial" if live_connector_adapters else "not_started" if available_live_connector_adapters else "needs_adapter",
            "detail": f"{len(live_connector_adapters)} live adapters enabled; {len(available_live_connector_adapters)} opt-in adapters still available.",
        },
    ]


_LIVE_CONNECTOR_CAPABILITIES = {
    "github": ("issue_comment_write", "issue_create"),
    "gitlab": ("issue_note_write", "merge_request_note_write"),
    "generic_rest": ("https_rest_write",),
    "mock_graph": ("calendar_write", "email_write", "contact_write"),
    "mock_servicenow": ("ticket_write",),
    "mock_messaging": ("message_send",),
}


_LIVE_CHANNEL_CAPABILITIES = {
    "webhook": ("signed_webhook_send",),
    "email": ("smtp_send",),
    "chat_webhook": ("chat_webhook_send",),
}


def _implemented_backend_adapters(backends: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": str(backend.get("name", "")),
            "status": "enabled",
            "local": bool(backend.get("local")),
            "activation": backend.get("activation", {}),
            "raw_secret_values_included": False,
        }
        for backend in backends
        if backend.get("enabled") and backend.get("name") != "local"
    ]


def _available_backend_adapters(backends: list[dict[str, Any]]) -> list[dict[str, Any]]:
    adapters: list[dict[str, Any]] = []
    for backend in backends:
        name = str(backend.get("name", ""))
        if backend.get("enabled") or name not in _LIVE_BACKEND_CAPABILITIES:
            continue
        adapters.append(
            {
                "name": name,
                "status": "available_opt_in",
            "local": bool(backend.get("local")),
            "persistent": bool(backend.get("persistent")),
            "capabilities": list(_LIVE_BACKEND_CAPABILITIES[name]),
            "required_controls": ["explicit_backend_enablement", "brokered_backend_auth", "scope_limits", "rollback_receipts"],
            "activation": backend.get("activation", {}),
            "raw_secret_values_included": False,
        }
    )
    return adapters


def _remote_backend_operator_checklist(implemented_backends: list[dict[str, Any]], available_backends: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "control": "explicit_backend_enablement",
            "state": "required_per_backend",
            "detail": "Nonlocal backends stay disabled until the runtime config names the exact backend.",
        },
        {
            "control": "brokered_backend_auth",
            "state": "required_per_backend",
            "detail": "SSH keys and hosted sandbox tokens must resolve through secret handles, not raw config values.",
        },
        {
            "control": "scope_limits",
            "state": "enforced",
            "detail": "Remote dispatch enforces allowed hosts, workspace boundaries, and command argument constraints.",
        },
        {
            "control": "resource_limits",
            "state": "required_per_backend",
            "detail": "Container and hosted executions need bounded CPU, memory, timeout, file, and network posture.",
        },
        {
            "control": "rollback_receipts",
            "state": "enforced",
            "detail": "Activation, execution, and cleanup receipts are recorded without raw command or secret capture.",
        },
        {
            "control": "disabled_backend_denial",
            "state": "enforced",
            "detail": "Backend-gated tools fail closed while a backend is absent, disabled, or outside policy.",
        },
        {
            "control": "provider_lifecycle_depth",
            "state": "partial" if implemented_backends else "not_started" if available_backends else "needs_adapter",
            "detail": f"{len(implemented_backends)} nonlocal backends enabled; {len(available_backends)} opt-in adapters still available.",
        },
    ]


_LIVE_BACKEND_CAPABILITIES = {
    "docker": ("container_limits", "network_none", "cleanup_receipt"),
    "ssh": ("brokered_private_key", "allowlisted_hosts", "temporary_key_cleanup"),
    "modal": ("hosted_sandbox_submission", "brokered_token", "allowlisted_https_api"),
    "daytona": ("hosted_sandbox_submission", "brokered_token", "allowlisted_https_api"),
    "vercel_sandbox": ("hosted_sandbox_submission", "brokered_token", "allowlisted_https_api"),
}


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
