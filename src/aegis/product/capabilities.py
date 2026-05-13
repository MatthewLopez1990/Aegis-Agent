"""Product capability summaries derived from live runtime state."""

from __future__ import annotations

import json
from typing import Any

from aegis.connectors.base import live_connector_activation
from aegis.kanban.manager import subagent_review_action_hints


ACTIVE_WORK_STATUSES = {"pending", "planned", "running", "waiting_approval", "paused"}


def build_product_dashboard(orchestrator: Any) -> dict[str, Any]:
    """Return a product-facing dashboard without exposing raw secrets or payloads."""

    connectors = orchestrator.connectors.status()
    channels = orchestrator.channels.list_channels()
    tools = orchestrator.tool_catalog.list()
    backends = orchestrator.execution_backends.list()
    processes = orchestrator.processes.status(limit=12)
    providers = orchestrator.models.list_providers()
    schedules = orchestrator.schedules.list_schedules()
    sessions = orchestrator.sessions.list_sessions()
    boards = orchestrator.kanban.list_boards()
    subagent_delegations = orchestrator.kanban.subagent_status(limit=12)
    approvals = orchestrator.approvals.list()
    pending_approvals = [_decode_pending_approval(orchestrator, approval) for approval in approvals if approval["status"] == "pending"]
    task_rows = orchestrator.store.list_tasks(limit=12)
    active_work_rows = [row for row in orchestrator.store.list_tasks(limit=1000) if str(row.get("status") or "") in ACTIVE_WORK_STATUSES]
    active_work_counts = _active_work_counts(active_work_rows)
    session_task_rows = _recent_session_task_rows(orchestrator, task_rows, sessions, limit=12)
    tasks = [_decode_task(orchestrator, row) for row in task_rows]
    active_work_tasks = [_decode_task(orchestrator, row) for row in active_work_rows[:12]]
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
            "background_processes": processes["process_count"],
            "active_background_processes": processes["active_process_count"],
            "model_providers": len(providers),
            "configured_or_local_providers": len(configured_providers),
            "sessions": len(sessions),
            "session_bound_recent_tasks": len(session_task_rows),
            "schedules": len(schedules),
            "boards": len(boards),
            "subagent_delegations": subagent_delegations["total_cards"],
            "open_subagent_delegations": subagent_delegations["open_cards"],
            "recent_tasks": len(tasks),
            "active_work_count": active_work_counts["total"],
            "pending_task_count": active_work_counts["pending"],
            "planned_task_count": active_work_counts["planned"],
            "running_task_count": active_work_counts["running"],
            "waiting_task_count": active_work_counts["waiting_approval"],
            "paused_task_count": active_work_counts["paused"],
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
                "detail": "Live writes, sends, shell execution, MCP calls, generated skills, reviewed skill draft installs, and risky backends are approval-gated.",
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
                "coverage": f"{len(schedules)} schedules, {len(boards)} work boards, {subagent_delegations['open_cards']} open subagent delegation(s)",
                "detail": "Schedules start paused pending approval; Kanban cards provide a durable multi-agent coordination surface with approved subagent delegation queues.",
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
                "coverage": f"{len(backends)} backend definitions, {processes['active_process_count']} active background process(es)",
                "detail": "Local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox are represented for policy decisions; governed argv-only background processes expose approval-gated start, PTY, stdin, resize, stop, status, and redacted private logs.",
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
            processes,
            subagent_delegations,
        ),
        "implementation_readiness": implementation_readiness,
        "subagent_delegations": subagent_delegations,
        "background_processes": processes,
        "enterprise_readiness": enterprise_readiness,
        "memory_readiness": memory_readiness,
        "self_improvement_readiness": self_improvement_readiness,
        "recent_tasks": tasks,
        "active_work_tasks": active_work_tasks,
        "recent_session_tasks": session_tasks,
        "pending_approvals": pending_approvals[:12],
    }


def _active_work_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {status: 0 for status in ACTIVE_WORK_STATUSES}
    for row in rows:
        status = str(row.get("status") or "")
        if status in counts:
            counts[status] += 1
    return {"total": sum(counts.values()), **counts}


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
                "model-ready subagent review packets",
                "terminal backends",
                "research tool surface",
                "session resume continuity",
                "guarded remote-control readiness",
                "approved outbound remote-control relay registration",
                "approved remote-control relay directory publish",
                "approved remote-control relay notification publish",
                "approved brokered native APNS/FCM remote notification publish",
                "approved remote-control relay action proxy",
                "scoped remote-control directory",
                "allowlisted brokered-bearer Streamable HTTP MCP",
                "remote MCP OAuth protected-resource metadata and brokered OAuth bearer configuration",
                "reviewed private skill draft candidates",
            ],
            "security_delta": "Aegis treats all external outputs as tainted data and requires approval for high-impact actions by default.",
            "live_gap": "API-key-ready Hermes providers including Hugging Face, NVIDIA NIM, Vercel AI Gateway, OpenCode, Kilo Code, Ollama Cloud, Arcee, GMI, StepFun, Xiaomi, Tencent TokenHub, Kimi China, and MiniMax China are routable alongside brokered Nous Portal OAuth, MiniMax Token Plan, brokered MiniMax OAuth, brokered Google Gemini OAuth / Code Assist, verified Codex/Claude/Qwen Code/Gemini CLI/Copilot subscription, Google Vertex AI, AWS Bedrock, Azure Foundry cloud-identity bridges, and remote MCP OAuth protected-resource metadata/brokered bearer configuration; remaining work is local operator sign-in/configuration for unverified accounts and future provider-native bridges beyond the tracked target set.",
            "target_requirements": [
                "provider_native_oauth_and_device_flows",
                "subscription_login_bridge",
                "remote_mcp_oauth",
                "messaging_gateway_depth",
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
                "reviewed skill draft candidates",
                "multi-agent routing primitives",
                "schedules",
                "diagnostic panels",
                "metadata-only migration inspection",
                "session-bound run visibility",
            ],
            "security_delta": "Aegis defaults to mock or dry-run mode for broad-access capabilities until credentials, scopes, rollback, and approvals are explicit.",
            "live_gap": "Mobile nodes, native desktop wrappers, and live third-party channel implementations remain staged; generic/OpenAI-style media plus Stability AI v1 image generation, Google Vertex Imagen image generation, ElevenLabs TTS, and ElevenLabs speech-to-text are implemented, while additional provider-specific image, audio, and video adapters remain staged behind secure adapter work.",
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
                "durable short-lived remote-control pairing tokens",
                "scoped remote-control directory",
                "approved outbound relay registration",
                "approved relay directory publish",
                "approved relay notification publish",
                "approved relay delivery confirmation reconciliation",
                "approved brokered native APNS/FCM notification publish",
                "brokered native push target lifecycle records",
                "approved brokered native push credential rotation",
                "structured redacted relay notification receipts",
                "approved relay action proxy",
                "background task submission",
                "operator-approved subagent batch runs",
                "model-ready subagent review packets",
                "governed lifecycle hooks",
                "governed local plugin install lifecycle",
                "reviewed private skill draft candidates",
                "disabled skill candidate installation",
                "verified plugin marketplace manifest fetch/install",
                "signed remote plugin bundle review",
                "explicit signed remote plugin bundle install",
                "prepared verified plugin marketplace update candidates",
                "verified plugin marketplace update application",
                "PR review comment autofix planning",
                "approved PR local patch application",
                "approved PR autofix response posting",
            ],
            "security_delta": "Aegis exposes Claude-style controls through the governed local runtime and requires scoped pairings, approved relay registration, and redacted receipts before off-device access.",
            "live_gap": "Unattended unreviewed plugin bundle auto-install, unattended plugin auto-update, recursive subagent model-loop depth, broad cloud relay delivery, and future provider OAuth bridges beyond the tracked target set remain explicit gaps instead of silent stubs; reviewed skill draft candidates can now be staged, verified, and installed disabled from CLI/TUI/API without raw observed task capture.",
            "target_requirements": [
                "unattended_remote_plugin_bundle_auto_install",
                "unattended_plugin_auto_update",
                "subagent_runtime_depth",
                "broad_cloud_relay_delivery",
                "future_provider_oauth_bridge_targets",
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
    processes: dict[str, Any],
    subagent_delegations: dict[str, Any],
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
                f"{model_auth_parity['operator_login_required_count']} provider-native subscription/OAuth/cloud-identity login surface(s) are implemented and awaiting local operator sign-in, "
                f"with {model_auth_parity['implementation_gap_count']} implementation gap(s)."
            ),
            "target_provider_count": model_auth_parity["target_provider_count"],
            "aegis_provider_count": model_auth_parity["aegis_provider_count"],
            "sample_tools": [],
            "target_providers": model_auth_parity["targets"],
            "subscription_bridge_targets": model_auth_parity["subscription_bridge_targets"],
            "operator_login_required_targets": model_auth_parity["operator_login_required_targets"],
            "implementation_gap_targets": model_auth_parity["implementation_gap_targets"],
            "not_started_targets": model_auth_parity["not_started_targets"],
            "implemented_auth_methods": model_auth_parity["implemented_auth_methods"],
            "operator_checklist": _model_auth_operator_checklist(model_auth_parity),
            "next_steps": [
                "Run the local provider login handoff for each unconfigured subscription, OAuth, OAuth-device, or cloud-identity target that should be active on this machine.",
                "Use the expanded Hermes API-key providers plus verified Codex/Claude/Qwen Code/Gemini CLI/Copilot subscription, brokered Nous Portal OAuth, brokered MiniMax OAuth, brokered Google Gemini OAuth / Code Assist, MiniMax Token Plan, Google Vertex AI, AWS Bedrock, and Azure Foundry bridges where available.",
                "For any future provider target that appears in implementation_gap_targets, add denied, approved, refresh, logout, and receipt-redaction tests before enabling live model calls through it.",
            ],
            "required_controls": model_auth_parity["required_controls"],
            "verification_gates": model_auth_parity["verification_gates"],
            "evaluation_scenarios": [
                "model_auth.subscription_cli_bridge",
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
                "Keep live writes approval-gated with runtime rate limits and redacted receipts.",
                "Create, verify, and explicitly approve channel activation packets before promoting signed webhook, email, or chat-webhook delivery.",
                "Promote each adapter only after mock, denied, approved, and audit-path tests pass.",
            ],
            "required_controls": ["human_approval", "secret_broker", "network_allowlist", "rate_limits", "rollback_receipts", "audit_receipts", "channel_activation_packet_verification", "channel_activation_approval_receipt"],
            "verification_gates": ["mock_fallback", "denied_write", "approved_write", "rate_limit_denial", "rollback_receipt", "receipt_redaction", "channel_activation_packet_integrity", "channel_activation_approval_receipt"],
            "evaluation_scenarios": [
                "connector_abuse.write_without_scope",
                "live_connector_receipts.redacted_write_summary",
                "live_connector_rate_limit.exceeded",
                "channel.live_activation_approval",
                "generic_rest.live_write_rate_limit",
                "github_gitlab.live_write_rate_limit",
                "github_gitlab.rollback_offer_receipt",
                "github_gitlab.approved_rollback_receipt",
                "graph.calendar_rollback_receipt",
                "messaging.live_send_rate_limit",
                "messaging.rollback_message_receipt",
                "service_desk.rollback_close_ticket_receipt",
            ],
            "configured_provider_count": len(configured_providers),
        },
        {
            "area": "browser_and_media_depth",
            "platforms": ["OpenClaw"],
            "status": "live_javascript_available_media_depth_remaining",
            "detail": "Sanitized browser rendering, bounded static DOM snapshots, approved static form fills, approved static GET form submits, approved static-anchor navigation, private Playwright/Chromium live-browser activation packet review artifacts, opt-in approved headless Chromium read-only snapshots, opt-in approved Chromium CDP selector mutation, opt-in approved private live downloads, opt-in approved workspace-scoped live uploads, and opt-in approved bounded live JavaScript evaluation are available; provider-backed media artifacts, transcription, and video jobs can run through allowlisted HTTPS adapters with media_sandbox_profile_v1 receipts, including OpenAI-style image JSON, Stability AI v1 text-to-image JSON, Google Vertex Imagen predict JSON, multipart image edit, OpenAI-style TTS, ElevenLabs TTS, OpenAI-style audio transcription, ElevenLabs speech-to-text, and video generation adapters, while persistent browser state, raw DOM capture, and raw network body capture remain blocked by design; broader provider-specific media depth still requires expansion.",
            "sample_tools": facade_tools[:8],
            "next_steps": [
                "Use the live-browser read-only adapter only for approved allowlisted screenshot evidence with ephemeral state.",
                "Use the live selector mutation adapter only for approved allowlisted click/fill/submit operations with ephemeral state.",
                "Use the live download adapter only for approved allowlisted selector downloads with private artifact hashes and size limits.",
                "Use the live upload adapter only for approved allowlisted file input selectors with workspace-scoped source files, private evidence hashes, and size/type limits.",
                "Use the live JavaScript adapter only for approved allowlisted pages with script-hash approval, bounded redacted results, and private evidence hashes.",
                "Extend provider-backed media execution toward provider-specific image, audio, and video adapters after redacted receipt coverage is proven.",
                "Gate any page mutation, recording, or generated media write behind approval.",
            ],
            "required_controls": ["sandbox_isolation", "taint_preservation", "artifact_hashing", "human_approval", "activation_packet_verification", "live_browser_readonly_approval", "live_browser_selector_mutation_approval", "live_browser_download_approval", "live_browser_upload_approval", "live_browser_javascript_approval"],
            "verification_gates": [
                "unsupported_selector_truthfulness",
                "artifact_hash_stability",
                "approval_required_mutation",
                "no_raw_secret_capture",
                "live_browser_activation_packet_schema",
                "live_browser_activation_packet_verification",
                "approved_live_browser_readonly_snapshot",
                "approved_live_browser_selector_mutation",
                "approved_live_browser_download",
                "approved_live_browser_upload",
                "approved_live_browser_javascript",
                "playwright_chromium_adapter_preflight",
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
                    "evidence": "approved image, TTS, transcription, and video tools can call allowlisted HTTPS media providers with brokered tokens and redacted receipts",
                },
                {
                    "control": "browser_automation_boundary_receipts",
                    "evidence": "browser snapshot and render evidence records cookie, storage, script, subresource, network, and mutation boundaries before live automation is enabled",
                },
                {
                    "control": "live_browser_activation_packets",
                    "evidence": "live browser preflight returns structured activation packets with configured controls, blockers, verification gates, and next steps while the adapter remains disabled",
                },
                {
                    "control": "playwright_chromium_adapter_preflight",
                    "evidence": "activation packets name the denied-by-default Playwright/Chromium adapter candidate, package/runtime availability, blockers, and no raw executable path",
                },
                {
                    "control": "live_browser_activation_packet_verification",
                    "evidence": "operators can verify private activation packet checksum, schema, blockers, cookie/storage isolation flags, redacted artifact controls, and approval gates while selector-event dispatch remains disabled",
                },
                {
                    "control": "approved_live_browser_readonly_adapter",
                    "evidence": "approved live_navigate and live_screenshot actions can run headless Chromium with an ephemeral profile, main-frame allowlist checks, disabled JavaScript/images, private PNG artifacts, and no raw DOM/cookie/storage return",
                },
                {
                    "control": "approved_live_browser_selector_mutation_adapter",
                    "evidence": "approved live_click, live_fill, and live_submit actions can run through a Chromium CDP ephemeral profile with allowlisted navigation, private PNG/evidence artifacts, no persistent cookies/storage, no downloads/uploads, and no raw DOM/cookie/storage return",
                },
                {
                    "control": "approved_live_browser_download_adapter",
                    "evidence": "approved live_download actions can click an allowlisted page selector through a Chromium CDP ephemeral profile and store one bounded private download artifact with screenshot/evidence hashes, no uploads, no persistent cookies/storage, and no raw DOM/cookie/storage return",
                },
                {
                    "control": "approved_live_browser_upload_adapter",
                    "evidence": "approved live_upload actions can attach one workspace-scoped allowlisted source file to an allowlisted page file input through a Chromium CDP ephemeral profile with private screenshot/evidence hashes, no persistent cookies/storage, and no raw file/DOM/cookie/storage return",
                },
                {
                    "control": "approved_live_browser_javascript_adapter",
                    "evidence": "approved live_evaluate actions can run bounded JavaScript on an allowlisted page through a Chromium CDP ephemeral profile with script-hash approvals, private screenshot/evidence hashes, redacted result summaries, no persistent cookies/storage, and no raw DOM/cookie/storage/network-body return",
                },
                {
                    "control": "platform_media_sandbox_profiles_v1",
                    "evidence": "local and provider-backed media paths return media_sandbox_profile_v1 receipts covering execution, network, filesystem, device, secret, content, and artifact boundaries",
                },
                {
                    "control": "openai_style_image_provider_adapter",
                    "evidence": "approved provider-backed image generation can send an OpenAI-style image JSON request and persist returned data[].b64_json artifacts without storing raw prompt, response body, or secret values",
                },
                {
                    "control": "stability_v1_image_provider_adapter",
                    "evidence": "approved provider-backed image generation can send a Stability AI v1 text-to-image JSON request and persist returned artifacts[].base64 image data without storing raw prompt, response body, or secret values",
                },
                {
                    "control": "google_imagen_provider_adapter",
                    "evidence": "approved provider-backed image generation can send a Google Vertex Imagen predict-style JSON request and persist returned predictions[].bytesBase64Encoded image data without storing raw prompt, response body, or secret values",
                },
                {
                    "control": "openai_style_image_edit_provider_adapter",
                    "evidence": "approved provider-backed image edits can upload one workspace-scoped source image through an OpenAI-style multipart request and persist returned data[].b64_json artifacts without storing raw prompt, source bytes, response body, or secret values",
                },
                {
                    "control": "openai_style_tts_provider_adapter",
                    "evidence": "approved provider-backed TTS can send an OpenAI-style speech request and persist the returned audio artifact without storing raw text, response body, or secret values",
                },
                {
                    "control": "elevenlabs_tts_provider_adapter",
                    "evidence": "approved provider-backed TTS can send an ElevenLabs text-to-speech JSON request with a brokered xi-api-key header and persist the returned audio artifact without storing raw text, response body, or secret values",
                },
                {
                    "control": "openai_style_transcription_provider_adapter",
                    "evidence": "approved provider-backed audio transcription can upload one workspace-scoped audio file through an OpenAI-style multipart request and return transcript text without storing raw audio, raw response bodies, or secret values",
                },
                {
                    "control": "elevenlabs_transcription_provider_adapter",
                    "evidence": "approved provider-backed audio transcription can upload one workspace-scoped audio file through an ElevenLabs speech-to-text multipart request with a brokered xi-api-key header and return transcript text without storing raw audio, raw response bodies, or secret values",
                },
                {
                    "control": "openai_style_video_provider_adapter",
                    "evidence": "approved provider-backed video generation can submit, poll, download, and delete OpenAI-style video jobs while storing only bounded artifacts and redacted job receipts",
                },
                {
                    "control": "static_dom_snapshot_no_js",
                    "evidence": "browser DOM snapshots parse bounded redacted stored HTTP content without JavaScript, cookies, storage, remote subresources, or selector-event dispatch",
                },
                {
                    "control": "approved_static_form_fill",
                    "evidence": "approved browser fills update matching stored static input/textarea controls while reporting no real page mutation, JavaScript, cookies, storage, or selector-event dispatch",
                },
                {
                    "control": "approved_static_form_submit",
                    "evidence": "approved static GET form submits resolve one stored form, bind approval to a hashed target URL, and navigate through the governed HTTP connector without JavaScript, cookies, storage, or selector-event dispatch",
                },
                {
                    "control": "approved_static_anchor_navigation",
                    "evidence": "approved exact-match anchor clicks resolve safe HTTP(S) hrefs through the governed HTTP connector without JavaScript, cookies, or DOM events",
                },
                {
                    "control": "disabled_live_browser_denial",
                    "evidence": "explicit live browser automation requests fail closed with activation preflight blockers",
                },
            ],
            "provider_media_adapters": {
                "implemented": [
                    {"adapter": "openai_images", "tool": "image_generate", "response_shape": "data[].b64_json"},
                    {"adapter": "stability_v1_text_to_image", "tool": "image_generate", "response_shape": "artifacts[].base64"},
                    {"adapter": "google_imagen", "tool": "image_generate", "response_shape": "predictions[].bytesBase64Encoded"},
                    {"adapter": "openai_image_edit", "tool": "image_edit", "response_shape": "data[].b64_json"},
                    {"adapter": "openai_tts", "tool": "tts", "response_shape": "binary_audio"},
                    {"adapter": "elevenlabs_tts", "tool": "tts", "response_shape": "binary_audio"},
                    {"adapter": "openai_transcription", "tool": "voice_transcribe", "response_shape": "transcript_text"},
                    {"adapter": "elevenlabs_transcription", "tool": "voice_transcribe", "response_shape": "transcript_text"},
                    {"adapter": "openai_video", "tool": "video_generate", "response_shape": "job_lifecycle_and_bounded_artifacts"},
                ],
                "remaining_by_modality": {
                    "image": ["additional provider-native image edit, upscale, and product-image adapters"],
                    "audio": ["additional provider-native speech-to-speech, voice-cloning, and dialogue adapters"],
                    "video": ["additional provider-native video lifecycle adapters"],
                },
                "raw_prompt_or_secret_storage": False,
                "raw_response_body_storage": False,
            },
            "remaining_depth_work": [
                "provider_specific_media_adapter_expansion",
            ],
            "evaluation_scenarios": [
                "artifact_integrity.browser_media_receipts",
                "browser.live_activation_packet_preflight",
                "browser.live_activation_packet_verification",
                "browser.live_readonly_snapshot",
                "browser.live_selector_mutation",
                "browser.live_download",
                "browser.live_upload",
                "browser.live_evaluate",
                "browser.live_automation_denied_until_adapter_ready",
            ],
            "operator_checklist": _browser_media_operator_checklist(
                implemented_controls=[
                    "unsupported_selector_truthfulness",
                    "artifact_hash_stability",
                    "approval_required_mutation",
                    "no_raw_secret_capture",
                    "sandboxed_media_worker_process",
                    "os_level_media_worker_limits",
                    "provider_backed_media_artifacts",
                    "platform_media_sandbox_profiles_v1",
                    "browser_automation_boundary_receipts",
                    "live_browser_activation_packets",
                    "playwright_chromium_adapter_preflight",
                    "live_browser_activation_packet_verification",
                    "approved_live_browser_readonly_adapter",
                    "approved_live_browser_selector_mutation_adapter",
                    "approved_live_browser_download_adapter",
                    "approved_live_browser_upload_adapter",
                    "approved_live_browser_javascript_adapter",
                    "openai_style_image_provider_adapter",
                    "stability_v1_image_provider_adapter",
                    "google_imagen_provider_adapter",
                    "openai_style_image_edit_provider_adapter",
                    "openai_style_tts_provider_adapter",
                    "elevenlabs_tts_provider_adapter",
                    "openai_style_transcription_provider_adapter",
                    "elevenlabs_transcription_provider_adapter",
                    "openai_style_video_provider_adapter",
                    "static_dom_snapshot_no_js",
                    "approved_static_form_fill",
                    "approved_static_form_submit",
                    "disabled_live_browser_denial",
                ],
                remaining_depth_work=[
                    "provider_specific_media_adapter_expansion",
                ],
            ),
            "configured_provider_count": len(configured_providers),
        },
        {
            "area": "subagent_runtime_depth",
            "platforms": ["Hermes Agent", "Claude Code"],
            "status": "isolated_loop_ready_autonomous_recursion_blocked",
            "detail": (
                f"Approved subagent work is tracked through a durable, auditable delegation queue with "
                f"{subagent_delegations['open_cards']} open card(s), {subagent_delegations.get('enabled_profile_count', 0)} enabled profile(s), enforced queue budgets, review-gated recursive child delegation budgets, sanitized handoff receipts, approved isolated worker-run receipts, parent-bound review receipts, model-ready review packets, approved sanitized model-review invocations, operator-approved batch-run receipts, scoped autonomy step-plan receipts, isolated autonomy loop rehearsal receipts, and explicit autonomy preflight receipts; recursive autonomous model-loop execution remains blocked."
            ),
            "sample_tools": ["subagent_delegate"],
            "operator_checklist": _subagent_operator_checklist(subagent_delegations),
            "next_steps": [
                "Use approved autonomy-step plans and autonomy-run rehearsals to build and exercise scoped isolated loop boundaries without model or tool execution.",
                "Use approved model-review invocations to review packet integrity without raw instruction or worker output forwarding.",
                "Only consider recursive autonomous model loops after the recursive model-loop executor lands.",
            ],
            "required_controls": ["human_approval", "tainted_instruction_metadata", "durable_queue", "recursive_budget_limits", "review_gated_recursive_child_delegations", "handoff_receipts", "isolated_worker_receipts", "parent_bound_review_receipts", "model_ready_review_packets", "sanitized_model_review_invocations", "operator_batch_receipts", "scoped_autonomy_step_plans", "autonomous_loop_isolation", "isolated_autonomy_loop_rehearsals", "autonomy_preflight_receipts"],
            "verification_gates": ["approval_required_delegation", "status_queue_visibility", "raw_instruction_redaction", "recursive_child_delegation_receipt", "isolated_worker_receipts", "parent_bound_review_receipt", "parent_task_review_binding", "model_ready_review_packet_sanitization", "sanitized_model_review_context", "operator_batch_receipts", "autonomy_step_plan_receipt", "isolated_autonomy_loop_receipt", "autonomy_preflight_receipt", "blocked_autonomous_runtime"],
            "evaluation_scenarios": ["subagent.delegation_queue_visibility", "subagent.recursive_child_delegation", "subagent.isolated_worker_receipts", "subagent.parent_bound_review_receipt", "subagent.model_ready_review_packet", "subagent.sanitized_model_review", "subagent.operator_batch_receipts", "subagent.autonomy_step_plan", "subagent.isolated_autonomy_loop", "subagent.autonomy_preflight", "subagent.autonomous_runtime_blocked"],
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
                else "Local governed background processes are available for argv-only and PTY-backed runs; nonlocal execution adapters exist but are disabled by default and require scoped credentials, allowlists, and rollback posture before use."
                if available_backends
                else "Enable backend-gated execution paths only after sandbox credentials, scope limits, rollback, and receipts are implemented."
            ),
            "sample_tools": backend_tools[:8],
            "local_process_registry": {
                "status": processes.get("status"),
                "active_process_count": processes.get("active_process_count"),
                "implemented_controls": processes.get("implemented_controls", []),
                "remaining_depth_work": processes.get("remaining_depth_work", []),
                "raw_command_included": False,
                "raw_secret_values_included": False,
            },
            "implemented_backend_adapters": implemented_backends,
            "available_backend_adapters": available_backends,
            "operator_checklist": _remote_backend_operator_checklist(implemented_backends, available_backends, processes),
            "next_steps": [
                "Add backend-specific auth checks through brokered handles.",
                "Enforce workspace, network, resource, and rollback limits before dispatch.",
                "Record activation, execution, and cleanup receipts for every remote run.",
            ],
            "required_controls": ["approval_required_process_start", "executable_allowlist", "private_redacted_process_logs", "pty_stdin_resize_receipts", "brokered_backend_auth", "scope_limits", "resource_limits", "rollback_receipts"],
            "verification_gates": ["process_start_approval_gate", "process_log_redaction", "process_pty_input_resize_receipts", "disabled_backend_denial", "approved_activation", "cleanup_receipt", "scope_escape_rejection"],
            "evaluation_scenarios": ["processes.governed_background_registry", "backend_activation.remote_execution_disabled"],
            "configured_provider_count": len(configured_providers),
        },
    ]


def _subagent_operator_checklist(subagent_delegations: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "control": "approval_required_delegation",
            "state": "enforced",
            "detail": "The subagent_delegate tool is approval-gated before a delegation card is created.",
        },
        {
            "control": "durable_queue_visibility",
            "state": "available" if subagent_delegations["status"] == "delegation_queue_ready" else "ready_for_first_delegation",
            "detail": "CLI, TUI, API, and web surfaces expose lane counts and safe card previews for delegated work.",
        },
        {
            "control": "tainted_instruction_metadata",
            "state": "enforced",
            "detail": "Delegation cards mark instructions as tainted and avoid forwarding raw instructions to an autonomous model loop.",
        },
        {
            "control": "handoff_receipts",
            "state": "enforced" if "handoff_receipts" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Operator lane transitions record sanitized receipts without raw delegation instructions or raw handoff reasons.",
        },
        {
            "control": "agent_profile_lifecycle",
            "state": "enforced" if "agent_profile_lifecycle" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Durable subagent profiles bind roles to approval-gated tool, workspace, network, and recursion metadata before any autonomous worker loop exists.",
        },
        {
            "control": "recursive_budget_limits",
            "state": "enforced" if "recursive_budget_limits" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Delegation creation enforces profile parallel-card ceilings and pins recursion, tool-call, runtime, workspace, and network budgets to every card.",
        },
        {
            "control": "review_gated_recursive_child_delegations",
            "state": "enforced" if "review_gated_recursive_child_delegations" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "A parent subagent card can create child cards only with explicit approval, remaining recursive depth, and sanitized child-delegation receipts.",
        },
        {
            "control": "isolated_parallel_runtime",
            "state": "enforced" if "isolated_parallel_runtime" in subagent_delegations.get("implemented_controls", []) else "blocked",
            "detail": "Approved subagent runs execute as isolated deterministic worker subprocesses without model, tool, or network access; recursive autonomous subagents remain disabled.",
        },
        {
            "control": "operator_approved_batch_runtime",
            "state": "enforced" if "operator_approved_batch_runtime" in subagent_delegations.get("implemented_controls", []) else "blocked",
            "detail": "Operators can drain multiple ready subagent cards through the same approved isolated worker path and receive one sanitized batch receipt.",
        },
        {
            "control": "parent_bound_review_receipts",
            "state": "enforced" if "parent_bound_review_receipts" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Isolated worker results produce parent-task review bindings with hashes, counts, taint flags, and explicit review actions without raw worker output.",
        },
        {
            "control": "model_ready_review_packets",
            "state": "enforced" if "model_ready_review_packets" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Operators can create private JSON/checksum review packets for model or reviewer handoff with only hashes, counts, statuses, and receipts, excluding raw instructions and worker output.",
        },
        {
            "control": "sanitized_model_review_invocations",
            "state": "enforced" if "sanitized_model_review_invocations" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Approved model reviews invoke the configured model with only verified packet metadata and store redacted receipt metadata on the card.",
        },
        {
            "control": "scoped_autonomy_step_plans",
            "state": "enforced" if "scoped_autonomy_step_plans" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Approved autonomy-step plans write private checksum-backed scoped context from verified review metadata, deny tool execution, and require operator review.",
        },
        {
            "control": "autonomous_loop_isolation",
            "state": "enforced" if "autonomous_loop_isolation" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Approved autonomy-run rehearsals execute sanitized step plans inside an isolated subprocess with no model, tool, network, or raw instruction access.",
        },
        {
            "control": "isolated_autonomy_loop_rehearsals",
            "state": "enforced" if "isolated_autonomy_loop_rehearsals" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "The isolated loop rehearsal records private plan integrity, subprocess isolation, review-gate, and tool-sandbox receipts while keeping recursive model loops disabled.",
        },
        {
            "control": "autonomy_preflight_receipts",
            "state": "enforced" if "autonomy_preflight_receipts" in subagent_delegations.get("implemented_controls", []) else "pending",
            "detail": "Autonomous recursive subagent runtime attempts expose structured blockers, missing controls, and verification gates instead of silently enabling model loops.",
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
            "state": "available_login_required" if model_auth_parity["operator_login_required_targets"] else "ready_for_review",
            "detail": "Codex/ChatGPT, Claude Code, Qwen Code, Gemini CLI, brokered Google Gemini OAuth / Code Assist, brokered GitHub Copilot OAuth, brokered Nous Portal OAuth, brokered MiniMax OAuth, and MiniMax Token Plan have governed login or invocation bridges without browser-token import; unconfigured targets require local operator sign-in.",
        },
        {
            "control": "oauth_device_flows",
            "state": "available_login_required" if model_auth_parity["operator_login_required_targets"] else "ready_for_review",
            "detail": "Nous Portal OAuth, MiniMax OAuth, Google Gemini OAuth / Code Assist, Google Vertex AI, AWS Bedrock, Azure Foundry, and Copilot have governed bridge paths; unconfigured targets require local operator sign-in.",
        },
        {
            "control": "raw_browser_token_capture",
            "state": "denied_by_design",
            "detail": "Aegis does not accept pasted browser cookies, session tokens, or refresh tokens as subscription auth.",
        },
        {
            "control": "provider_catalog_depth",
            "state": "complete" if model_auth_parity["status"] == "target_surface_ready" else "partial",
            "detail": f"{model_auth_parity['target_provider_count']} target providers tracked against {model_auth_parity['aegis_provider_count']} current provider routes; implementation gaps: {model_auth_parity.get('implementation_gap_count', 0)}.",
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
            name = str(connector.get("name", "unknown"))
            adapters.append(
                {
                    "kind": "connector",
                    "name": name,
                    "status": "live_enabled",
                    "live_flags": live_flags,
                    "capabilities": list(_LIVE_CONNECTOR_CAPABILITIES.get(name, ())),
                    "activation": _configured_live_connector_activation(name, connector),
                    "raw_secret_values_included": False,
                }
            )
    if getattr(config.webhook, "enabled", False) and getattr(config.webhook, "outbound_enabled", False):
        adapters.append(
            {
                "kind": "channel",
                "name": "webhook",
                "status": "live_outbound_enabled",
                "capabilities": list(_LIVE_CHANNEL_CAPABILITIES["webhook"]),
                "activation": _configured_live_channel_activation("webhook"),
                "raw_secret_values_included": False,
            }
        )
    if getattr(config.email, "outbound_enabled", False):
        adapters.append(
            {
                "kind": "channel",
                "name": "email",
                "status": "live_outbound_enabled",
                "capabilities": list(_LIVE_CHANNEL_CAPABILITIES["email"]),
                "activation": _configured_live_channel_activation("email"),
                "raw_secret_values_included": False,
            }
        )
    if getattr(config.chat_webhook, "outbound_enabled", False):
        adapters.append(
            {
                "kind": "channel",
                "name": "chat_webhook",
                "status": "live_outbound_enabled",
                "capabilities": list(_LIVE_CHANNEL_CAPABILITIES["chat_webhook"]),
                "activation": _configured_live_channel_activation("chat_webhook"),
                "raw_secret_values_included": False,
            }
        )
    return adapters


def _configured_live_connector_activation(name: str, connector: dict[str, Any]) -> dict[str, Any]:
    configured_controls = ["live_enablement_flag", "redacted_receipts", "runtime_rate_limits", "rollback_receipts"]
    blockers: list[dict[str, str]] = []
    allowlist = tuple(str(item) for item in connector.get("allowlist", ()) if str(item))
    if allowlist:
        configured_controls.append("network_allowlist")
    else:
        blockers.append({"control": "network_allowlist", "detail": "at least one provider host must remain allowlisted before live writes run"})
    if name in _LIVE_CONNECTOR_TOKEN_REQUIRED:
        blockers.append({"control": "brokered_token", "detail": "a brokered provider credential must resolve for each approved live write"})
    preflight_status = "ready_for_approved_call" if not blockers else "runtime_configuration_required"
    return {
        "status": "live_enabled",
        "preflight_status": preflight_status,
        "required_controls": ["live_enablement_flag", "network_allowlist", "human_approval", "redacted_receipts"]
        + (["brokered_token"] if name in _LIVE_CONNECTOR_TOKEN_REQUIRED else []),
        "configured_controls": configured_controls,
        "blockers": blockers,
        "verification_gates": ["mock_fallback", "approved_write", "rate_limit_denial", "rollback_receipt", "receipt_redaction"],
        "next_steps": [
            f"Run one approved {name} live write against an allowlisted provider endpoint.",
            "Confirm the receipt stays redacted and rollback guidance is present before broader promotion.",
        ],
        "raw_secret_values_included": False,
    }


def _configured_live_channel_activation(name: str) -> dict[str, Any]:
    return {
        "status": "live_outbound_enabled",
        "preflight_status": "ready_for_approved_send",
        "required_controls": ["explicit_channel_config", "human_approval", "secret_broker_or_allowlist", "redacted_receipts", "activation_approval_receipt"],
        "configured_controls": ["explicit_channel_config", "redacted_receipts", "activation_approval_receipt"],
        "blockers": [],
        "verification_gates": ["activation_packet_integrity", "activation_approval_receipt", "approved_send", "receipt_redaction"],
        "next_steps": [
            f"Approve a verified {name} activation packet to record the promotion receipt.",
            f"Send one approved {name} delivery in the target environment.",
            "Confirm delivery receipts stay redacted before using the channel broadly.",
        ],
        "raw_secret_values_included": False,
    }


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
            "control": "live_browser_activation_packets",
            "state": "available_adapter_blocked" if "live_browser_activation_packets" in implemented else "pending",
            "detail": "Activation packets expose live-browser preflight controls, blockers, verification gates, and next steps while real page automation remains disabled.",
        },
        {
            "control": "playwright_chromium_adapter_preflight",
            "state": "blocked_adapter_candidate" if "playwright_chromium_adapter_preflight" in implemented else "pending",
            "detail": "Playwright/Chromium is reported as a denied-by-default candidate with runtime availability and blockers, without exposing raw executable paths.",
        },
        {
            "control": "live_browser_activation_packet_verification",
            "state": "verified_adapter_blocked" if "live_browser_activation_packet_verification" in implemented else "pending",
            "detail": "Packet verification checks adapter, isolation, redaction, and approval blockers as review evidence while denied live automation requests remain blocked separately.",
        },
        {
            "control": "live_browser_readonly_adapter",
            "state": "available_opt_in" if "approved_live_browser_readonly_adapter" in implemented else "pending",
            "detail": "Approved live_navigate and live_screenshot can capture allowlisted pages with headless Chromium, an ephemeral profile, private PNG evidence, and no raw DOM/cookie/storage return.",
        },
        {
            "control": "live_browser_selector_mutation_adapter",
            "state": "available_opt_in" if "approved_live_browser_selector_mutation_adapter" in implemented else "pending",
            "detail": "Approved live_click, live_fill, and live_submit can mutate allowlisted pages with Chromium CDP through an ephemeral profile while persistent state and raw DOM capture stay blocked.",
        },
        {
            "control": "live_browser_download_adapter",
            "state": "available_opt_in" if "approved_live_browser_download_adapter" in implemented else "pending",
            "detail": "Approved live_download can store one bounded private download artifact from an allowlisted page selector with Chromium CDP while uploads, persistent state, and raw DOM capture stay blocked.",
        },
        {
            "control": "live_browser_upload_adapter",
            "state": "available_opt_in" if "approved_live_browser_upload_adapter" in implemented else "pending",
            "detail": "Approved live_upload can attach one workspace-scoped allowlisted source file to an allowlisted page file input with Chromium CDP while persistent state, raw DOM capture, and raw source content return stay blocked.",
        },
        {
            "control": "live_browser_javascript_adapter",
            "state": "available_opt_in" if "approved_live_browser_javascript_adapter" in implemented else "pending",
            "detail": "Approved live_evaluate can run bounded JavaScript on allowlisted pages with Chromium CDP while raw DOM, cookie/storage values, network bodies, and persistent state stay blocked.",
        },
        {
            "control": "media_worker_sandbox",
            "state": "available" if {"sandboxed_media_worker_process", "os_level_media_worker_limits"}.issubset(implemented) else "partial",
            "detail": "Local media artifacts run in an isolated subprocess with OS limits where supported.",
        },
        {
            "control": "live_browser_automation",
            "state": "javascript_available_media_depth_remaining" if "approved_live_browser_javascript_adapter" in implemented else "upload_available_depth_remaining" if "approved_live_browser_upload_adapter" in implemented else "download_available_depth_remaining" if "approved_live_browser_download_adapter" in implemented else "selector_mutation_available_depth_remaining" if "approved_live_browser_selector_mutation_adapter" in implemented else "read_only_available_mutation_blocked" if "approved_live_browser_readonly_adapter" in implemented else "blocked_with_preflight" if "disabled_live_browser_denial" in implemented else "not_started",
            "detail": "Read-only live screenshot capture, approved selector click/fill/submit mutation, approved private selector downloads, approved workspace-scoped selector uploads, and approved bounded JavaScript evaluation are available when explicitly configured; persistent browser state, raw DOM capture, and raw network body capture remain blocked.",
        },
        {
            "control": "provider_media_depth",
            "state": "partial" if "provider_backed_media_artifacts" in implemented else "not_started",
            "detail": "Provider-backed image, TTS, transcription, and video job paths exist, including OpenAI-style image JSON, Stability AI v1 text-to-image JSON, Google Vertex Imagen predict JSON, multipart image edit, OpenAI-style TTS, ElevenLabs TTS, OpenAI-style audio transcription, ElevenLabs speech-to-text, and video generation adapters; additional provider-specific image/audio/video adapters still need expansion.",
        },
        {
            "control": "platform_media_sandbox_profiles",
            "state": "ready_for_review" if "platform_media_sandbox_profiles_v1" in implemented else "pending" if "stricter_platform_media_sandbox_profiles" in remaining else "ready_for_review",
            "detail": "Versioned media_sandbox_profile_v1 receipts cover local worker and allowlisted provider media boundaries.",
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
                    "required_controls": ["enable_live_writes", "network_allowlist", "human_approval", "rate_limits", "rollback_receipts", "redacted_receipts"],
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
                    "required_controls": ["explicit_channel_config", "human_approval", "secret_broker_or_allowlist", "redacted_receipts", "activation_approval_receipt"],
                    "activation": _live_channel_activation(name),
                    "raw_secret_values_included": False,
                }
            )
    return adapters


def _live_channel_activation(name: str) -> dict[str, Any]:
    return {
        "status": "live_channel_required",
        "preflight_status": "blocked",
        "required_controls": ["explicit_channel_config", "human_approval", "secret_broker_or_allowlist", "redacted_receipts", "activation_approval_receipt"],
        "configured_controls": ["redacted_receipts"],
        "blockers": [
            {"control": "explicit_channel_config", "detail": f"{name} outbound channel is not fully enabled"},
            {"control": "human_approval", "detail": f"{name} outbound sends require approval before delivery"},
            {"control": "secret_broker_or_allowlist", "detail": f"{name} credentials or provider target must be brokered and allowlisted"},
            {"control": "activation_approval_receipt", "detail": f"{name} activation requires a verified packet approval receipt before promotion"},
        ],
        "verification_gates": ["disabled_channel_denial", "activation_packet_integrity", "activation_approval_receipt", "approved_send", "receipt_redaction"],
        "next_steps": [
            f"Configure only the scoped outbound {name} channel needed for the deployment.",
            "Create, verify, and approve a private activation packet without sending a probe payload.",
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
            "detail": "High-impact live writes and sends remain approval-gated before execution; channel sends require payload-bound approval ids rather than standalone approved booleans.",
        },
        {
            "control": "receipt_redaction",
            "state": "enforced",
            "detail": "Live connector receipts expose operation summaries and hashes, not raw secret values.",
        },
        {
            "control": "runtime_rate_limits",
            "state": "partial",
            "detail": "Generic REST, GitHub, GitLab, service-desk, Microsoft Graph, messaging live writes, and outbound channel sends enforce in-memory per-operation rate limits; remaining live adapters must add provider-specific limits before promotion.",
        },
        {
            "control": "rollback_receipts",
            "state": "partial",
            "detail": "GitHub/GitLab issue and comment rollbacks, service-desk close-ticket rollbacks, Microsoft Graph calendar/contact rollbacks, and messaging rollback_message actions expose approved redacted rollback receipts; remaining live adapters still require provider-specific rollback paths.",
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
        {
            "control": "channel_activation_approval_receipt",
            "state": "available",
            "detail": "Verified channel activation packets can be explicitly approved with a no-send receipt before any live delivery probe or broader promotion.",
        },
    ]


_LIVE_CONNECTOR_CAPABILITIES = {
    "github": ("issue_comment_write", "issue_create"),
    "gitlab": ("issue_note_write", "merge_request_note_write"),
    "generic_rest": ("https_rest_write",),
    "mock_graph": ("calendar_write", "email_write", "contact_write"),
    "mock_servicenow": ("ticket_write",),
    "mock_messaging": ("message_send", "message_rollback"),
}


_LIVE_CONNECTOR_TOKEN_REQUIRED = {"github", "gitlab", "mock_graph", "mock_servicenow", "mock_messaging"}


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
            "persistent": bool(backend.get("persistent")),
            "capabilities": list(_LIVE_BACKEND_CAPABILITIES.get(str(backend.get("name", "")), ())),
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


def _remote_backend_operator_checklist(
    implemented_backends: list[dict[str, Any]],
    available_backends: list[dict[str, Any]],
    processes: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    process_controls = set((processes or {}).get("implemented_controls", []))
    return [
        {
            "control": "local_background_process_registry",
            "state": "enforced" if {"approval_required_start", "private_redacted_logs", "stop_receipts", "interactive_pty_attach", "stdin_streaming", "terminal_resize_events"}.issubset(process_controls) else "pending",
            "detail": "Local background processes use argv-only execution, executable allowlists, explicit approval, private redacted logs, PTY attach, stdin streaming, resize receipts, and stop receipts.",
        },
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
            "detail": f"{len(implemented_backends)} nonlocal backends enabled; {len(available_backends)} opt-in adapters still available. Hosted sandbox adapters expose generic status, logs, cancel, artifact, and rollback lifecycle requests when configured.",
        },
    ]


_LIVE_BACKEND_CAPABILITIES = {
    "docker": ("container_limits", "network_none", "cleanup_receipt"),
    "ssh": ("brokered_private_key", "allowlisted_hosts", "temporary_key_cleanup"),
    "modal": ("hosted_sandbox_submission", "hosted_sandbox_lifecycle", "brokered_token", "allowlisted_https_api"),
    "daytona": ("hosted_sandbox_submission", "hosted_sandbox_lifecycle", "brokered_token", "allowlisted_https_api"),
    "vercel_sandbox": ("hosted_sandbox_submission", "hosted_sandbox_lifecycle", "brokered_token", "allowlisted_https_api"),
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
    checkpoint = _decode_checkpoint_json(row.get("checkpoint_json"))
    task = {
        "id": row["id"],
        "user_request": row["user_request"],
        "interpretation": row["interpretation"],
        "status": row["status"],
        "risk_level": row["risk_level"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "action_hints": _task_action_hints(row.get("id"), row.get("session_id"), status=row.get("status"), checkpoint=checkpoint),
    }
    if row.get("session_id"):
        task["session_id"] = row["session_id"]
        session = _session_summary(orchestrator, str(row["session_id"]))
        if session:
            task["session"] = session
    return task


def _task_action_hints(task_id: Any, session_id: Any, *, status: Any, checkpoint: dict[str, Any] | None = None) -> list[dict[str, str]]:
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
    if isinstance(checkpoint, dict):
        hints.extend(subagent_review_action_hints(checkpoint))
    return hints


def _decode_checkpoint_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        return {}
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


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
