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
    pending_approvals = [approval for approval in approvals if approval["status"] == "pending"]
    tasks = [_decode_task(row) for row in orchestrator.store.list_tasks(limit=12)]
    audit_chain_ok = orchestrator.audit_logger.verify_chain()

    high_risk_tools = [tool for tool in tools if tool["risk_level"] in {"high", "critical"}]
    approval_tools = [tool for tool in tools if tool["approval_required"]]
    configured_providers = [provider for provider in providers if provider["auth_configured"] or provider["local"]]

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
            "execution_backends": len(backends),
            "model_providers": len(providers),
            "configured_or_local_providers": len(configured_providers),
            "sessions": len(sessions),
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
                "name": "Execution backends",
                "state": "policy_visible",
                "coverage": f"{len(backends)} backend definitions",
                "detail": "Local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox are represented for policy decisions.",
            },
        ],
        "competitive_targets": [
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
                ],
                "security_delta": "Aegis defaults to mock or dry-run mode for broad-access capabilities until credentials, scopes, rollback, and approvals are explicit.",
                "live_gap": "Mobile nodes, native desktop wrappers, and live third-party channel implementations remain staged behind secure adapter work.",
            },
        ],
        "recent_tasks": tasks,
        "pending_approvals": pending_approvals[:12],
    }


def _decode_task(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "user_request": row["user_request"],
        "interpretation": row["interpretation"],
        "status": row["status"],
        "risk_level": row["risk_level"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
