"""Aegis Agent command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys
from typing import Any

from aegis.api.server import serve
from aegis.agent.orchestrator import build_orchestrator
from aegis.approvals.manager import ApprovalManager
from aegis.audit.logger import AuditLogger
from aegis.channels.registry import ChannelRegistry
from aegis.config.loader import load_config, write_default_config
from aegis.connectors.registry import build_default_registry
from aegis.execution.backends import ExecutionBackendRegistry
from aegis.kanban.manager import KanbanManager
from aegis.memory.manager import MemoryManager
from aegis.memory.models import MemoryType
from aegis.memory.store import LocalStore
from aegis.mcp.registry import McpRegistry
from aegis.migration.openclaw import inspect_hermes_home, inspect_openclaw_home
from aegis.models.registry import ModelRegistry
from aegis.personality.context import ContextFileLoader, PERSONALITY_NAMES
from aegis.scheduler.manager import ScheduleManager
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import Sensitivity
from aegis.sessions.manager import SessionManager
from aegis.skills.manifest import SkillManifest
from aegis.skills.hub import SkillHubCatalog
from aegis.skills.registry import SkillRegistry
from aegis.tools.catalog import ToolCatalog
from aegis.tui.main import run_tui


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = dispatch(args)
    except Exception as exc:  # noqa: BLE001 - CLI should show concise actionable errors.
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 1
    if result is not None:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis Agent local-first runtime")
    parser.add_argument("--data-dir", default=".aegis", help="Aegis data directory")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("init", help="Create default local configuration")
    subcommands.add_parser("health", help="Show local runtime health")
    server = subcommands.add_parser("serve", help="Run the local development API server")
    server.add_argument("--workspace", default=".")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    tui = subcommands.add_parser("tui", help="Run the interactive terminal UI")
    tui.add_argument("--workspace", default=".")

    task = subcommands.add_parser("task", help="Submit and inspect tasks")
    task_sub = task.add_subparsers(dest="task_command", required=True)
    task_submit = task_sub.add_parser("submit", help="Submit a task")
    task_submit.add_argument("request", help="User request")
    task_submit.add_argument("--workspace", default=".", help="Workspace root for scoped connectors")
    task_submit.add_argument("--path", help="Optional path for filesystem tasks")
    task_status = task_sub.add_parser("status", help="Show task status")
    task_status.add_argument("task_id")
    task_status.add_argument("--workspace", default=".")
    task_resume = task_sub.add_parser("resume", help="Resume a task after approval")
    task_resume.add_argument("task_id")
    task_resume.add_argument("--workspace", default=".")
    task_evidence = task_sub.add_parser("evidence", help="Show a task evidence bundle")
    task_evidence.add_argument("task_id")
    task_evidence.add_argument("--workspace", default=".")

    session = subcommands.add_parser("session", help="Manage conversation sessions")
    session_sub = session.add_subparsers(dest="session_command", required=True)
    session_create = session_sub.add_parser("create", help="Create a session")
    session_create.add_argument("title")
    session_create.add_argument("--channel", default="terminal")
    session_create.add_argument("--model")
    session_create.add_argument("--personality")
    session_list = session_sub.add_parser("list", help="List sessions")
    session_list.add_argument("--limit", type=int, default=50)
    session_history = session_sub.add_parser("history", help="Show session history")
    session_history.add_argument("session_id")

    approval = subcommands.add_parser("approval", help="Manage approval queue")
    approval_sub = approval.add_subparsers(dest="approval_command", required=True)
    approval_list = approval_sub.add_parser("list", help="List approvals")
    approval_list.add_argument("--status")
    approval_approve = approval_sub.add_parser("approve", help="Approve a request")
    approval_approve.add_argument("approval_id")
    approval_deny = approval_sub.add_parser("deny", help="Deny a request")
    approval_deny.add_argument("approval_id")

    memory = subcommands.add_parser("memory", help="Inspect and edit governed memory")
    memory_sub = memory.add_subparsers(dest="memory_command", required=True)
    memory_create = memory_sub.add_parser("create", help="Create a memory")
    memory_create.add_argument("type", choices=[item.value for item in MemoryType])
    memory_create.add_argument("content")
    memory_create.add_argument("--source", default="cli")
    memory_create.add_argument("--confidence", type=float, default=0.8)
    memory_create.add_argument("--sensitivity", choices=[item.value for item in Sensitivity], default=Sensitivity.INTERNAL.value)
    memory_create.add_argument("--tag", action="append", default=[])
    memory_create.add_argument("--confirmed", action="store_true")
    memory_search = memory_sub.add_parser("search", help="Search memory")
    memory_search.add_argument("query")
    memory_update = memory_sub.add_parser("update", help="Update a memory")
    memory_update.add_argument("memory_id")
    memory_update.add_argument("--content")
    memory_update.add_argument("--confidence", type=float)
    memory_update.add_argument("--confirmed", action="store_true")
    memory_delete = memory_sub.add_parser("delete", help="Delete a memory")
    memory_delete.add_argument("memory_id")

    skill = subcommands.add_parser("skill", help="Manage governed skills")
    skill_sub = skill.add_subparsers(dest="skill_command", required=True)
    skill_sub.add_parser("list", help="List skills")
    skill_hub = skill_sub.add_parser("hub-search", help="Search the virtual skill hub safely")
    skill_hub.add_argument("query", nargs="?", default="")
    skill_create = skill_sub.add_parser("create", help="Create a disabled skill manifest template")
    skill_create.add_argument("skill_id")
    skill_create.add_argument("--name", required=True)
    skill_create.add_argument("--description", required=True)
    skill_create.add_argument("--output", help="Optional path to write the manifest JSON")
    skill_register = skill_sub.add_parser("register", help="Register a skill manifest JSON file")
    skill_register.add_argument("manifest_path")
    skill_register.add_argument("--enable", action="store_true")
    skill_disable = skill_sub.add_parser("disable", help="Disable a skill")
    skill_disable.add_argument("skill_id")

    connector = subcommands.add_parser("connector", help="List connector status")
    connector_sub = connector.add_subparsers(dest="connector_command", required=True)
    connector_sub.add_parser("list", help="List connectors")
    connector_sub.add_parser("status", help="Show connector health")

    channels = subcommands.add_parser("channel", help="Inspect and test channel adapters")
    channel_sub = channels.add_subparsers(dest="channel_command", required=True)
    channel_sub.add_parser("list", help="List channels")
    channel_sub.add_parser("status", help="Show channel health")
    channel_receive = channel_sub.add_parser("receive", help="Normalize an inbound channel message")
    channel_receive.add_argument("channel")
    channel_receive.add_argument("text")
    channel_receive.add_argument("--sender", default="local-user")

    models = subcommands.add_parser("model", help="Manage model routes and usage")
    model_sub = models.add_subparsers(dest="model_command", required=True)
    model_sub.add_parser("list", help="List supported models")
    model_sub.add_parser("providers", help="List model providers and auth status")
    model_route = model_sub.add_parser("route", help="Resolve a model identifier or alias")
    model_route.add_argument("identifier")
    model_alias = model_sub.add_parser("alias", help="Set a model alias")
    model_alias.add_argument("alias")
    model_alias.add_argument("identifier")
    model_auth = model_sub.add_parser("auth", help="Manage model provider auth")
    model_auth_sub = model_auth.add_subparsers(dest="auth_command", required=True)
    model_auth_status = model_auth_sub.add_parser("status", help="Show model provider auth status")
    model_auth_status.add_argument("provider", nargs="?")
    model_auth_login = model_auth_sub.add_parser("login", help="Store a model provider API key in the local secret store")
    model_auth_login.add_argument("provider", choices=("openai", "openrouter"))
    model_auth_login.add_argument("--api-key", help="API key value. Prefer --api-key-stdin or interactive entry.")
    model_auth_login.add_argument("--api-key-stdin", action="store_true", help="Read API key from stdin")
    model_auth_logout = model_auth_sub.add_parser("logout", help="Remove a model provider API key from the local secret store")
    model_auth_logout.add_argument("provider", choices=("openai", "openrouter"))
    model_sub.add_parser("usage", help="Show usage summary")

    tools = subcommands.add_parser("tool", help="List built-in tools")
    tool_sub = tools.add_subparsers(dest="tool_command", required=True)
    tool_sub.add_parser("list", help="List tools")

    backend = subcommands.add_parser("backend", help="List execution backends")
    backend_sub = backend.add_subparsers(dest="backend_command", required=True)
    backend_sub.add_parser("list", help="List execution backends")

    schedule = subcommands.add_parser("schedule", help="Manage scheduled automations")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    schedule_create = schedule_sub.add_parser("create", help="Create a paused schedule")
    schedule_create.add_argument("name")
    schedule_create.add_argument("cron")
    schedule_create.add_argument("task_request")
    schedule_create.add_argument("--natural-language", default="")
    schedule_create.add_argument("--channel", default="terminal")
    schedule_sub.add_parser("list", help="List schedules")

    kanban = subcommands.add_parser("kanban", help="Manage work boards")
    kanban_sub = kanban.add_subparsers(dest="kanban_command", required=True)
    board_create = kanban_sub.add_parser("board-create", help="Create a board")
    board_create.add_argument("name")
    kanban_sub.add_parser("boards", help="List boards")
    card_add = kanban_sub.add_parser("card-add", help="Add a card")
    card_add.add_argument("board_id")
    card_add.add_argument("title")
    card_add.add_argument("description")
    card_add.add_argument("--lane", default="backlog")
    card_list = kanban_sub.add_parser("cards", help="List cards")
    card_list.add_argument("board_id")
    card_move = kanban_sub.add_parser("card-move", help="Move a card")
    card_move.add_argument("card_id")
    card_move.add_argument("lane")

    mcp = subcommands.add_parser("mcp", help="Manage governed MCP server registrations")
    mcp_sub = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_register = mcp_sub.add_parser("register", help="Register an MCP server disabled by default")
    mcp_register.add_argument("name")
    mcp_register.add_argument("server_command")
    mcp_register.add_argument("--tool", action="append", default=[])
    mcp_sub.add_parser("list", help="List MCP servers")

    personality = subcommands.add_parser("personality", help="Inspect built-in personalities and context files")
    personality_sub = personality.add_subparsers(dest="personality_command", required=True)
    personality_sub.add_parser("list", help="List built-in personalities")
    personality_load = personality_sub.add_parser("context", help="Load SOUL/AGENTS/TOOLS context files safely")
    personality_load.add_argument("--workspace", default=".")

    migrate = subcommands.add_parser("migrate", help="Dry-run migration inspections")
    migrate_sub = migrate.add_subparsers(dest="migrate_command", required=True)
    migrate_openclaw = migrate_sub.add_parser("openclaw", help="Inspect an OpenClaw home directory")
    migrate_openclaw.add_argument("path")
    migrate_hermes = migrate_sub.add_parser("hermes", help="Inspect a Hermes home directory")
    migrate_hermes.add_argument("path")

    audit = subcommands.add_parser("audit", help="Inspect audit logs")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_log = audit_sub.add_parser("log", help="Tail audit log")
    audit_log.add_argument("--limit", type=int, default=20)
    audit_sub.add_parser("verify", help="Verify audit hash chain")

    return parser


def dispatch(args: argparse.Namespace) -> dict[str, Any] | None:
    config = load_config(args.data_dir)
    if args.command == "init":
        path = write_default_config(args.data_dir)
        store = LocalStore(config.database_path)
        audit = AuditLogger(config.audit_log_path)
        audit.append("runtime.initialized", {"config": str(path), "database": str(store.database_path)})
        return {"ok": True, "config": str(path), "database": str(store.database_path), "audit_log": str(audit.path)}

    if args.command == "health":
        store = LocalStore(config.database_path)
        audit = AuditLogger(config.audit_log_path)
        connectors = build_default_registry(config, audit)
        return {"ok": True, "data_dir": str(config.data_dir), "database": str(store.database_path), "audit_chain_ok": audit.verify_chain(), "connectors": connectors.status()}

    if args.command == "serve":
        serve(data_dir=args.data_dir, workspace=args.workspace, host=args.host, port=args.port)
        return None

    if args.command == "tui":
        run_tui(data_dir=args.data_dir, workspace=args.workspace)
        return None

    if args.command == "task":
        orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=getattr(args, "workspace", "."))
        if args.task_command == "submit":
            return orchestrator.submit_task(args.request, path=args.path)
        if args.task_command == "status":
            return orchestrator.status(args.task_id)
        if args.task_command == "resume":
            return orchestrator.resume_task(args.task_id)
        if args.task_command == "evidence":
            return orchestrator.evidence.build(args.task_id)

    if args.command == "session":
        manager = _session_manager(config)
        if args.session_command == "create":
            return manager.create_session(title=args.title, channel=args.channel, model=args.model, personality=args.personality)
        if args.session_command == "list":
            return {"sessions": manager.list_sessions(limit=args.limit)}
        if args.session_command == "history":
            return {"messages": manager.history(args.session_id)}

    if args.command == "approval":
        manager = _approval_manager(config)
        if args.approval_command == "list":
            return {"approvals": manager.list(status=args.status)}
        if args.approval_command == "approve":
            return manager.approve(args.approval_id)
        if args.approval_command == "deny":
            return manager.deny(args.approval_id)

    if args.command == "memory":
        manager = _memory_manager(config)
        if args.memory_command == "create":
            record = manager.create_memory(
                memory_type=MemoryType(args.type),
                content=args.content,
                source=args.source,
                provenance={"cli": True},
                confidence=args.confidence,
                sensitivity=Sensitivity(args.sensitivity),
                tags=tuple(args.tag),
                confirmed=args.confirmed,
            )
            return record.to_row()
        if args.memory_command == "search":
            return {"memories": manager.retrieve_relevant(args.query)}
        if args.memory_command == "update":
            return manager.update_memory(args.memory_id, content=args.content, confidence=args.confidence, confirmed=args.confirmed)
        if args.memory_command == "delete":
            manager.delete_memory(args.memory_id)
            return {"ok": True, "deleted": args.memory_id}

    if args.command == "skill":
        registry = _skill_registry(config)
        if args.skill_command == "list":
            return {"skills": registry.list()}
        if args.skill_command == "hub-search":
            return SkillHubCatalog().search(args.query)
        if args.skill_command == "create":
            manifest = create_skill_template(args.skill_id, name=args.name, description=args.description)
            if args.output:
                Path(args.output).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                return {"ok": True, "path": args.output, "manifest": manifest}
            return {"manifest": manifest}
        if args.skill_command == "register":
            raw = json.loads(Path(args.manifest_path).read_text(encoding="utf-8"))
            manifest = registry.register(SkillManifest.from_dict(raw), enable=args.enable)
            return manifest.to_dict()
        if args.skill_command == "disable":
            registry.disable(args.skill_id)
            return {"ok": True, "disabled": args.skill_id}

    if args.command == "connector":
        audit = AuditLogger(config.audit_log_path)
        connectors = build_default_registry(config, audit)
        if args.connector_command == "list":
            return {"connectors": connectors.list()}
        if args.connector_command == "status":
            return {"connectors": connectors.status()}

    if args.command == "channel":
        registry = _channel_registry(config)
        if args.channel_command == "list":
            return {"channels": registry.list_channels()}
        if args.channel_command == "status":
            return {"channels": registry.status()}
        if args.channel_command == "receive":
            message = registry.receive(args.channel, {"sender": args.sender, "text": args.text})
            return {"message": message.__dict__}

    if args.command == "model":
        registry = _model_registry(config)
        if args.model_command == "list":
            return {"models": registry.list_models()}
        if args.model_command == "providers":
            return {"providers": registry.list_providers()}
        if args.model_command == "route":
            route = registry.route(args.identifier)
            return {"identifier": route.identifier, "provider": route.provider.provider, "model": route.model, "fallbacks": list(route.fallback_identifiers), "secret_handle_id": route.secret_handle_id}
        if args.model_command == "alias":
            registry.set_alias(args.alias, args.identifier)
            return {"ok": True, "alias": args.alias, "identifier": args.identifier}
        if args.model_command == "auth":
            if args.auth_command == "status":
                return {"auth": registry.auth_status(args.provider)}
            if args.auth_command == "login":
                status = registry.login_provider(args.provider, _read_api_key(args))
                return {"ok": True, "auth": status}
            if args.auth_command == "logout":
                status = registry.logout_provider(args.provider)
                return {"ok": True, "auth": status}
        if args.model_command == "usage":
            return registry.usage_summary()

    if args.command == "tool":
        if args.tool_command == "list":
            return {"tools": ToolCatalog().list()}

    if args.command == "backend":
        if args.backend_command == "list":
            return {"backends": ExecutionBackendRegistry().list()}

    if args.command == "schedule":
        manager = _schedule_manager(config)
        if args.schedule_command == "create":
            return manager.create_schedule(
                name=args.name,
                natural_language=args.natural_language or args.task_request,
                cron=args.cron,
                task_request=args.task_request,
                channel=args.channel,
            )
        if args.schedule_command == "list":
            return {"schedules": manager.list_schedules()}

    if args.command == "kanban":
        manager = _kanban_manager(config)
        if args.kanban_command == "board-create":
            return manager.create_board(args.name)
        if args.kanban_command == "boards":
            return {"boards": manager.list_boards()}
        if args.kanban_command == "card-add":
            return manager.add_card(args.board_id, title=args.title, description=args.description, lane=args.lane)
        if args.kanban_command == "cards":
            return {"cards": manager.list_cards(args.board_id)}
        if args.kanban_command == "card-move":
            manager.move_card(args.card_id, args.lane)
            return {"ok": True, "card_id": args.card_id, "lane": args.lane}

    if args.command == "mcp":
        registry = _mcp_registry(config)
        if args.mcp_command == "register":
            return registry.register_server(name=args.name, command=args.server_command, allowed_tools=tuple(args.tool))
        if args.mcp_command == "list":
            return {"servers": registry.list_servers()}

    if args.command == "personality":
        if args.personality_command == "list":
            return {"personalities": list(PERSONALITY_NAMES)}
        if args.personality_command == "context":
            loader = ContextFileLoader(args.workspace)
            return {"items": [item.to_dict() for item in loader.load()]}

    if args.command == "migrate":
        if args.migrate_command == "openclaw":
            return inspect_openclaw_home(args.path)
        if args.migrate_command == "hermes":
            return inspect_hermes_home(args.path)

    if args.command == "audit":
        audit = AuditLogger(config.audit_log_path)
        if args.audit_command == "log":
            return {"events": audit.tail(args.limit)}
        if args.audit_command == "verify":
            return {"ok": audit.verify_chain()}

    raise ValueError("unhandled command")


def _approval_manager(config: Any) -> ApprovalManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return ApprovalManager(store, audit)


def _memory_manager(config: Any) -> MemoryManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return MemoryManager(store, audit)


def _skill_registry(config: Any) -> SkillRegistry:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return SkillRegistry(store, audit)


def _session_manager(config: Any) -> SessionManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return SessionManager(store, audit)


def _channel_registry(config: Any) -> ChannelRegistry:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return ChannelRegistry(store, audit)


def _model_registry(config: Any) -> ModelRegistry:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return ModelRegistry(store, audit, SecretsBroker(config.secrets_path))


def _read_api_key(args: argparse.Namespace) -> str:
    if getattr(args, "api_key", None) and getattr(args, "api_key_stdin", False):
        raise ValueError("use either --api-key or --api-key-stdin, not both")
    if getattr(args, "api_key", None):
        return str(args.api_key)
    if getattr(args, "api_key_stdin", False):
        return sys.stdin.read().strip()
    return getpass.getpass(f"{args.provider} API key: ").strip()


def _schedule_manager(config: Any) -> ScheduleManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return ScheduleManager(store, audit)


def _kanban_manager(config: Any) -> KanbanManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return KanbanManager(store, audit)


def _mcp_registry(config: Any) -> McpRegistry:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return McpRegistry(store, audit)


def create_skill_template(skill_id: str, *, name: str, description: str) -> dict[str, Any]:
    return {
        "id": skill_id,
        "name": name,
        "description": description,
        "version": "0.1.0",
        "author": "local-user",
        "source": "cli-generated",
        "permissions": {},
        "connectors": [],
        "secrets": [],
        "network": {},
        "filesystem": {},
        "commands": [],
        "input_schema": {"type": "object"},
        "output_schema": {"type": "object"},
        "risk_level": "medium",
        "approval_required": True,
        "sandbox_profile": "no_tools",
        "tests": [],
        "evals": [],
        "rollback": "Disable or delete the skill.",
        "changelog": ["Created disabled template."],
    }


if __name__ == "__main__":
    raise SystemExit(main())
