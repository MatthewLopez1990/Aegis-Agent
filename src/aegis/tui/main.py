"""Dependency-free terminal UI for Aegis Agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import cmd
import getpass
import hashlib
import json
import os
import shlex
import shutil
import sys
import textwrap

from aegis.agent.orchestrator import build_orchestrator
from aegis.approvals.models import ApprovalRequest
from aegis.channels.base import ChannelResponse
from aegis.memory.models import MemoryType
from aegis.migration.openclaw import inspect_hermes_home, inspect_openclaw_home, preview_hermes_memory_import, preview_openclaw_memory_import
from aegis.product.capabilities import build_product_dashboard
from aegis.research.harness import ResearchHarness
from aegis.security.policy_engine import PolicyRequest
from aegis.security.policy_profile import activate_due_policy_rollouts, apply_policy_bundle, diff_policy_bundle, import_policy_bundle, list_policy_bundles, list_policy_promotions, list_policy_rollouts, policy_profile_to_dict, promote_policy_bundle, rollback_policy_bundle, schedule_policy_bundle
from aegis.security.taint import RiskLevel, Sensitivity, TrustClass


TOP_LEVEL_COMMANDS = (
    "approval",
    "approvals",
    "audit",
    "backends",
    "boards",
    "browser",
    "cancel",
    "capabilities",
    "channel",
    "channels",
    "connectors",
    "dashboard",
    "deny",
    "evidence",
    "events",
    "evaluation",
    "exit",
    "help",
    "mcp",
    "memory",
    "menu",
    "menus",
    "migrate",
    "models",
    "pause",
    "repair",
    "repairs",
    "resume",
    "schedule",
    "schedules",
    "security",
    "session",
    "sessions",
    "skills",
    "status",
    "submit",
    "tasks",
    "timeline",
    "tools",
)
MEMORY_COMMANDS = ("search", "session-preview", "session-commit", "create", "review-queue", "review-digest", "review-action", "review-batch", "recertify", "update", "merge", "resolve-conflict", "expire", "cleanup-expired", "explain", "export", "delete")
MIGRATE_COMMANDS = ("openclaw", "hermes", "openclaw-memory-preview", "hermes-memory-preview", "openclaw-memory-commit", "hermes-memory-commit")
MODEL_COMMANDS = ("list", "route", "alias", "fallbacks", "usage", "auth", "providers")
MODEL_AUTH_COMMANDS = ("login", "logout")
TOOLS_COMMANDS = ("run",)
SKILLS_COMMANDS = ("hub", "disable", "enable")
REPAIR_COMMANDS = ("readiness", "review", "approve", "reject", "candidate", "generate-candidate", "synthesis-prompt", "synthesize-candidate", "review-candidate", "apply-candidate", "rollback-candidate", "attempt")
SCHEDULE_COMMANDS = ("create", "memory-review-digest", "memory-review-escalation", "evaluation-run", "evaluation-suite", "due", "approve", "activate", "pause", "run-due")
BROWSER_COMMANDS = ("session", "sessions", "close", "navigate", "extract", "inspect", "table", "screenshot", "render", "click", "fill")
MCP_COMMANDS = ("list", "register", "call")
SESSION_COMMANDS = ("new", "open", "rename", "set-model", "set-personality", "activate", "archive", "pause", "append", "history", "tasks", "compact")
TASKS_COMMANDS = ("all", "session")
SECURITY_COMMANDS = (
    "profile",
    "bundles",
    "import-bundle",
    "diff-bundle",
    "apply-bundle",
    "schedule-bundle",
    "activate-due",
    "promote-bundle",
    "promotions",
    "rollouts",
    "rollback-bundle",
    "evaluate",
)
CHANNEL_COMMANDS = ("render", "receive", "send-webhook", "send-email", "events")
EVALUATION_COMMANDS = ("queue", "review", "trends", "delta", "readiness")
TUI_HISTORY_LIMIT = 1000


class AegisTui(cmd.Cmd):
    """Small but product-facing command deck built on the stdlib cmd loop."""

    def __init__(
        self,
        *,
        data_dir: str | Path,
        workspace: str | Path,
        session_id: str | None = None,
        model: str | None = None,
        personality: str | None = None,
    ) -> None:
        super().__init__()
        self.workspace = Path(workspace).expanduser().resolve()
        self.orchestrator = build_orchestrator(data_dir=data_dir, workspace=workspace)
        self.history_path = self.orchestrator.config.data_dir / "tui_history"
        self.session = self._load_or_create_session(
            workspace=workspace,
            session_id=session_id,
            model=model,
            personality=personality,
        )
        self.last_task_id: str | None = None
        self.browser_session_id: str | None = None
        self.prompt = _paint("aegis> ", "36;1")
        self.intro = self._render_dashboard()

    def preloop(self) -> None:
        _load_tui_history(self.history_path)

    def postloop(self) -> None:
        _save_tui_history(self.history_path)

    def completenames(self, text: str, *ignored: Any) -> list[str]:
        return _complete_options(TOP_LEVEL_COMMANDS, text)

    def completedefault(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        stripped = line.lstrip()
        if stripped.startswith("/"):
            slash_text = stripped[1:] if begidx <= 1 else text
            return [f"/{name}" for name in _complete_options(TOP_LEVEL_COMMANDS, slash_text)]
        return []

    def complete_memory(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(MEMORY_COMMANDS, text, line, begidx)

    def complete_migrate(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(MIGRATE_COMMANDS, text, line, begidx)

    def complete_models(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        parts = shlex.split(line[:begidx])
        if len(parts) >= 2 and parts[1] == "auth":
            return _complete_options(MODEL_AUTH_COMMANDS, text)
        return _complete_subcommand(MODEL_COMMANDS, text, line, begidx)

    def complete_repair(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(REPAIR_COMMANDS, text, line, begidx)

    def complete_schedule(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(SCHEDULE_COMMANDS, text, line, begidx)

    def complete_browser(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(BROWSER_COMMANDS, text, line, begidx)

    def complete_mcp(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(MCP_COMMANDS, text, line, begidx)

    def complete_session(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(SESSION_COMMANDS, text, line, begidx)

    def complete_tasks(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(TASKS_COMMANDS, text, line, begidx)

    def complete_security(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(SECURITY_COMMANDS, text, line, begidx)

    def complete_channel(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(CHANNEL_COMMANDS, text, line, begidx)

    def complete_evaluation(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(EVALUATION_COMMANDS, text, line, begidx)

    def complete_tools(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(TOOLS_COMMANDS, text, line, begidx)

    def complete_skills(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(SKILLS_COMMANDS, text, line, begidx)

    def do_dashboard(self, arg: str) -> None:
        """dashboard -- show runtime, security, and capability posture."""
        print(self._render_dashboard())

    def do_submit(self, arg: str) -> None:
        """submit <request> -- submit a governed task."""
        request = arg.strip()
        if not request:
            print("request required")
            return
        result = self.orchestrator.submit_task(request, session_id=self.session["id"])
        self.last_task_id = result["id"]
        _print_task_result(result)

    def do_status(self, arg: str) -> None:
        """status [task_id] -- show task status."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        try:
            _print_task_result(self.orchestrator.status(task_id))
        except KeyError:
            print(f"task not found: {task_id}")

    def do_resume(self, arg: str) -> None:
        """resume [task_id] -- resume after approval."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        try:
            task = self.orchestrator.status(task_id)
            resume_session_id = task.get("session_id") or self.session["id"]
            result = self.orchestrator.resume_task(task_id, session_id=resume_session_id)
            if result.get("session_id") and result["session_id"] != self.session.get("id"):
                self.session = self.orchestrator.sessions.get_session(result["session_id"])
                print(_paint(f"active session switched to {self.session['id']}", "33;1"))
        except KeyError:
            print(f"task not found: {task_id}")
            return
        except PermissionError as exc:
            print(f"resume blocked: {exc}")
            return
        _print_task_result(result)

    def do_pause(self, arg: str) -> None:
        """pause [task_id] [reason] -- pause a non-terminal task."""
        parts = shlex.split(arg)
        task_id = parts[0] if parts else self.last_task_id
        reason = " ".join(parts[1:]) if parts else ""
        if not task_id:
            print("no task id")
            return
        try:
            task = self.orchestrator.status(task_id)
            pause_session_id = task.get("session_id") or self.session["id"]
            result = self.orchestrator.pause_task(task_id, session_id=pause_session_id, actor="tui-user", reason=reason)
        except KeyError:
            print(f"task not found: {task_id}")
            return
        except PermissionError as exc:
            print(f"pause blocked: {exc}")
            return
        _print_task_result(result)

    def do_cancel(self, arg: str) -> None:
        """cancel [task_id] [reason] -- cancel a non-terminal task."""
        parts = shlex.split(arg)
        task_id = parts[0] if parts else self.last_task_id
        reason = " ".join(parts[1:]) if parts else ""
        if not task_id:
            print("no task id")
            return
        try:
            task = self.orchestrator.status(task_id)
            cancel_session_id = task.get("session_id") or self.session["id"]
            result = self.orchestrator.cancel_task(task_id, session_id=cancel_session_id, actor="tui-user", reason=reason)
        except KeyError:
            print(f"task not found: {task_id}")
            return
        except PermissionError as exc:
            print(f"cancel blocked: {exc}")
            return
        _print_task_result(result)

    def do_tasks(self, arg: str) -> None:
        """tasks [all|session <session_id>] [--limit N] -- show recent task history."""
        parts = shlex.split(arg)
        limit = int(_option_value(parts, "--limit") or "12")
        positional = _positional_without_flags(parts, {"--limit": 1})
        session_id = self.session["id"]
        if positional and positional[0] == "all":
            session_id = None
        elif len(positional) >= 2 and positional[0] == "session":
            session_id = positional[1]
        rows = [_task_list_row(self.orchestrator, row) for row in self.orchestrator.store.list_tasks(limit=limit, session_id=session_id)]
        print(
            _table(
                rows,
                (
                    ("id", "short_id", 10),
                    ("status", "status", 18),
                    ("risk", "risk_level", 10),
                    ("session", "session_label", 20),
                    ("next", "next_actions", 160),
                    ("request", "user_request", 52),
                    ("updated", "updated_at", 22),
                ),
            )
        )

    def do_session(self, arg: str) -> None:
        """session [new|rename|set-model|set-personality|activate|archive|pause|append|history|tasks|compact] -- manage active session."""
        parts = shlex.split(arg)
        if parts:
            action = parts[0]
            if action == "new" and len(parts) > 1:
                channel = _option_value(parts, "--channel") or "terminal"
                model = _option_value(parts, "--model")
                personality = _option_value(parts, "--personality")
                title_parts = _positional_without_flags(parts[1:], {"--channel": 1, "--model": 1, "--personality": 1})
                if not title_parts:
                    print("session title required")
                    return
                self.session = self.orchestrator.sessions.create_session(
                    title=" ".join(title_parts),
                    channel=channel,
                    model=model,
                    personality=personality,
                )
                _print_json(self.session)
                return
            if action == "open" and len(parts) == 2:
                self.session = self.orchestrator.sessions.get_session(parts[1])
                _print_json(self.session)
                return
            if action == "rename" and len(parts) > 1:
                self.session = self.orchestrator.sessions.update_session(self.session["id"], title=" ".join(parts[1:]))
                _print_json(self.session)
                return
            if action == "set-model" and len(parts) == 2:
                self.session = self.orchestrator.sessions.update_session(self.session["id"], model=parts[1])
                _print_json(self.session)
                return
            if action == "set-personality" and len(parts) == 2:
                self.session = self.orchestrator.sessions.update_session(self.session["id"], personality=parts[1])
                _print_json(self.session)
                return
            if action in {"activate", "archive", "pause"} and len(parts) == 1:
                status = "active" if action == "activate" else "archived" if action == "archive" else "paused"
                self.session = self.orchestrator.sessions.update_session(self.session["id"], status=status)
                _print_json(self.session)
                return
            if action == "append":
                flags = {"--role": 1, "--trust-class": 1, "--trust": 1}
                content_parts = _positional_without_flags(parts[1:], flags)
                if not content_parts:
                    print("session append content required")
                    return
                role = _option_value(parts, "--role") or "user"
                if role not in {"user", "assistant"}:
                    print("role must be user or assistant")
                    return
                trust_class = TrustClass(_option_value(parts, "--trust-class") or _option_value(parts, "--trust") or TrustClass.USER_DIRECTIVE.value)
                _print_json(
                    self.orchestrator.sessions.add_message(
                        self.session["id"],
                        role=role,
                        content=" ".join(content_parts),
                        trust_class=trust_class,
                        metadata={"source": "tui", "submitted": False},
                    )
                )
                return
            if action == "compact":
                keep_last = int(parts[1]) if len(parts) > 1 else 20
                _print_json(self.orchestrator.sessions.compact_history(self.session["id"], keep_last=keep_last))
                return
            if action == "history":
                limit = int(_option_value(parts, "--limit") or "20")
                positional = _positional_without_flags(parts[1:], {"--limit": 1})
                history_session_id = positional[0] if positional else self.session["id"]
                print(
                    _table(
                        [_session_history_row(row) for row in self.orchestrator.sessions.history(history_session_id, limit=limit)],
                        (
                            ("role", "role", 11),
                            ("trust", "trust_class", 18),
                            ("meta", "meta", 80),
                            ("next", "next_actions", 72),
                            ("content", "content", 64),
                            ("created", "created_at", 22),
                        ),
                    )
                )
                return
            if action == "tasks":
                limit = int(_option_value(parts, "--limit") or "12")
                print(
                    _table(
                        [_task_list_row(self.orchestrator, row) for row in self.orchestrator.store.list_tasks(limit=limit, session_id=self.session["id"])],
                        (
                            ("id", "short_id", 10),
                            ("status", "status", 18),
                            ("risk", "risk_level", 10),
                            ("session", "session_label", 20),
                            ("next", "next_actions", 160),
                            ("request", "user_request", 52),
                            ("updated", "updated_at", 22),
                        ),
                    )
                )
                return
            print("usage: session [new <title> [--channel c] [--model m] [--personality p]|open <session_id>|rename <title>|set-model <model>|set-personality <name>|activate|archive|pause|append <content> [--role user|assistant] [--trust-class CLASS]|history [session_id] [--limit N]|tasks [--limit N]|compact [keep_last]]")
            return
        session = self.orchestrator.sessions.get_session(self.session["id"])
        print()
        print(_paint("Session", "36;1"))
        print("-" * 36)
        print(f"id          {session['id']}")
        print(f"title       {session['title']}")
        print(f"channel     {session['channel']}")
        print(f"status      {session['status']}")
        print(f"model       {session.get('model') or ''}")
        print(f"personality {session.get('personality') or ''}")
        print(f"updated     {session['updated_at']}")
        print()

    def do_approvals(self, arg: str) -> None:
        """approvals -- list pending approvals."""
        rows = self.orchestrator.approvals.list(status="pending")
        if not rows:
            print("no pending approvals")
            return
        rows = [_approval_list_row(self.orchestrator, row) for row in rows]
        print(
            _table(
                rows,
                (
                    ("id", "id", 36),
                    ("task", "task_short_id", 10),
                    ("session", "session_label", 20),
                    ("next", "next_actions", 54),
                    ("risk", "risk_level", 10),
                    ("reason", "reason", 42),
                ),
            )
        )

    def do_approval(self, arg: str) -> None:
        """approval <approval_id> -- inspect a pending approval payload."""
        approval_id = arg.strip()
        if not approval_id:
            print("approval id required")
            return
        try:
            _print_approval_detail(_approval_with_session(self.orchestrator, self.orchestrator.approvals.get(approval_id)))
        except KeyError:
            print(f"approval not found: {approval_id}")

    def do_approve(self, arg: str) -> None:
        """approve <approval_id> [--actor name] [--reason text] [--admin] -- approve a pending action."""
        parts = shlex.split(arg)
        approval_id = parts[0] if parts else ""
        if not approval_id:
            print("approval id required")
            return
        try:
            _print_approval_result(
                _approval_with_session(
                    self.orchestrator,
                    self.orchestrator.approvals.approve(
                        approval_id,
                        actor=_option_value(parts, "--actor") or "local-user",
                        reason=_option_value(parts, "--reason") or "",
                        admin="--admin" in parts,
                    ),
                )
            )
        except KeyError:
            print(f"approval not found: {approval_id}")

    def do_deny(self, arg: str) -> None:
        """deny <approval_id> [--actor name] [--reason text] [--admin] -- deny a pending action."""
        parts = shlex.split(arg)
        approval_id = parts[0] if parts else ""
        if not approval_id:
            print("approval id required")
            return
        try:
            _print_approval_result(
                _approval_with_session(
                    self.orchestrator,
                    self.orchestrator.approvals.deny(
                        approval_id,
                        actor=_option_value(parts, "--actor") or "local-user",
                        reason=_option_value(parts, "--reason") or "",
                        admin="--admin" in parts,
                    ),
                )
            )
        except KeyError:
            print(f"approval not found: {approval_id}")

    def do_connectors(self, arg: str) -> None:
        """connectors -- list connector status."""
        print(
            _table(
                self.orchestrator.connectors.list(),
                (
                    ("name", "name", 18),
                    ("auth", "auth_type", 14),
                    ("mode", "default_mode", 14),
                    ("operations", "supported_operations", 48),
                ),
            )
        )

    def do_channels(self, arg: str) -> None:
        """channels -- list channel adapters."""
        print(
            _table(
                self.orchestrator.channels.list_channels(),
                (
                    ("name", "name", 22),
                    ("auth", "auth_type", 20),
                    ("difficulty", "difficulty", 12),
                    ("rich messages", "rich_messages", 42),
                ),
            )
        )

    def do_channel(self, arg: str) -> None:
        """channel render|receive|send-webhook|send-email|send-chat-webhook|events -- inspect and exercise channel adapters."""
        parts = shlex.split(arg)
        if parts and parts[0] == "events":
            limit = int(parts[1]) if len(parts) > 1 else 20
            _print_json({"events": self.orchestrator.channels.events(limit=limit)})
            return
        if parts and parts[0] == "send-webhook":
            if len(parts) < 2:
                print("usage: channel send-webhook <text> --approved")
                return
            text = " ".join(part for part in parts[1:] if part != "--approved")
            _print_json(self.orchestrator.send_webhook(text=text, approved="--approved" in parts, session_id=self.session["id"], metadata={"source": "tui"}))
            return
        if parts and parts[0] == "send-email":
            if len(parts) < 3:
                print("usage: channel send-email <subject> <text> --approved")
                return
            subject = parts[1]
            text = " ".join(part for part in parts[2:] if part != "--approved")
            _print_json(self.orchestrator.send_email(subject=subject, text=text, approved="--approved" in parts, session_id=self.session["id"], metadata={"source": "tui"}))
            return
        if parts and parts[0] == "send-chat-webhook":
            if len(parts) < 2:
                print("usage: channel send-chat-webhook <text> --approved")
                return
            text = " ".join(part for part in parts[1:] if part != "--approved")
            _print_json(self.orchestrator.send_chat_webhook(text=text, approved="--approved" in parts, session_id=self.session["id"], metadata={"source": "tui"}))
            return
        if len(parts) >= 3 and parts[0] == "receive":
            self.orchestrator.channels.receive(
                parts[1],
                {
                    "sender": "tui-user",
                    "text": " ".join(parts[2:]),
                    "session_id": self.session["id"],
                },
            )
            _print_json({"message": self.orchestrator.channels.events(limit=1)[0]})
            return
        if len(parts) < 3 or parts[0] != "render":
            print("usage: channel render <channel> <text> | channel receive <channel> <text> | channel send-webhook <text> --approved | channel send-email <subject> <text> --approved | channel send-chat-webhook <text> --approved | channel events [limit]")
            return
        channel = parts[1]
        text = " ".join(parts[2:])
        _print_json(
            {
                "status": "rendered_pending_approval",
                "rendered": self.orchestrator.channels.render(
                    ChannelResponse(
                        channel=channel,
                        text=text,
                        metadata={"session_id": self.session["id"], "source": "tui"},
                    )
                ),
            }
        )

    def do_models(self, arg: str) -> None:
        """models [list|providers|route|alias|usage|auth] -- inspect model routing."""
        parts = shlex.split(arg)
        command = parts[0] if parts else "providers"
        if command == "list":
            _print_json({"models": self.orchestrator.models.list_models()})
            return
        if command == "route":
            if len(parts) < 2:
                print("usage: models route <identifier>")
                return
            try:
                route = self.orchestrator.models.route(parts[1])
            except (KeyError, ValueError) as exc:
                print(f"model route failed: {exc}")
                return
            _print_json(
                {
                    "identifier": route.identifier,
                    "provider": route.provider.provider,
                    "model": route.model,
                    "fallbacks": list(route.fallback_identifiers),
                    "secret_handle_id": route.secret_handle_id,
                }
            )
            return
        if command == "alias":
            if len(parts) < 3:
                print("usage: models alias <alias> <identifier>")
                return
            try:
                self.orchestrator.models.set_alias(parts[1], parts[2])
            except (KeyError, ValueError) as exc:
                print(f"model alias failed: {exc}")
                return
            _print_json({"ok": True, "alias": parts[1], "identifier": parts[2]})
            return
        if command == "fallbacks":
            if len(parts) < 3:
                print("usage: models fallbacks <identifier> <fallback> [fallback...]")
                return
            try:
                self.orchestrator.models.set_fallbacks(parts[1], tuple(parts[2:]))
            except (KeyError, ValueError) as exc:
                print(f"model fallbacks failed: {exc}")
                return
            _print_json({"ok": True, "identifier": parts[1], "fallbacks": parts[2:]})
            return
        if command == "usage":
            _print_json(self.orchestrator.models.usage_summary())
            return
        if command == "auth":
            try:
                if len(parts) >= 3 and parts[1] == "login":
                    api_key = getpass.getpass(f"{parts[2]} API key: ")
                    _print_json({"auth": self.orchestrator.models.login_provider(parts[2], api_key)})
                    return
                if len(parts) >= 3 and parts[1] == "logout":
                    _print_json({"auth": self.orchestrator.models.logout_provider(parts[2])})
                    return
                provider = parts[1] if len(parts) > 1 else None
                _print_json({"auth": self.orchestrator.models.auth_status(provider)})
            except KeyError as exc:
                print(f"model auth failed: {exc}")
            except ValueError as exc:
                print(f"model auth invalid: {exc}")
            return
        if command != "providers":
            print("usage: models list|providers|route <identifier>|alias <alias> <identifier>|fallbacks <identifier> <fallback> [fallback...]|usage|auth [provider]|auth login <provider>|auth logout <provider>")
            return
        print(
            _table(
                self.orchestrator.models.list_providers(),
                (
                    ("provider", "provider", 18),
                    ("local", "local", 7),
                    ("tools", "supports_tools", 7),
                    ("auth", "auth_configured", 8),
                    ("models", "models", 58),
                ),
            )
        )

    def do_tools(self, arg: str) -> None:
        """tools [run <name> <json-params> [--approved]] -- list or run built-in tools."""
        parts = shlex.split(arg)
        if parts and parts[0] == "run":
            if len(parts) < 3:
                print("usage: tools run <name> <json-params> [--approved]")
                return
            approved = "--approved" in parts[3:]
            try:
                params = json.loads(parts[2])
            except json.JSONDecodeError as exc:
                print(f"invalid JSON params: {exc}")
                return
            if not isinstance(params, dict):
                print("tool params must be a JSON object")
                return
            _print_json(self.orchestrator.tools.execute(parts[1], params, approved=approved))
            return
        print(
            _table(
                self.orchestrator.tool_catalog.list(),
                (
                    ("name", "name", 24),
                    ("risk", "risk_level", 10),
                    ("approval", "approval_required", 10),
                    ("categories", "categories", 36),
                ),
            )
        )

    def do_skills(self, arg: str) -> None:
        """skills [hub query|disable skill_id|enable skill_id] -- manage governed skills or inspect the read-only hub."""
        parts = shlex.split(arg)
        if parts and parts[0] == "hub":
            query = " ".join(parts[1:])
            _print_json(self.orchestrator.skill_hub.search(query))
            return
        if parts and parts[0] in {"disable", "enable"}:
            if len(parts) < 2:
                print(f"usage: skills {parts[0]} <skill_id>")
                return
            try:
                if parts[0] == "disable":
                    self.orchestrator.skills.disable(parts[1])
                else:
                    result = self.orchestrator.enable_skill(parts[1], approval_id=_option_value(parts, "--approval-id"))
                    _print_json(result)
                    return
            except KeyError:
                print(f"skill not found: {parts[1]}")
                return
            except PermissionError as exc:
                print(f"skill not enabled: {exc}")
                return
            _print_json({"ok": True, "skill_id": parts[1], "enabled": parts[0] == "enable"})
            return
        rows = []
        enable_approvals = _skill_enable_approval_refs(self.orchestrator)
        for row in self.orchestrator.skills.list():
            manifest = row["manifest"]
            rows.append(
                {
                    "id": row["id"],
                    "enabled": row["enabled"],
                    "risk_level": manifest.get("risk_level", ""),
                    "enable_approval": enable_approvals.get(row["id"], ""),
                    "name": manifest.get("name", ""),
                }
            )
        print(
            _table(
                rows,
                (
                    ("id", "id", 36),
                    ("enabled", "enabled", 8),
                    ("risk", "risk_level", 10),
                    ("enable approval", "enable_approval", 18),
                    ("name", "name", 40),
                ),
            )
        )

    def do_migrate(self, arg: str) -> None:
        """migrate openclaw|hermes|openclaw-memory-preview|hermes-memory-preview|openclaw-memory-commit|hermes-memory-commit <path> [--owner USER] [--scope SCOPE] -- migration inspection and governed memory commit."""
        try:
            parts = shlex.split(arg)
        except ValueError as exc:
            print(f"invalid migrate command: {exc}")
            return
        if len(parts) < 2 or parts[0] not in MIGRATE_COMMANDS:
            print("usage: migrate openclaw|hermes|openclaw-memory-preview|hermes-memory-preview|openclaw-memory-commit|hermes-memory-commit <path> [--owner USER] [--scope SCOPE] [--candidate-id ID] [--confirmed]")
            return
        command = parts[0]
        path = parts[1]
        owner = _flag_joined_value(parts, "--owner") or "local-user"
        scope = _flag_joined_value(parts, "--scope") or str(self.workspace)
        if command == "openclaw":
            _print_json(inspect_openclaw_home(path))
            return
        if command == "hermes":
            _print_json(inspect_hermes_home(path))
            return
        if command == "openclaw-memory-preview":
            _print_json(preview_openclaw_memory_import(path, owner=owner, scope=scope))
            return
        if command == "hermes-memory-preview":
            _print_json(preview_hermes_memory_import(path, owner=owner, scope=scope))
            return
        preview = (
            preview_openclaw_memory_import(path, owner=owner, scope=scope)
            if command == "openclaw-memory-commit"
            else preview_hermes_memory_import(path, owner=owner, scope=scope)
        )
        _print_json(
            self.orchestrator.memory.commit_preview_candidates(
                preview,
                candidate_ids=_flag_values(parts, "--candidate-id") or None,
                confirmed="--confirmed" in parts,
                reviewer=_flag_joined_value(parts, "--reviewer") or "local-user",
            )
        )

    def do_memory(self, arg: str) -> None:
        """memory search|session-preview|session-commit|create|review-queue|review-digest|review-escalation|review-action|review-batch|recertify|update|merge|resolve-conflict|expire|cleanup-expired|explain|export|delete -- manage governed memory."""
        try:
            parts = shlex.split(arg)
        except ValueError as exc:
            print(f"invalid memory command: {exc}")
            return
        command = parts[0] if parts else "search"
        if command == "search":
            query = " ".join(parts[1:])
            if not query:
                print("usage: memory search <query>")
                return
            _print_json({"memories": self.orchestrator.memory.retrieve_relevant(query)})
            return
        if command == "session-preview":
            session_id = parts[1] if len(parts) > 1 else self.session["id"]
            try:
                _print_json(
                    self.orchestrator.memory.preview_session_memory_candidates(
                        session_id=session_id,
                        messages=self.orchestrator.sessions.history(session_id, limit=1000),
                        owner=_flag_joined_value(parts, "--owner") or "local-user",
                        scope=_flag_joined_value(parts, "--scope") or str(self.workspace),
                        limit=_flag_int(parts, "--limit", default=25) or 25,
                    )
                )
            except KeyError:
                print(f"session not found: {session_id}")
            except ValueError as exc:
                print(f"memory session preview failed: {exc}")
            return
        if command == "session-commit":
            session_id = parts[1] if len(parts) > 1 else self.session["id"]
            try:
                _print_json(
                    self.orchestrator.memory.commit_session_memory_candidates(
                        session_id=session_id,
                        messages=self.orchestrator.sessions.history(session_id, limit=1000),
                        owner=_flag_joined_value(parts, "--owner") or "local-user",
                        scope=_flag_joined_value(parts, "--scope") or str(self.workspace),
                        limit=_flag_int(parts, "--limit", default=25) or 25,
                        candidate_ids=_flag_values(parts, "--candidate-id") or None,
                        confirmed="--confirmed" in parts,
                    )
                )
            except KeyError:
                print(f"session not found: {session_id}")
            except ValueError as exc:
                print(f"memory session commit failed: {exc}")
            return
        if command == "create":
            if len(parts) < 3:
                print("usage: memory create <type> <content> [--confidence N] [--tag tag] [--ttl-days N] [--confirmed]")
                return
            try:
                confidence = _flag_float(parts, "--confidence", default=0.8)
                ttl_days = _flag_int(parts, "--ttl-days", default=None)
                tags = tuple(_flag_values(parts, "--tag"))
                confirmed = "--confirmed" in parts
                content_parts = _positional_without_flags(parts[2:], {"--confidence": 1, "--tag": 1, "--ttl-days": 1, "--confirmed": 0})
                content = " ".join(content_parts).strip()
                if not content:
                    raise ValueError("memory content is required")
                record = self.orchestrator.memory.create_memory(
                    memory_type=MemoryType(parts[1]),
                    content=content,
                    source="tui",
                    provenance={"tui": True, "session_id": self.session["id"]},
                    confidence=confidence,
                    sensitivity=Sensitivity.INTERNAL,
                    tags=tags,
                    confirmed=confirmed,
                    ttl_days=ttl_days,
                )
            except ValueError as exc:
                print(f"memory create failed: {exc}")
                return
            _print_json(record.to_row())
            return
        if command == "review-queue":
            try:
                positionals = _positional_without_flags(parts[1:], {"--limit": 1, "--scope": 1})
                limit = _flag_int(parts, "--limit", default=int(positionals[0]) if positionals else 50) or 50
                scope = _flag_joined_value(parts, "--scope") or "workspace"
                _print_json(self.orchestrator.memory.review_queue(limit=limit, scope=scope))
            except ValueError as exc:
                print(f"memory review queue failed: {exc}")
            return
        if command == "review-digest":
            try:
                positionals = _positional_without_flags(parts[1:], {"--limit": 1, "--scope": 1})
                limit = _flag_int(parts, "--limit", default=int(positionals[0]) if positionals else 10) or 10
                scope = _flag_joined_value(parts, "--scope") or "workspace"
                _print_json(self.orchestrator.memory.review_digest(limit=limit, scope=scope))
            except ValueError as exc:
                print(f"memory review digest failed: {exc}")
            return
        if command == "review-escalation":
            try:
                _print_json(
                    self.orchestrator.memory.review_escalation(
                        max_age_days=_flag_int(parts, "--max-age-days", default=7) or 7,
                        limit=_flag_int(parts, "--limit", default=10) or 10,
                        scope=_flag_joined_value(parts, "--scope") or "workspace",
                        route=_flag_joined_value(parts, "--route") or "operator",
                    )
                )
            except ValueError as exc:
                print(f"memory review escalation failed: {exc}")
            return
        if command == "review-action":
            if len(parts) < 3:
                print("usage: memory review-action <memory_id> <confirm|delete> [--confidence N] [--rationale text]")
                return
            try:
                _print_json(
                    self.orchestrator.memory.review_memory(
                        parts[1],
                        action=parts[2],
                        confidence=_flag_float(parts, "--confidence", default=None),
                        rationale=_flag_joined_value(parts, "--rationale") or "",
                    )
                )
            except KeyError:
                print(f"memory not found: {parts[1]}")
            except ValueError as exc:
                print(f"memory review action failed: {exc}")
            return
        if command == "review-batch":
            if len(parts) < 3:
                print("usage: memory review-batch <confirm|delete> <memory_id>... [--confidence N] [--rationale text]")
                return
            try:
                memory_ids = _positional_without_flags(parts[2:], {"--confidence": 1, "--rationale": 1})
                _print_json(
                    self.orchestrator.memory.review_memory_batch(
                        list(memory_ids),
                        action=parts[1],
                        confidence=_flag_float(parts, "--confidence", default=None),
                        rationale=_flag_joined_value(parts, "--rationale") or "",
                    )
                )
            except ValueError as exc:
                print(f"memory review batch failed: {exc}")
            return
        if command == "recertify":
            try:
                _print_json(
                    self.orchestrator.memory.recertify_due(
                        max_age_days=_flag_int(parts, "--max-age-days", default=None),
                        limit=_flag_int(parts, "--limit", default=50) or 50,
                        scope=_flag_joined_value(parts, "--scope") or "workspace",
                        dry_run="--dry-run" in parts,
                    )
                )
            except ValueError as exc:
                print(f"memory recertify failed: {exc}")
            return
        if command == "update":
            if len(parts) < 2:
                print("usage: memory update <memory_id> [--content text] [--confidence N] [--confirmed]")
                return
            try:
                content = _flag_joined_value(parts, "--content")
                confidence = _flag_float(parts, "--confidence", default=None)
                updated = self.orchestrator.memory.update_memory(
                    parts[1],
                    content=content,
                    confidence=confidence,
                    confirmed="--confirmed" in parts,
                )
            except KeyError:
                print(f"memory not found: {parts[1]}")
                return
            except ValueError as exc:
                print(f"memory update failed: {exc}")
                return
            _print_json(updated)
            return
        if command == "explain":
            if len(parts) < 3:
                print("usage: memory explain <memory_id> <query>")
                return
            try:
                _print_json({"memory_id": parts[1], "query": " ".join(parts[2:]), "explanation": self.orchestrator.memory.explain_usage(parts[1], " ".join(parts[2:]))})
            except KeyError:
                print(f"memory not found: {parts[1]}")
            return
        if command == "export":
            _print_json({"memories": self.orchestrator.memory.export_memory(" ".join(parts[1:]))})
            return
        if command == "merge":
            if len(parts) < 3:
                print("usage: memory merge <primary_id> <duplicate_id>")
                return
            try:
                _print_json(self.orchestrator.memory.merge_duplicate(parts[1], parts[2]))
            except KeyError:
                print("memory not found: primary or duplicate memory not found")
            return
        if command == "resolve-conflict":
            if len(parts) < 5:
                print("usage: memory resolve-conflict <primary_id> <conflicting_id> <keep_primary|keep_conflicting|synthesize|keep_both> <rationale>")
                return
            try:
                _print_json(self.orchestrator.memory.resolve_conflict(parts[1], parts[2], strategy=parts[3], rationale=" ".join(parts[4:])))
            except KeyError:
                print("memory not found: primary or conflicting memory not found")
            except ValueError as exc:
                print(f"memory conflict resolution failed: {exc}")
            return
        if command == "expire":
            if len(parts) < 2:
                print("usage: memory expire <memory_id>")
                return
            try:
                _print_json(self.orchestrator.memory.expire_memory(parts[1]))
            except KeyError:
                print(f"memory not found: {parts[1]}")
            return
        if command == "cleanup-expired":
            _print_json(self.orchestrator.memory.cleanup_expired())
            return
        if command == "delete":
            if len(parts) < 2:
                print("usage: memory delete <memory_id>")
                return
            try:
                self.orchestrator.memory.delete_memory(parts[1])
            except KeyError:
                print(f"memory not found: {parts[1]}")
                return
            _print_json({"ok": True, "deleted": parts[1]})
            return
        print("usage: memory search|session-preview|session-commit|create|review-queue|review-digest|review-escalation|review-action|review-batch|recertify|update|merge|resolve-conflict|expire|cleanup-expired|explain|export|delete")

    def do_mcp(self, arg: str) -> None:
        """mcp list|register|call -- inspect, register, or call governed MCP servers."""
        parts = shlex.split(arg)
        command = parts[0] if parts else "list"
        if command == "list":
            _print_json({"servers": self.orchestrator.mcp.list_servers()})
            return
        if command == "call":
            if len(parts) < 4:
                print("usage: mcp call <server> <tool> <json-arguments> [--approved]")
                return
            approved = "--approved" in parts[4:]
            _print_json(
                self.orchestrator.tools.execute(
                    "mcp_call",
                    {"server": parts[1], "tool": parts[2], "arguments": json.loads(parts[3])},
                    approved=approved,
                )
            )
            return
        if command == "register":
            if len(parts) < 4:
                print("usage: mcp register <name> <command> <tool,tool>")
                return
            tools = tuple(item.strip() for item in parts[3].split(",") if item.strip())
            _print_json(
                self.orchestrator.mcp.register_server(
                    name=parts[1],
                    command=parts[2],
                    allowed_tools=tools,
                    enabled=False,
                    approval_required=True,
                    metadata={"source": "tui"},
                )
            )
            return
        print("usage: mcp list | mcp register <name> <command> <tool,tool> | mcp call <server> <tool> <json-arguments> [--approved]")

    def do_repairs(self, arg: str) -> None:
        """repairs [status] -- list self-repair proposals."""
        status = arg.strip() or None
        rows = self.orchestrator.list_improvement_proposals(status=status, limit=20)
        if not rows:
            print("no repair proposals")
            return
        table_rows = [
            {
                **row,
                "task_short_id": _short_id(row.get("task_id", "")),
                "evidence": ", ".join(str(item) for item in row.get("evidence", [])[:3]),
            }
            for row in rows
        ]
        print(
            _table(
                table_rows,
                (
                    ("id", "id", 36),
                    ("status", "status", 14),
                    ("task", "task_short_id", 10),
                    ("kind", "kind", 22),
                    ("summary", "summary", 58),
                ),
            )
        )

    def do_repair(self, arg: str) -> None:
        """repair <id>|readiness|review <id>|approve <id>|reject <id>|candidate <id> <summary>|generate-candidate <id>|synthesis-prompt <id>|synthesize-candidate <id> <json_file>|review-candidate <id> <candidate_id> <approved|rejected>|apply-candidate <id> <candidate_id>|rollback-candidate <id> <candidate_id>|attempt <id> <outcome> [--candidate-id id] [--test-command cmd] [--test-result passed] -- review repair proposals."""
        parts = shlex.split(arg)
        if not parts:
            print("repair id required")
            return
        command = parts[0]
        try:
            if command == "readiness":
                _print_json(self.orchestrator.repair_readiness_summary(status=_option_value(parts, "--status"), limit=_flag_int(parts, "--limit", default=20) or 20))
                return
            if command in {"review", "approve", "reject"}:
                if len(parts) < 2:
                    print("repair id required")
                    return
                status = "reviewing" if command == "review" else "approved" if command == "approve" else "rejected"
                _print_repair_detail(self.orchestrator.update_improvement_proposal(parts[1], status=status))
                return
            if command == "attempt":
                if len(parts) < 3:
                    print("usage: repair attempt <id> <outcome> <changed_file> [changed_file...] [--candidate-id id] [--test-command cmd] [--test-result passed]")
                    return
                outcome, changed_files, candidate_id, test_command, test_result = _parse_repair_attempt_command(parts[2:])
                _print_repair_detail(
                    self.orchestrator.record_improvement_attempt(
                        parts[1],
                        outcome=outcome,
                        changed_files=tuple(changed_files),
                        candidate_id=candidate_id,
                        test_command=test_command,
                        test_result=test_result,
                    )
                )
                return
            if command == "candidate":
                if len(parts) < 3:
                    print("usage: repair candidate <id> <summary> [changed_file...]")
                    return
                summary, changed_files = _parse_repair_attempt_args(parts[2:])
                _print_repair_detail(
                    self.orchestrator.create_repair_candidate(
                        parts[1],
                        summary=summary,
                        actor="tui",
                        changed_files=tuple(changed_files),
                        patch_plan=summary,
                    )
                )
                return
            if command == "generate-candidate":
                if len(parts) < 2:
                    print("usage: repair generate-candidate <id>")
                    return
                _print_repair_detail(self.orchestrator.generate_repair_candidate(parts[1], actor="tui"))
                return
            if command == "synthesis-prompt":
                if len(parts) < 2:
                    print("usage: repair synthesis-prompt <id>")
                    return
                print(json.dumps(self.orchestrator.create_repair_synthesis_prompt(parts[1], actor="tui"), indent=2, sort_keys=True))
                return
            if command == "synthesize-candidate":
                if len(parts) < 3:
                    print("usage: repair synthesize-candidate <id> <json_file>")
                    return
                synthesis = json.loads(Path(parts[2]).read_text(encoding="utf-8"))
                _print_repair_detail(self.orchestrator.synthesize_repair_candidate(parts[1], synthesis=synthesis, actor="tui"))
                return
            if command == "review-candidate":
                if len(parts) < 4:
                    print("usage: repair review-candidate <id> <candidate_id> <approved|rejected>")
                    return
                _print_repair_detail(self.orchestrator.review_repair_candidate(parts[1], parts[2], status=parts[3], actor="tui"))
                return
            if command == "apply-candidate":
                if len(parts) < 3:
                    print("usage: repair apply-candidate <id> <candidate_id>")
                    return
                _print_repair_detail(self.orchestrator.apply_repair_candidate(parts[1], parts[2], actor="tui"))
                return
            if command == "rollback-candidate":
                if len(parts) < 3:
                    print("usage: repair rollback-candidate <id> <candidate_id>")
                    return
                _print_repair_detail(self.orchestrator.rollback_repair_candidate(parts[1], parts[2], actor="tui"))
                return
            _print_repair_detail(self.orchestrator.get_improvement_proposal(command))
        except KeyError:
            repair_id = parts[1] if command in {"review", "approve", "reject", "attempt", "candidate", "synthesis-prompt", "synthesize-candidate", "review-candidate", "apply-candidate", "rollback-candidate"} and len(parts) > 1 else command
            print(f"repair proposal not found: {repair_id}")
        except PermissionError as exc:
            print(f"repair blocked: {exc}")
        except ValueError as exc:
            print(f"repair invalid: {exc}")

    def do_sessions(self, arg: str) -> None:
        """sessions [--limit N] -- list sessions."""
        parts = shlex.split(arg)
        limit = int(_option_value(parts, "--limit") or (parts[0] if parts and not parts[0].startswith("--") else "50"))
        print(
            _table(
                [_session_list_row(row) for row in self.orchestrator.sessions.list_sessions(limit=limit)],
                (
                    ("id", "short_id", 10),
                    ("title", "title", 32),
                    ("channel", "channel", 14),
                    ("status", "status", 12),
                    ("msgs", "message_count", 6),
                    ("tasks", "task_count", 7),
                    ("waiting", "waiting_task_count", 8),
                    ("latest", "latest_task_label", 20),
                    ("next", "next_actions", 160),
                    ("updated", "updated_at", 22),
                ),
            )
        )

    def do_schedules(self, arg: str) -> None:
        """schedules -- list scheduled automations."""
        print(
            _table(
                [_schedule_list_row(row) for row in self.orchestrator.schedules.list_schedules()],
                (
                    ("id", "short_id", 10),
                    ("name", "name", 28),
                    ("cron", "cron", 16),
                    ("status", "status", 26),
                    ("next", "next_run_at", 24),
                ),
            )
        )

    def do_schedule(self, arg: str) -> None:
        """schedule create|memory-review-digest|memory-review-escalation|evaluation-run|evaluation-suite|due|approve|activate|pause|run-due -- manage scheduled automations."""
        parts = shlex.split(arg)
        if not parts:
            print("schedule command required")
            return
        command = parts[0]
        try:
            if command == "create":
                if len(parts) < 4:
                    print("usage: schedule create <name> <cron> <task_request> [--natural-language text] [--channel name]")
                    return
                channel = _option_value(parts, "--channel") or "terminal"
                natural_language = _flag_joined_value(parts, "--natural-language")
                positional = _positional_without_flags(parts[1:], {"--natural-language": 1, "--channel": 1})
                if len(positional) < 3:
                    print("usage: schedule create <name> <cron> <task_request> [--natural-language text] [--channel name]")
                    return
                name, cron = positional[0], positional[1]
                task_request = " ".join(positional[2:])
                _print_json(
                    self.orchestrator.schedules.create_schedule(
                        name=name,
                        natural_language=natural_language or task_request,
                        cron=cron,
                        task_request=task_request,
                        channel=channel,
                    )
                )
                return
            if command == "memory-review-digest":
                if len(parts) < 3:
                    print("usage: schedule memory-review-digest <name> <cron> [--channel name] [--limit N] [--scope scope]")
                    return
                positional = _positional_without_flags(parts[1:], {"--channel": 1, "--limit": 1, "--scope": 1})
                if len(positional) < 2:
                    print("usage: schedule memory-review-digest <name> <cron> [--channel name] [--limit N] [--scope scope]")
                    return
                _print_json(
                    self.orchestrator.schedules.create_memory_review_digest_schedule(
                        name=positional[0],
                        cron=positional[1],
                        channel=_option_value(parts, "--channel") or "terminal",
                        limit=int(_option_value(parts, "--limit") or "10"),
                        scope=_option_value(parts, "--scope") or "workspace",
                    )
                )
                return
            if command == "memory-review-escalation":
                if len(parts) < 3:
                    print("usage: schedule memory-review-escalation <name> <cron> [--channel name] [--max-age-days N] [--limit N] [--scope scope] [--route name]")
                    return
                positional = _positional_without_flags(parts[1:], {"--channel": 1, "--max-age-days": 1, "--limit": 1, "--scope": 1, "--route": 1})
                if len(positional) < 2:
                    print("usage: schedule memory-review-escalation <name> <cron> [--channel name] [--max-age-days N] [--limit N] [--scope scope] [--route name]")
                    return
                _print_json(
                    self.orchestrator.schedules.create_memory_review_escalation_schedule(
                        name=positional[0],
                        cron=positional[1],
                        channel=_option_value(parts, "--channel") or "terminal",
                        max_age_days=int(_option_value(parts, "--max-age-days") or "7"),
                        limit=int(_option_value(parts, "--limit") or "10"),
                        scope=_option_value(parts, "--scope") or "workspace",
                        route=_option_value(parts, "--route") or "operator",
                    )
                )
                return
            if command == "evaluation-run":
                if len(parts) < 4:
                    print("usage: schedule evaluation-run <name> <cron> <scenario> [steps...] [--channel name] [--reviewer name]")
                    return
                positional = _positional_without_flags(parts[1:], {"--channel": 1, "--reviewer": 1})
                if len(positional) < 3:
                    print("usage: schedule evaluation-run <name> <cron> <scenario> [steps...] [--channel name] [--reviewer name]")
                    return
                _print_json(
                    self.orchestrator.schedules.create_evaluation_run_schedule(
                        name=positional[0],
                        cron=positional[1],
                        scenario=positional[2],
                        steps=tuple(positional[3:]),
                        channel=_option_value(parts, "--channel") or "terminal",
                        reviewer=_option_value(parts, "--reviewer") or "scheduler",
                    )
                )
                return
            if command == "evaluation-suite":
                if len(parts) < 3:
                    print("usage: schedule evaluation-suite <name> <cron> [--suite name] [--scenario-id id] [--channel name] [--reviewer name]")
                    return
                positional = _positional_without_flags(parts[1:], {"--suite": 1, "--scenario-id": 1, "--channel": 1, "--reviewer": 1})
                if len(positional) < 2:
                    print("usage: schedule evaluation-suite <name> <cron> [--suite name] [--scenario-id id] [--channel name] [--reviewer name]")
                    return
                scenario_ids = _option_values(parts, "--scenario-id")
                _print_json(
                    self.orchestrator.schedules.create_evaluation_suite_schedule(
                        name=positional[0],
                        cron=positional[1],
                        suite=_option_value(parts, "--suite") or "security",
                        scenario_ids=tuple(scenario_ids),
                        channel=_option_value(parts, "--channel") or "terminal",
                        reviewer=_option_value(parts, "--reviewer") or "scheduler",
                    )
                )
                return
            if command == "due":
                _print_json({"schedules": self.orchestrator.schedules.due()})
                return
            if command == "run-due":
                _print_json(self.orchestrator.run_due_schedules())
                return
            if len(parts) < 2:
                print("schedule id required")
                return
            schedule_id = parts[1]
            if command == "approve":
                _print_json(self.orchestrator.schedules.approve(schedule_id, approved_by=_option_value(parts, "--approved-by") or "local-user"))
                return
            if command == "activate":
                _print_json(self.orchestrator.schedules.activate(schedule_id))
                return
            if command == "pause":
                _print_json(self.orchestrator.schedules.pause(schedule_id))
                return
            print(f"unknown schedule command: {command}")
        except KeyError:
            print(f"schedule not found: {parts[1] if len(parts) > 1 else ''}")
        except PermissionError as exc:
            print(f"schedule blocked: {exc}")

    def do_evaluation(self, arg: str) -> None:
        """evaluation queue|review|trends|delta|readiness -- review local evaluation reports."""
        parts = shlex.split(arg)
        if not parts:
            print("evaluation command required")
            return
        harness = ResearchHarness(data_dir=self.orchestrator.config.data_dir)
        command = parts[0]
        try:
            if command == "queue":
                _print_json(harness.evaluation_review_queue(limit=_flag_int(parts, "--limit", default=20) or 20, reviewer=_option_value(parts, "--reviewer")))
                return
            if command == "review":
                if len(parts) < 3:
                    print("usage: evaluation review <report-id> <status> [--reviewer name] [--notes text]")
                    return
                _print_json(
                    harness.review_evaluation_report(
                        parts[1],
                        status=parts[2],
                        reviewer=_option_value(parts, "--reviewer") or "local",
                        notes=_flag_joined_value(parts, "--notes") or "",
                    )
                )
                return
            if command == "trends":
                _print_json(harness.evaluation_trends(limit=_flag_int(parts, "--limit", default=20) or 20))
                return
            if command == "delta":
                _print_json(
                    harness.evaluation_regression_delta(
                        baseline_report_id=_option_value(parts, "--baseline-report-id"),
                        candidate_report_id=_option_value(parts, "--candidate-report-id"),
                        scenario=_option_value(parts, "--scenario"),
                    )
                )
                return
            if command == "readiness":
                _print_json(
                    harness.release_readiness_summary(
                        baseline_report_id=_option_value(parts, "--baseline-report-id"),
                        candidate_report_id=_option_value(parts, "--candidate-report-id"),
                        scenario=_option_value(parts, "--scenario"),
                        reviewer=_option_value(parts, "--reviewer"),
                        limit=_flag_int(parts, "--limit", default=20) or 20,
                    )
                )
                return
            print(f"unknown evaluation command: {command}")
        except KeyError:
            print(f"evaluation report not found: {parts[1] if len(parts) > 1 else ''}")
        except ValueError as exc:
            print(f"evaluation review failed: {exc}")

    def do_browser(self, arg: str) -> None:
        """browser session|sessions|close|navigate|extract|inspect|table|screenshot|render|click|fill -- operate the governed browser sandbox."""
        raw_parts = arg.strip().split(maxsplit=1)
        raw_command = raw_parts[0] if raw_parts else "session"
        parts = [raw_command, raw_parts[1]] if raw_command == "fill" and len(raw_parts) > 1 else shlex.split(arg)
        command = parts[0] if parts else "session"
        try:
            if command == "session":
                session = self.orchestrator.browser.create_session(label="TUI browser")
                self.browser_session_id = session["id"]
                _print_json(session)
                return
            if command == "sessions":
                _print_json({"sessions": self.orchestrator.browser.list_sessions()})
                return
            if command == "close":
                close_session_id = parts[1] if len(parts) > 1 else self.browser_session_id
                if not close_session_id:
                    print("browser session required")
                    return
                result = self.orchestrator.browser.close_session(session_id=close_session_id)
                if self.browser_session_id == close_session_id:
                    self.browser_session_id = None
                _print_json(result)
                return
            if command == "navigate":
                if len(parts) < 2:
                    print("browser url required")
                    return
                result = self.orchestrator.browser.navigate(session_id=self.browser_session_id, url=parts[1])
                self.browser_session_id = result.get("session", {}).get("id", self.browser_session_id)
                _print_json(result)
                return
            if not self.browser_session_id:
                print("browser session required")
                return
            if command == "extract":
                _print_json(self.orchestrator.browser.extract_text(session_id=self.browser_session_id))
                return
            if command == "inspect":
                _print_json(self.orchestrator.browser.inspect(session_id=self.browser_session_id))
                return
            if command == "table":
                selector = parts[1] if len(parts) > 1 else None
                _print_json(self.orchestrator.browser.extract_table(session_id=self.browser_session_id, selector=selector))
                return
            if command == "screenshot":
                _print_json(self.orchestrator.browser.screenshot(session_id=self.browser_session_id))
                return
            if command == "render":
                _print_json(self.orchestrator.browser.render_screenshot(session_id=self.browser_session_id))
                return
            if command == "click":
                if len(parts) < 2:
                    print("browser selector required")
                    return
                approval_id = _option_value(parts, "--approval-id")
                approval = _browser_action_approval(self.orchestrator, action="click", session_id=self.browser_session_id, selector=parts[1], approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.click(session_id=self.browser_session_id, selector=parts[1], approved=True))
                return
            if command == "fill":
                if len(parts) < 2:
                    print("browser fields JSON required")
                    return
                fields_text, approval_id = _split_json_approval_arg(parts[1])
                fields = json.loads(fields_text)
                if not isinstance(fields, dict):
                    raise ValueError("browser fill requires a JSON object")
                approval = _browser_action_approval(self.orchestrator, action="fill", session_id=self.browser_session_id, fields=fields, approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.fill(session_id=self.browser_session_id, fields=fields, approved=True))
                return
            print(f"unknown browser command: {command}")
        except json.JSONDecodeError:
            print("browser fields JSON invalid")
        except PermissionError as exc:
            print(f"browser approval blocked: {exc}")
        except KeyError as exc:
            print(f"browser session not found: {exc}")
        except ValueError as exc:
            print(f"browser invalid: {exc}")

    def do_boards(self, arg: str) -> None:
        """boards -- list work boards."""
        boards = self.orchestrator.kanban.list_boards()
        if not boards:
            print("no boards")
            return
        print(_table(boards, (("id", "id", 36), ("name", "name", 34), ("updated", "updated_at", 22))))
        for board in boards[:3]:
            cards = self.orchestrator.kanban.list_cards(board["id"])
            if cards:
                print()
                print(_paint(board["name"], "36;1"))
                print(_table(cards, (("lane", "lane", 14), ("risk", "risk_level", 10), ("title", "title", 52))))

    def do_backends(self, arg: str) -> None:
        """backends -- list execution backends."""
        print(
            _table(
                self.orchestrator.execution_backends.list(),
                (
                    ("name", "name", 18),
                    ("enabled", "enabled", 8),
                    ("local", "local", 7),
                    ("risk", "risk_level", 10),
                    ("activation", "activation", 28),
                    ("description", "description", 54),
                ),
            )
        )

    def do_security(self, arg: str) -> None:
        """security [profile|bundles|import-bundle|diff-bundle|apply-bundle|schedule-bundle|activate-due|promote-bundle|promotions|rollouts|rollback-bundle|evaluate] -- show or update security controls."""
        parts = shlex.split(arg)
        if parts and parts[0] == "profile":
            profile = self.orchestrator.policy_gate.engine.profile
            _print_json(policy_profile_to_dict(profile))
            return
        if parts and parts[0] == "bundles":
            _print_json({"bundles": list_policy_bundles()})
            return
        if parts and parts[0] == "import-bundle":
            if len(parts) < 2:
                print("usage: security import-bundle <path>")
                return
            try:
                _print_json(import_policy_bundle(parts[1], base=self.orchestrator.config.policy_profile))
            except (OSError, ValueError) as exc:
                print(f"policy import failed: {exc}")
            return
        if parts and parts[0] == "apply-bundle":
            if len(parts) < 2:
                print("usage: security apply-bundle <bundle-name-or-path> --approved [--name name]")
                return
            try:
                _print_json(
                    apply_policy_bundle(
                        parts[1],
                        data_dir=self.orchestrator.config.data_dir,
                        approved="--approved" in parts,
                        name=_option_value(parts, "--name"),
                        base=self.orchestrator.config.policy_profile,
                    )
                )
            except (OSError, ValueError) as exc:
                print(f"policy apply failed: {exc}")
            return
        if parts and parts[0] == "diff-bundle":
            if len(parts) < 2:
                print("usage: security diff-bundle <bundle-name-or-path>")
                return
            try:
                _print_json(diff_policy_bundle(parts[1], current=self.orchestrator.config.policy_profile, base=self.orchestrator.config.policy_profile))
            except (OSError, ValueError) as exc:
                print(f"policy diff failed: {exc}")
            return
        if parts and parts[0] == "rollback-bundle":
            _print_json(rollback_policy_bundle(data_dir=self.orchestrator.config.data_dir, approved="--approved" in parts))
            return
        if parts and parts[0] == "schedule-bundle":
            if len(parts) < 2 or "--activate-at" not in parts:
                print("usage: security schedule-bundle <bundle-name-or-path> --activate-at timestamp --approved [--environment name] [--name name]")
                return
            _print_json(
                schedule_policy_bundle(
                    parts[1],
                    data_dir=self.orchestrator.config.data_dir,
                    activate_at=str(_option_value(parts, "--activate-at")),
                    environment=_option_value(parts, "--environment") or "local",
                    approved="--approved" in parts,
                    name=_option_value(parts, "--name"),
                    base=self.orchestrator.config.policy_profile,
                )
            )
            return
        if parts and parts[0] == "promote-bundle":
            if len(parts) < 2 or "--from-environment" not in parts or "--to-environment" not in parts:
                print("usage: security promote-bundle <bundle-name-or-path> --from-environment name --to-environment name --approved [--name name] [--require-clean-evaluation] [--require-live-parity] [--defer-live-gap area] [--live-gap-deferral-reason reason]")
                return
            live_gap_backlog = None
            if "--require-live-parity" in parts:
                live_gap_backlog = build_product_dashboard(self.orchestrator).get("live_gap_backlog", [])
            _print_json(
                promote_policy_bundle(
                    parts[1],
                    data_dir=self.orchestrator.config.data_dir,
                    from_environment=str(_option_value(parts, "--from-environment")),
                    to_environment=str(_option_value(parts, "--to-environment")),
                    approved="--approved" in parts,
                    name=_option_value(parts, "--name"),
                    base=self.orchestrator.config.policy_profile,
                    require_clean_evaluation="--require-clean-evaluation" in parts,
                    baseline_report_id=_option_value(parts, "--baseline-report-id"),
                    candidate_report_id=_option_value(parts, "--candidate-report-id"),
                    evaluation_scenario=_option_value(parts, "--evaluation-scenario"),
                    require_live_parity="--require-live-parity" in parts,
                    live_gap_backlog=live_gap_backlog,
                    deferred_live_gap_areas=_option_values(parts, "--defer-live-gap"),
                    live_gap_deferral_reason=_flag_joined_value(parts, "--live-gap-deferral-reason"),
                )
            )
            return
        if parts and parts[0] == "activate-due":
            _print_json(
                activate_due_policy_rollouts(
                    data_dir=self.orchestrator.config.data_dir,
                    now=_option_value(parts, "--now"),
                    environment=_option_value(parts, "--environment"),
                    limit=_flag_int(parts, "--limit", default=20) or 20,
                )
            )
            return
        if parts and parts[0] == "rollouts":
            _print_json(list_policy_rollouts(data_dir=self.orchestrator.config.data_dir))
            return
        if parts and parts[0] == "promotions":
            _print_json(list_policy_promotions(data_dir=self.orchestrator.config.data_dir, limit=_flag_int(parts, "--limit", default=20) or 20))
            return
        if parts and parts[0] == "evaluate":
            if len(parts) < 3:
                print("usage: security evaluate <operation> <low|medium|high|critical> [scope,scope] [target_domain]")
                return
            scopes = tuple(scope for scope in (parts[3].split(",") if len(parts) > 3 else []) if scope)
            decision = self.orchestrator.policy_gate.evaluate(
                PolicyRequest(
                    user_role="local-user",
                    workspace=str(self.workspace),
                    task_type="tui-policy-evaluation",
                    risk_level=RiskLevel(parts[2]),
                    operation=parts[1],
                    requested_scopes=scopes,
                    target_domain=parts[4] if len(parts) > 4 else None,
                )
            )
            _print_json(
                {
                    "decision": decision.decision.value,
                    "allowed": decision.allowed,
                    "risk_level": decision.risk_level.value,
                    "reasons": list(decision.reasons),
                    "requirements": list(decision.requirements),
                }
            )
            return
        dashboard = build_product_dashboard(self.orchestrator)
        print(_table(dashboard["security_controls"], (("control", "name", 24), ("state", "state", 16), ("detail", "detail", 74))))

    def do_capabilities(self, arg: str) -> None:
        """capabilities -- show product capability groups and implementation readiness."""
        dashboard = build_product_dashboard(self.orchestrator)
        print(_table(dashboard["capability_groups"], (("capability", "name", 30), ("state", "state", 22), ("coverage", "coverage", 42), ("detail", "detail", 64))))
        print()
        print("Implementation Readiness")
        print(
            _table(
                dashboard.get("implementation_readiness", []),
                (("state", "state", 22), ("label", "label", 30), ("tools", "count", 8), ("statuses", "statuses", 48), ("sample", "sample_tools", 48)),
            )
        )
        print()
        print("Live Gap Backlog")
        print(
            _table(
                dashboard.get("live_gap_backlog", []),
                (
                    ("area", "area", 34),
                    ("status", "status", 28),
                    ("controls", "required_controls", 34),
                    ("gates", "verification_gates", 34),
                    ("evaluations", "evaluation_scenarios", 48),
                ),
            )
        )
        provider_gap = next((item for item in dashboard.get("live_gap_backlog", []) if item.get("area") == "provider_and_channel_live_connectors"), None)
        if provider_gap:
            print()
            print("Live Connector Readiness")
            print(
                _table(
                    provider_gap.get("operator_checklist", []),
                    (("control", "control", 28), ("state", "state", 24), ("detail", "detail", 84)),
                )
            )
        browser_gap = next((item for item in dashboard.get("live_gap_backlog", []) if item.get("area") == "browser_and_media_depth"), None)
        if browser_gap:
            print()
            print("Browser And Media Readiness")
            print(
                _table(
                    browser_gap.get("operator_checklist", []),
                    (("control", "control", 32), ("state", "state", 20), ("detail", "detail", 82)),
                )
            )
        backend_gap = next((item for item in dashboard.get("live_gap_backlog", []) if item.get("area") == "remote_backend_activation"), None)
        if backend_gap:
            print()
            print("Remote Backend Readiness")
            print(
                _table(
                    backend_gap.get("operator_checklist", []),
                    (("control", "control", 30), ("state", "state", 24), ("detail", "detail", 82)),
                )
            )

    def do_audit(self, arg: str) -> None:
        """audit [export-siem [limit]] -- show audit tail or normalized SIEM JSONL."""
        parts = shlex.split(arg)
        if parts and parts[0] == "export-siem":
            limit = int(parts[1]) if len(parts) > 1 else 1000
            _print_json(self.orchestrator.audit_logger.export_siem(limit=limit))
            return
        print(
            _table(
                self.orchestrator.audit_logger.tail(20),
                (
                    ("event", "event_type", 34),
                    ("task", "task_id", 36),
                    ("time", "timestamp", 24),
                ),
            )
        )

    def do_evidence(self, arg: str) -> None:
        """evidence [task_id] -- show task receipt and audit evidence."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        try:
            _print_evidence_bundle(self.orchestrator.evidence.build(task_id))
        except KeyError:
            print(f"task not found: {task_id}")

    def do_timeline(self, arg: str) -> None:
        """timeline [task_id] -- show ordered plan, receipt, and audit events."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        try:
            _print_task_timeline(self.orchestrator.evidence.timeline(task_id))
        except KeyError:
            print(f"task not found: {task_id}")

    def do_events(self, arg: str) -> None:
        """events [task_id] -- show grouped run-event progress for a task."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        try:
            _print_run_events(self.orchestrator.evidence.run_events(task_id))
        except KeyError:
            print(f"task not found: {task_id}")

    def do_help(self, arg: str) -> None:
        """help -- show command reference."""
        print(_command_reference())

    def do_menu(self, arg: str) -> None:
        """menu -- show the grouped command menu."""
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        print(_command_menu(width))

    def do_menus(self, arg: str) -> None:
        """menus -- show the grouped command menu."""
        self.do_menu(arg)

    def do_exit(self, arg: str) -> bool:
        """exit -- quit."""
        return True

    def do_quit(self, arg: str) -> bool:
        """quit -- quit."""
        return True

    def do_EOF(self, arg: str) -> bool:  # noqa: N802 - cmd hook name.
        print()
        return True

    def default(self, line: str) -> bool | None:
        stripped = line.strip()
        if not stripped:
            return
        if stripped.startswith("/"):
            command = stripped[1:].strip()
            if not command:
                return
            name = command.split(maxsplit=1)[0]
            if name in {"q", "quit"}:
                return self.do_quit("")
            if hasattr(self, f"do_{name}"):
                return bool(self.onecmd(command))
            print(f"unknown slash command: /{name}")
            return
        self.do_submit(stripped)

    def _load_or_create_session(
        self,
        *,
        workspace: str | Path,
        session_id: str | None,
        model: str | None,
        personality: str | None,
    ) -> dict[str, Any]:
        if session_id:
            session = self.orchestrator.sessions.get_session(session_id)
            if model and session.get("model") and session["model"] != model:
                raise ValueError(f"session {session_id} already uses model {session['model']}")
            if personality and session.get("personality") and session["personality"] != personality:
                raise ValueError(f"session {session_id} already uses personality {session['personality']}")
            return session
        return self.orchestrator.sessions.create_session(
            title="Aegis TUI",
            channel="terminal",
            model=model or "alias/smart",
            personality=personality,
            metadata={"workspace": str(Path(workspace).expanduser().resolve())},
        )

    def _render_dashboard(self) -> str:
        dashboard = build_product_dashboard(self.orchestrator)
        runtime = dashboard["runtime"]
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        lines = [
            _aegis_logo(width),
            _banner("Aegis Agent Command Deck", width),
            _stat_line(
                (
                    ("audit", "ok" if runtime["audit_chain_ok"] else "failed"),
                    ("channels", runtime["channels"]),
                    ("tools", runtime["tools"]),
                    ("approval tools", runtime["approval_gated_tools"]),
                ),
                width,
            ),
            _stat_line(
                (
                    ("providers", runtime["model_providers"]),
                    ("pending", runtime["pending_approvals"]),
                    ("session", _short_id(self.session["id"])),
                ),
                width,
            ),
            _section(
                "Command Palette",
                _command_palette_lines(compact=True),
                width,
            ),
            _section(
                "Security Control Center",
                [
                    f"{control['name']}: {control['state']} - {control['detail']}"
                    for control in dashboard["security_controls"][:3]
                ],
                width,
            ),
            _section(
                "Capability Coverage",
                [
                    f"{item['name']}: {item['state']} ({item['coverage']})"
                    for item in dashboard["capability_groups"][:4]
                ],
                width,
            ),
            _section(
                "Implementation Readiness",
                [
                    f"{item['label']}: {item['count']} tools ({', '.join(item.get('statuses', [])[:3]) or item['state']})"
                    for item in dashboard.get("implementation_readiness", [])
                ],
                width,
            ),
            _section(
                "Competitive Parity",
                [
                    f"{target['platform']}: live gap - {target['live_gap']}"
                    for target in dashboard.get("competitive_targets", [])
                ],
                width,
            ),
            _section(
                "Live Gap Backlog",
                [
                    f"{item['area']}: {item['status']} - gates {', '.join(item.get('verification_gates', [])[:3]) or 'none'} - hardened {', '.join(control.get('control', 'unknown') for control in item.get('implemented_hardening_controls', [])[:8]) or 'none'} - remaining {', '.join(item.get('remaining_depth_work', [])[:3]) or 'none'} - evals {', '.join(item.get('evaluation_scenarios', [])[:2]) or 'none'} - live adapters {', '.join(adapter.get('name', 'unknown') for adapter in item.get('implemented_live_adapters', [])[:3]) or 'none'} - backend adapters {', '.join(adapter.get('name', 'unknown') for adapter in item.get('implemented_backend_adapters', [])[:3]) or 'none'}"
                    for item in dashboard.get("live_gap_backlog", [])
                ],
                width,
            ),
            _section(
                "Commands",
                [
                    "Type a plain request to submit a task.",
                    "Operate: dashboard | tasks [all|session <id>] | session | status [task] | resume [task] | pause [task] | cancel [task]",
                    "Govern: approvals | approval <id> | approve <id> | deny <id> | security | audit | evidence [task] | timeline [task] | events [task]",
                    "Build: models | tools | skills | memory | mcp | repairs | repair <id> | schedules | schedule ...",
                    "Explore: capabilities | connectors | channels | browser ... | boards | backends",
                    "Slash aliases work too, for example /tasks or /submit summarize this repo.",
                ],
                width,
            ),
        ]
        return "\n".join(lines)


def run_tui(
    *,
    data_dir: str | Path = ".aegis",
    workspace: str | Path = ".",
    session_id: str | None = None,
    model: str | None = None,
    personality: str | None = None,
) -> None:
    AegisTui(data_dir=data_dir, workspace=workspace, session_id=session_id, model=model, personality=personality).cmdloop()


def _compact_task(task: dict[str, object]) -> dict[str, object]:
    model_response = _model_response(task)
    return {
        "id": task["id"],
        "status": task["status"],
        "risk_level": task["risk_level"],
        "interpretation": task["interpretation"],
        "checkpoint": task["checkpoint"],
        "receipt_result": task["receipt"]["result"] if task.get("receipt") else None,
        "model_status": model_response.get("status") if model_response else None,
        "model": model_response.get("identifier") if model_response else None,
    }


def _print_task_result(task: dict[str, object]) -> None:
    _print_task_card(task)
    model_response = _model_response(task)
    if model_response and model_response.get("status") == "completed":
        content = str(model_response.get("content", "")).strip()
        if content:
            print()
            print(_paint("Model Response", "36;1"))
            print(textwrap.fill(content, width=min(shutil.get_terminal_size((100, 24)).columns, 100)))
            print()
    elif model_response and model_response.get("status") == "failed":
        print(_paint(f"model failed: {model_response.get('error', 'unknown error')}", "31;1"))
    elif model_response and model_response.get("status") == "blocked":
        print(_paint(f"model blocked: {model_response.get('reason', 'policy gate')}", "33;1"))


def _print_task_card(task: dict[str, object]) -> None:
    compact = _compact_task(task)
    width = min(shutil.get_terminal_size((100, 24)).columns, 100)
    status = str(compact["status"])
    status_color = "32;1" if status == "completed" else "33;1" if status == "waiting_approval" else "31;1" if status in {"failed", "blocked"} else "36;1"
    rows = [
        f"id       {_short_id(task['id'])}  ({task['id']})",
        f"status   {_paint(status, status_color)}",
        f"risk     {compact['risk_level']}",
        f"receipt  {compact['receipt_result'] or 'pending'}",
    ]
    session_line = _session_summary_line(task)
    if session_line:
        rows.append(session_line)
    if compact.get("model_status"):
        rows.append(f"model    {compact['model_status']} {compact.get('model') or ''}".rstrip())
    checkpoint = compact.get("checkpoint")
    if isinstance(checkpoint, dict) and checkpoint.get("admin_required"):
        rows.append("approval admin required")
    print()
    print(_paint("Task", "36;1"))
    print("-" * min(width, 36))
    print("\n".join(rows))
    _print_action_hints(task)
    print(textwrap.fill(f"plan     {compact['interpretation']}", width=width, subsequent_indent="         "))
    if isinstance(checkpoint, dict) and checkpoint.get("approval_id"):
        approval_id = str(checkpoint["approval_id"])
        admin_flag = " --admin" if checkpoint.get("admin_required") else ""
        print(_paint(f"next     approve {approval_id}{admin_flag}", "33;1"))
        print(_paint(f"         resume {task['id']}", "33;1"))
    print()


def _print_approval_result(approval: dict[str, Any]) -> None:
    status = str(approval.get("status", "unknown"))
    task_id = str(approval.get("task_id") or "")
    print()
    print(_paint("Approval", "36;1"))
    print("-" * 36)
    print(f"id       {approval.get('id')}")
    print(f"status   {status}")
    print(f"risk     {approval.get('risk_level')}")
    session_line = _session_summary_line(approval)
    if session_line:
        print(session_line)
    if approval.get("session_id"):
        print(_paint(f"next     session open {approval.get('session_id')}", "33;1"))
        print(_paint(f"         session history {approval.get('session_id')}", "33;1"))
    print(textwrap.fill(f"reason   {approval.get('reason')}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="         "))
    decision = approval.get("decision")
    if isinstance(decision, dict):
        print(f"actor    {decision.get('actor')}{' (admin)' if decision.get('admin') else ''}")
        if decision.get("reason"):
            print(textwrap.fill(f"decision {decision.get('reason')}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="         "))
    if status == "approved" and task_id:
        print(_paint(f"next     resume {task_id}", "33;1"))
    print()


def _print_approval_detail(approval: dict[str, Any]) -> None:
    payload = approval.get("payload", {})
    step = payload.get("step") if isinstance(payload, dict) else None
    if not isinstance(step, dict):
        step = payload.get("action", {}) if isinstance(payload, dict) else {}
    print()
    print(_paint("Approval Review", "36;1"))
    print("-" * 36)
    print(f"id       {approval.get('id')}")
    print(f"status   {approval.get('status')}")
    print(f"risk     {approval.get('risk_level')}")
    print(f"task     {approval.get('task_id') or ''}")
    session_line = _session_summary_line(approval)
    if session_line:
        print(session_line)
    if approval.get("session_id"):
        print(_paint(f"next     session open {approval.get('session_id')}", "33;1"))
        print(_paint(f"         session history {approval.get('session_id')}", "33;1"))
    if isinstance(payload, dict) and payload.get("admin_required"):
        print("approval admin required")
    print(textwrap.fill(f"reason   {approval.get('reason')}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="         "))
    decision = approval.get("decision")
    if isinstance(decision, dict):
        print(f"actor    {decision.get('actor')}{' (admin)' if decision.get('admin') else ''}")
        if decision.get("reason"):
            print(textwrap.fill(f"decision {decision.get('reason')}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="         "))
    if step:
        print(_paint("requested step", "36;1"))
        print(textwrap.indent(json.dumps(step, indent=2, sort_keys=True), "  "))
    if isinstance(payload, dict):
        print(_paint("payload", "36;1"))
        print(textwrap.indent(json.dumps(payload, indent=2, sort_keys=True), "  "))
    admin_flag = " --admin" if isinstance(payload, dict) and payload.get("admin_required") else ""
    print(_paint(f"next     approve {approval.get('id')}{admin_flag}  OR  deny {approval.get('id')}{admin_flag}", "33;1"))
    print()


def _print_repair_detail(proposal: dict[str, Any]) -> None:
    metadata = proposal.get("metadata", {})
    attempts = metadata.get("repair_attempts", []) if isinstance(metadata, dict) else []
    candidates = metadata.get("repair_candidates", []) if isinstance(metadata, dict) else []
    print()
    print(_paint("Repair Proposal", "36;1"))
    print("-" * 36)
    print(f"id       {proposal.get('id')}")
    print(f"status   {proposal.get('status')}")
    print(f"kind     {proposal.get('kind')}")
    print(f"task     {proposal.get('task_id') or ''}")
    print(f"default  {proposal.get('default_state')}")
    print(textwrap.fill(f"summary  {proposal.get('summary')}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="         "))
    evidence = proposal.get("evidence", [])
    if evidence:
        print(_paint("evidence", "36;1"))
        for item in evidence[:8]:
            print(textwrap.fill(f"- {item}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="  "))
    if isinstance(metadata, dict) and metadata:
        print(_paint("metadata", "36;1"))
        print(textwrap.indent(json.dumps(metadata, indent=2, sort_keys=True), "  "))
    if attempts:
        print(_paint("attempts", "36;1"))
        for attempt in attempts[-5:]:
            print(textwrap.fill(f"- {attempt.get('status')}: {attempt.get('outcome')}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="  "))
    if candidates:
        print(_paint("candidates", "36;1"))
        for candidate in candidates[-5:]:
            review_status = candidate.get("review_status", "pending")
            print(textwrap.fill(f"- {candidate.get('id')}: [{review_status}] {candidate.get('summary')}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="  "))
    status = proposal.get("status")
    if status == "proposed":
        print(_paint(f"next     repair review {proposal.get('id')}", "33;1"))
    elif status == "reviewing":
        print(_paint(f"next     repair candidate {proposal.get('id')} <summary>", "33;1"))
        print(_paint(f"         repair approve {proposal.get('id')}  OR  repair reject {proposal.get('id')}", "33;1"))
    elif status == "approved":
        for candidate in candidates[-3:]:
            if candidate.get("status") == "applied_pending_verification":
                print(_paint(f"next     repair rollback-candidate {proposal.get('id')} {candidate.get('id')}", "33;1"))
            elif candidate.get("patch") and candidate.get("review_status") != "approved":
                print(_paint(f"next     repair review-candidate {proposal.get('id')} {candidate.get('id')} approved", "33;1"))
            elif candidate.get("patch"):
                print(_paint(f"next     repair apply-candidate {proposal.get('id')} {candidate.get('id')}", "33;1"))
        print(_paint(f"next     repair attempt {proposal.get('id')} <outcome>", "33;1"))
    print()


def _print_evidence_bundle(bundle: dict[str, Any]) -> None:
    task = bundle["task"]
    receipt = task.get("receipt") if isinstance(task.get("receipt"), dict) else None
    audit_tail = bundle.get("audit_tail", [])
    width = min(shutil.get_terminal_size((100, 24)).columns, 100)
    print()
    print(_paint("Evidence", "36;1"))
    print("-" * min(width, 36))
    print(f"task     {_short_id(task['id'])}  ({task['id']})")
    print(f"status   {task['status']}")
    session_line = _session_summary_line(task)
    if session_line:
        print(session_line)
    _print_action_hints(task)
    print(textwrap.fill(f"plan     {task['interpretation']}", width=width, subsequent_indent="         "))
    if receipt:
        print(f"receipt  {receipt.get('result', 'unknown')}")
        actions = receipt.get("actions", [])
        if actions:
            print(_paint("actions", "36;1"))
            for action in actions[:8]:
                print(textwrap.fill(f"- {_stringify(action)}", width=width, subsequent_indent="  "))
    checkpoint = task.get("checkpoint")
    if isinstance(checkpoint, dict) and checkpoint:
        print(_paint("checkpoint", "36;1"))
        for key, value in checkpoint.items():
            print(textwrap.fill(f"{key}: {_stringify(value)}", width=width, subsequent_indent="  "))
    if audit_tail:
        rows = [
            {
                "event_type": row.get("event_type"),
                "timestamp": row.get("timestamp"),
                "details": row.get("payload", {}),
            }
            for row in audit_tail[-10:]
        ]
        print(_paint("audit", "36;1"))
        print(_table(rows, (("event", "event_type", 34), ("time", "timestamp", 24), ("details", "details", 42))))
    else:
        print("audit    no task-specific audit entries")
    print()


def _print_task_timeline(timeline: dict[str, Any]) -> None:
    rows = []
    for index, item in enumerate(timeline.get("items", []), start=1):
        details = item.get("details", {})
        detail = _timeline_detail(details)
        rows.append(
            {
                "index": index,
                "kind": item.get("kind", ""),
                "status": item.get("status", ""),
                "when": item.get("timestamp") or f"step {item.get('sequence', '')}".strip(),
                "title": item.get("title", ""),
                "detail": detail,
            }
        )
    print()
    print(_paint("Timeline", "36;1"))
    print("-" * 36)
    print(f"task     {_short_id(timeline.get('task_id', ''))}  ({timeline.get('task_id', '')})")
    print(f"status   {timeline.get('status', '')}")
    session_line = _session_summary_line(timeline)
    if session_line:
        print(session_line)
    _print_action_hints(timeline)
    if rows:
        print(
            _table(
                rows,
                (
                    ("#", "index", 4),
                    ("kind", "kind", 12),
                    ("status", "status", 12),
                    ("when", "when", 24),
                    ("title", "title", 34),
                    ("detail", "detail", 48),
                ),
            )
        )
    else:
        print("no timeline entries")
    print()


def _print_run_events(snapshot: dict[str, Any]) -> None:
    progress = snapshot.get("progress", {}) if isinstance(snapshot.get("progress"), dict) else {}
    print()
    print(_paint("Run Events", "36;1"))
    print("-" * 36)
    print(f"task     {_short_id(snapshot.get('task_id', ''))}  ({snapshot.get('task_id', '')})")
    print(f"status   {snapshot.get('status', '')}")
    session_line = _session_summary_line(snapshot)
    if session_line:
        print(session_line)
    _print_action_hints(snapshot)
    print(
        "progress "
        f"steps={progress.get('completed_steps', 0)}/{progress.get('total_steps', 0)} "
        f"waiting={progress.get('waiting_steps', 0)} failed={progress.get('failed_steps', 0)} "
        f"events={progress.get('total_events', 0)} latest={progress.get('latest_sequence', 0)}"
    )
    event_rows = [
        {"key": key, "count": count}
        for key, count in (progress.get("events_by_kind") or {}).items()
    ]
    if event_rows:
        print(_paint("event kinds", "36;1"))
        print(_table(event_rows, (("kind", "key", 24), ("count", "count", 8))))
    step_rows = [
        {
            "step": row.get("title", ""),
            "status": row.get("status", ""),
            "events": row.get("event_count", 0),
            "latest": row.get("latest_event") or "",
        }
        for row in snapshot.get("step_groups", [])[:12]
    ]
    if step_rows:
        print(_paint("steps", "36;1"))
        print(_table(step_rows, (("step", "step", 34), ("status", "status", 12), ("events", "events", 8), ("latest", "latest", 42))))
    provider_rows = [
        {
            "tool": row.get("identifier") or row.get("provider") or "",
            "operation": row.get("operation", ""),
            "kind": row.get("kind", ""),
            "status": row.get("status", ""),
            "events": row.get("event_count", row.get("sequence", "")),
        }
        for row in snapshot.get("provider_substeps", [])[:12]
    ]
    if provider_rows:
        print(_paint("provider substeps", "36;1"))
        print(_table(provider_rows, (("tool", "tool", 20), ("operation", "operation", 18), ("kind", "kind", 12), ("status", "status", 12), ("events", "events", 8))))
    recent_rows = [
        {
            "seq": row.get("sequence"),
            "kind": row.get("kind", ""),
            "status": row.get("status", ""),
            "tool": row.get("tool", ""),
            "summary": row.get("summary", ""),
        }
        for row in snapshot.get("events", [])[-12:]
    ]
    if recent_rows:
        print(_paint("recent", "36;1"))
        print(_table(recent_rows, (("#", "seq", 5), ("kind", "kind", 12), ("status", "status", 12), ("tool", "tool", 20), ("summary", "summary", 54))))
    else:
        print("events   no run events")
    print()


def _timeline_detail(details: Any) -> str:
    if not isinstance(details, dict):
        return _stringify(details)
    context_refs = []
    for key in ("resolved_context_ref", "task_context_ref", "requested_context_ref"):
        value = details.get(key)
        if value:
            context_refs.append(f"{key.removesuffix('_context_ref')}={value}")
    if context_refs:
        return "context " + ", ".join(context_refs)
    return details.get("error") or details.get("reason") or details.get("from") or details.get("to") or _stringify(details)


def _session_summary_line(payload: dict[str, Any]) -> str | None:
    session = payload.get("session")
    if isinstance(session, dict):
        title = session.get("title") or "missing session"
        return f"session  {_short_id(session.get('id', payload.get('session_id', '')))}  {title}"
    if payload.get("session_id"):
        return f"session  {_short_id(payload.get('session_id'))}"
    return None


def _print_action_hints(payload: dict[str, Any]) -> None:
    hints = payload.get("action_hints", [])
    if not isinstance(hints, list):
        return
    commands = [_tui_action_command(hint) for hint in hints if isinstance(hint, dict)]
    commands = [command for command in commands if command]
    if not commands:
        return
    print(_paint(f"next     {'; '.join(commands)}", "33;1"))


def _tui_action_command(hint: dict[str, Any]) -> str:
    action = str(hint.get("action") or "")
    session_id = str(hint.get("session_id") or "")
    task_id = str(hint.get("task_id") or "")
    if action == "session_show" and session_id:
        return f"session open {session_id}"
    if action == "session_history" and session_id:
        return f"session history {session_id}"
    if action == "task_resume" and task_id:
        return f"resume {task_id}"
    command = hint.get("command")
    return str(command) if command else ""


def _model_response(task: dict[str, object]) -> dict[str, object] | None:
    receipt = task.get("receipt")
    if not isinstance(receipt, dict):
        return None
    response = receipt.get("model_response")
    return response if isinstance(response, dict) else None


def _model_content(task: dict[str, object]) -> str | None:
    response = _model_response(task)
    if not response or response.get("status") != "completed":
        return None
    content = str(response.get("content", "")).strip()
    return content or None


def _print_json(payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _flag_float(parts: list[str], flag: str, *, default: float | None) -> float | None:
    if flag not in parts:
        return default
    index = parts.index(flag)
    if index + 1 >= len(parts):
        raise ValueError(f"{flag} requires a value")
    return float(parts[index + 1])


def _flag_int(parts: list[str], flag: str, *, default: int | None) -> int | None:
    if flag not in parts:
        return default
    index = parts.index(flag)
    if index + 1 >= len(parts):
        raise ValueError(f"{flag} requires a value")
    return int(parts[index + 1])


def _flag_joined_value(parts: list[str], flag: str) -> str | None:
    if flag not in parts:
        return None
    index = parts.index(flag)
    if index + 1 >= len(parts):
        raise ValueError(f"{flag} requires a value")
    value_parts: list[str] = []
    for value in parts[index + 1 :]:
        if value.startswith("--"):
            break
        value_parts.append(value)
    if not value_parts:
        raise ValueError(f"{flag} requires a value")
    return " ".join(value_parts)


def _flag_values(parts: list[str], flag: str) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(parts):
        if parts[index] == flag and index + 1 < len(parts):
            values.append(parts[index + 1])
            index += 2
            continue
        index += 1
    return values


def _positional_without_flags(parts: list[str], flags: dict[str, int]) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(parts):
        flag_width = flags.get(parts[index])
        if flag_width is not None:
            index += 1 + flag_width
            continue
        values.append(parts[index])
        index += 1
    return values


def _command_reference() -> str:
    width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
    return "\n".join(
        (
            _aegis_logo(width),
            _paint("Aegis TUI Commands", "36;1"),
            "",
            _command_menu(width),
            "",
            "submit <request>       Submit a governed task",
            "status [task_id]       Show task state and receipt",
            "resume [task_id]       Continue after approval",
            "pause [task_id]        Pause a non-terminal task",
            "cancel [task_id]       Cancel a non-terminal task",
            "tasks [all|session <id>]  Recent active-session tasks, all tasks, or another session",
            "session                Show active session context",
            "session new|open       Create or switch conversation sessions",
            "session history|tasks  Show active session transcript or tasks",
            "evidence [task_id]     Show receipt and audit evidence",
            "timeline [task_id]     Show plan, receipt, and audit sequence",
            "events [task_id]       Show grouped run-event progress",
            "approvals              Pending approvals",
            "approval <id>          Inspect approval payload before action",
            "approve <id> [--admin] Approve a gated action",
            "deny <id> [--admin]    Deny a gated action",
            "dashboard              Runtime command deck",
            "menu                   Grouped command menu",
            "security               Security controls",
            "capabilities           Capability groups",
            "connectors             Connector health",
            "channels               Channel adapters",
            "channel render <c> <t>  Render outbound channel payload",
            "channel receive <c> <t> Normalize inbound channel payload",
            "channel events [limit]  Recent channel activity",
            "models                 Model providers",
            "models auth login|logout <provider>",
            "tools                  Governed tool catalog",
            "tools run <name> <json> Run a governed tool",
            "skills [hub query]     Governed skills and virtual Skill Hub",
            "memory search|session-preview|create|update|merge|expire",
            "mcp list|register|call Governed MCP registry",
            "repairs [status]       List self-repair proposals",
            "repair <id>            Inspect self-repair proposal evidence",
            "repair review|approve|reject <id>",
            "repair synthesis-prompt <id>",
            "repair synthesize-candidate <id> <json_file>",
            "repair review-candidate <id> <candidate_id> <approved|rejected>",
            "repair apply-candidate|rollback-candidate <id> <candidate_id>",
            "repair attempt <id> <outcome> [--candidate-id id] [--test-command cmd]",
            "schedules              Scheduled automations",
            "schedule create <n> <c> <task>",
            "schedule memory-review-digest <n> <c>",
            "schedule evaluation-run <n> <c> <scenario>",
            "schedule evaluation-suite <n> <c>",
            "schedule due",
            "schedule approve|activate|pause <id>",
            "schedule run-due",
            "browser session|sessions|close|navigate <url>",
            "browser extract|inspect|screenshot|render|click <selector>|fill <json>",
            "boards                 Work boards and cards",
            "backends               Execution backends",
            "audit                  Audit tail",
            "exit                   Quit",
            "",
            "Plain text submits a task. Slash aliases such as /tasks also work.",
        )
    )


def _aegis_logo(width: int) -> str:
    art = [
        r"      ___       ______   _______   ___   _______",
        r"     /   \     |  ____| |  _____| |_ _| /  _____|",
        r"    /  ^  \    | |__    | |  __    | |  | |_____",
        "   /  /_\\  \\   |  __|   | | |_ |   | |  \\_____  \\",
        r"  /  _____  \  | |____  | |__| |   | |   _____| |",
        r" /__/     \__\ |______| |_______| |___| |_______/",
        r"        AEGIS SHIELD :: governed local agent",
    ]
    return _boxed_lines("Aegis Identity", art, width)


COMMAND_MENU_GROUPS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    (
        "Operate",
        (
            ("submit <request>", "start a governed task"),
            ("dashboard", "runtime command deck"),
            ("tasks [all|session <id>]", "recent task lanes"),
            ("session", "active transcript context"),
            ("status|resume|pause|cancel", "task controls"),
        ),
    ),
    (
        "Govern",
        (
            ("approvals", "pending gates"),
            ("approval <id>", "inspect before action"),
            ("approve|deny <id>", "decide gated work"),
            ("security", "policy posture"),
            ("audit|evidence|timeline|events", "receipts and replay"),
        ),
    ),
    (
        "Build",
        (
            ("models", "provider routes and auth"),
            ("tools run <name> <json>", "safe tool execution"),
            ("skills [hub query]", "governed skill hub"),
            ("memory search|create|review", "durable memory"),
            ("mcp|repair|schedules", "extensions and self-repair"),
        ),
    ),
    (
        "Explore",
        (
            ("capabilities", "parity and readiness"),
            ("connectors|channels", "integration surfaces"),
            ("browser session|render", "sandboxed browser work"),
            ("boards|backends", "work and execution planes"),
        ),
    ),
)


def _command_palette_lines(*, compact: bool = False) -> list[str]:
    if compact:
        return [
            "Operate  submit, dashboard, tasks, session, status, resume",
            "Govern   approvals, approve, deny, security, audit, evidence",
            "Build    models, tools, skills, memory, mcp, repair",
            "Explore  capabilities, connectors, channels, browser, boards",
        ]
    lines: list[str] = []
    for group, commands in COMMAND_MENU_GROUPS:
        command_names = ", ".join(command for command, _detail in commands)
        lines.append(f"{group:<8} {command_names}")
    return lines


def _command_menu(width: int) -> str:
    lines: list[str] = []
    for group, commands in COMMAND_MENU_GROUPS:
        lines.append(f"[{group}]")
        for command, detail in commands:
            lines.append(f"  {command:<34} {detail}")
        lines.append("")
    if lines and not lines[-1]:
        lines.pop()
    return _boxed_lines("Command Menu", lines, width)


def _complete_options(options: tuple[str, ...], text: str) -> list[str]:
    return [option for option in options if option.startswith(text)]


def _complete_subcommand(options: tuple[str, ...], text: str, line: str, begidx: int) -> list[str]:
    try:
        parts = shlex.split(line[:begidx])
    except ValueError:
        return []
    if len(parts) <= 1:
        return _complete_options(options, text)
    return []


def _load_tui_history(path: Path) -> bool:
    readline = _readline_module()
    if readline is None:
        return False
    readline.set_history_length(TUI_HISTORY_LIMIT)
    if path.exists():
        readline.read_history_file(str(path))
    return True


def _save_tui_history(path: Path) -> bool:
    readline = _readline_module()
    if readline is None:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    readline.set_history_length(TUI_HISTORY_LIMIT)
    readline.write_history_file(str(path))
    path.chmod(0o600)
    return True


def _readline_module() -> Any | None:
    try:
        import readline  # type: ignore[import-not-found]
    except ImportError:
        return None
    return readline


def _banner(title: str, width: int) -> str:
    inner = width - 4
    rule = "+" + "-" * (width - 2) + "+"
    text = f"| {_paint(title.ljust(inner), '36;1')} |"
    return "\n".join(("", rule, text, rule))


def _boxed_lines(title: str, items: list[str], width: int) -> str:
    inner = width - 4
    rule = "+" + "-" * (width - 2) + "+"
    title_line = f"| {_paint(title.ljust(inner), '36;1')} |"
    body = []
    for item in items:
        for line in textwrap.wrap(item, width=inner, replace_whitespace=False, drop_whitespace=False) or [""]:
            body.append(f"| {line.ljust(inner)} |")
    return "\n".join(("", rule, title_line, rule, *body, rule))


def _section(title: str, items: list[str], width: int) -> str:
    inner = width - 4
    lines = ["", _paint(title, "36;1"), "-" * min(width, len(title) + 8)]
    for item in items:
        wrapped = textwrap.wrap(item, width=inner, replace_whitespace=True) or [""]
        lines.extend(f"  {line}" for line in wrapped)
    return "\n".join(lines)


def _stat_line(stats: tuple[tuple[str, object], ...], width: int) -> str:
    cells = [f"{label}: {_paint(str(value), '32;1')}" for label, value in stats]
    line = "  ".join(cells)
    return textwrap.shorten(line, width=width, placeholder="...")


def _table(rows: list[dict[str, Any]], columns: tuple[tuple[str, str, int], ...]) -> str:
    if not rows:
        return "no rows"
    widths = [min(max(len(label), 4), max_width) for label, _key, max_width in columns]
    for row in rows:
        for index, (_label, key, max_width) in enumerate(columns):
            widths[index] = min(max(widths[index], len(_stringify(row.get(key, ""))) + 1), max_width)

    header = " ".join(_fit(label, widths[index]) for index, (label, _key, _max) in enumerate(columns))
    rule = " ".join("-" * width for width in widths)
    body = []
    for row in rows:
        body.append(" ".join(_fit(_stringify(row.get(key, "")), widths[index]) for index, (_label, key, _max) in enumerate(columns)))
    return "\n".join((_paint(header, "36;1"), rule, *body))


def _fit(value: str, width: int) -> str:
    normalized = " ".join(value.split())
    if len(normalized) > width:
        normalized = normalized[: max(0, width - 3)] + "..."
    return normalized.ljust(width)


def _stringify(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    if value is None:
        return ""
    return str(value)


def _task_list_row(orchestrator: Any, row: dict[str, Any]) -> dict[str, Any]:
    session_label = ""
    next_actions: list[str] = []
    if row.get("session_id"):
        try:
            session = orchestrator.status(str(row["id"])).get("session")
        except KeyError:
            session = None
        if isinstance(session, dict):
            session_label = f"{_short_id(session.get('id', row.get('session_id', '')))} {session.get('title') or ''}".strip()
        else:
            session_label = _short_id(row.get("session_id", ""))
        next_actions.extend([f"session open {row['session_id']}", f"session history {row['session_id']}"])
    task_id = str(row.get("id") or "")
    if task_id:
        task_ref = _short_id(task_id)
        next_actions.extend([f"status {task_ref}", f"events {task_ref}", f"timeline {task_ref}"])
    return {**row, "short_id": _short_id(row.get("id", "")), "session_label": session_label, "next_actions": "; ".join(next_actions)}


def _approval_with_session(orchestrator: Any, approval: dict[str, Any]) -> dict[str, Any]:
    payload = dict(approval)
    payload["session_id"] = None
    payload["session"] = None
    task_id = payload.get("task_id")
    if task_id:
        try:
            task = orchestrator.status(str(task_id))
        except KeyError:
            task = {}
        payload["session_id"] = task.get("session_id")
        payload["session"] = task.get("session")
    elif isinstance(payload.get("payload"), dict):
        payload_session_id = _approval_payload_session_id(payload["payload"])
        if payload_session_id:
            payload["session_id"] = payload_session_id
            payload["session"] = _safe_session_summary(orchestrator, payload_session_id)
    return payload


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


def _safe_session_summary(orchestrator: Any, session_id: str) -> dict[str, Any] | None:
    session = orchestrator.store.get_session(session_id)
    if not session:
        return None
    return {
        "id": session["id"],
        "title": session["title"],
        "channel": session["channel"],
        "status": session["status"],
    }


def _approval_list_row(orchestrator: Any, row: dict[str, Any]) -> dict[str, Any]:
    payload = _approval_with_session(orchestrator, row)
    session_label = ""
    next_actions = f"approval {payload.get('id')}"
    session = payload.get("session")
    if isinstance(session, dict):
        session_label = f"{_short_id(session.get('id', payload.get('session_id', '')))} {session.get('title') or ''}".strip()
    elif payload.get("session_id"):
        session_label = _short_id(payload.get("session_id"))
    if payload.get("session_id"):
        next_actions = f"session open {payload.get('session_id')}; session history {payload.get('session_id')}; {next_actions}"
    return {**payload, "task_short_id": _short_id(payload.get("task_id", "")), "session_label": session_label, "next_actions": next_actions}


def _session_list_row(row: dict[str, Any]) -> dict[str, Any]:
    latest_task = row.get("latest_task")
    latest_task_label = ""
    if isinstance(latest_task, dict):
        latest_task_label = f"{_short_id(latest_task.get('id', ''))} {latest_task.get('status', '')}".strip()
    session_id = str(row.get("id") or "")
    next_actions = "; ".join(
        action
        for action in (
            f"session open {session_id}" if session_id else "",
            f"session history {session_id}" if session_id else "",
            f"tasks session {session_id}" if session_id and int(row.get("task_count") or 0) else "",
        )
        if action
    )
    return {**row, "short_id": _short_id(row.get("id", "")), "latest_task_label": latest_task_label, "next_actions": next_actions}


def _session_history_row(row: dict[str, Any]) -> dict[str, Any]:
    content = str(row.get("content", ""))
    metadata = row.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    task_id = str(metadata.get("task_id") or "")
    current_task_status = str(row.get("current_task_status") or "")
    current_approval_status = str(row.get("current_approval_status") or "")
    metadata_status = str(metadata.get("status") or "")
    meta = " ".join(
        part
        for part in (
            str(metadata.get("source") or ""),
            f"task:{_short_id(task_id)}" if task_id else "",
            metadata_status,
            f"current:{current_task_status}" if current_task_status and current_task_status != metadata_status else "",
            f"approval:{current_approval_status}" if current_approval_status else "",
        )
        if part
    )
    action_hints = row.get("action_hints", [])
    if isinstance(action_hints, list) and action_hints:
        next_actions = "; ".join(str(hint.get("command", "")) for hint in action_hints if isinstance(hint, dict) and hint.get("command"))
    else:
        next_actions = f"status {task_id[:8]}; events {task_id[:8]}; timeline {task_id[:8]}" if task_id else ""
    return {**row, "content": content.replace("\n", " ")[:180], "meta": meta, "next_actions": next_actions}


def _schedule_list_row(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "short_id": _short_id(row.get("id", ""))}


def _parse_repair_attempt_args(parts: list[str]) -> tuple[str, list[str]]:
    if not parts:
        raise ValueError("repair outcome required")
    if "--changed-file" in parts:
        index = parts.index("--changed-file")
        outcome = " ".join(parts[:index]).strip()
        changed_files = [value for value in parts[index + 1 :] if value != "--changed-file"]
    else:
        outcome = parts[0]
        changed_files = parts[1:]
    if not outcome:
        raise ValueError("repair outcome required")
    if not changed_files:
        raise ValueError("implemented repair attempts require changed-file evidence")
    return outcome, changed_files


def _parse_repair_attempt_command(parts: list[str]) -> tuple[str, list[str], str | None, str, str]:
    candidate_id = _option_value(parts, "--candidate-id")
    test_command = _option_value(parts, "--test-command") or "python3 -c 'print(\"tui repair verified\")'"
    test_result = _option_value(parts, "--test-result") or "passed"
    for option in ("--candidate-id", "--test-command", "--test-result"):
        parts = _without_option(parts, option)
    outcome, changed_files = _parse_repair_attempt_args(parts)
    return outcome, changed_files, candidate_id, test_command, test_result


def _without_option(parts: list[str], option: str) -> list[str]:
    if option not in parts:
        return parts
    index = parts.index(option)
    if index + 1 >= len(parts):
        raise ValueError(f"{option} requires a value")
    return parts[:index] + parts[index + 2 :]


def _option_value(parts: list[str], option: str) -> str | None:
    if option not in parts:
        return None
    index = parts.index(option)
    if index + 1 >= len(parts):
        raise ValueError(f"{option} requires a value")
    return parts[index + 1]


def _option_values(parts: list[str], option: str) -> list[str]:
    values = []
    for index, part in enumerate(parts):
        if part != option:
            continue
        if index + 1 >= len(parts):
            raise ValueError(f"{option} requires a value")
        values.append(parts[index + 1])
    return values


def _split_json_approval_arg(value: str) -> tuple[str, str | None]:
    marker = " --approval-id "
    if marker not in value:
        return value, None
    json_text, approval_id = value.rsplit(marker, 1)
    return json_text.strip(), approval_id.strip() or None


def _browser_action_approval(
    orchestrator: Any,
    *,
    action: str,
    session_id: str,
    selector: str | None = None,
    fields: dict[str, Any] | None = None,
    approval_id: str | None = None,
) -> dict[str, Any]:
    payload = _browser_action_payload(action=action, session_id=session_id, selector=selector, fields=fields)
    if approval_id:
        approval = orchestrator.approvals.get(approval_id)
        if _approved_payload(approval) != payload:
            raise PermissionError("browser approval does not match requested action")
        if approval["status"] == "denied":
            return {"approved": False, "response": {"status": "approval_denied", "approval_id": approval["id"], "action": action}}
        if approval["status"] != "approved":
            return {"approved": False, "response": {"status": "approval_required", "approval_id": approval["id"], "action": action}}
        return {"approved": True}
    approval = orchestrator.approvals.request_approval(
        ApprovalRequest(
            task_id=None,
            reason=f"browser {action} requires approval",
            risk_level=RiskLevel.HIGH,
            payload=payload,
        )
    )
    return {
        "approved": False,
        "response": {
            "status": "approval_required",
            "approval_id": approval.id,
            "action": action,
            "session_id": session_id,
            "reason": f"browser {action} requires approval",
        },
    }


def _browser_action_payload(*, action: str, session_id: str, selector: str | None = None, fields: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"kind": "browser_action", "action": action, "session_id": session_id}
    if action == "click":
        payload["selector"] = selector or ""
        return payload
    if action == "fill":
        safe_fields = {str(key): str(value) for key, value in (fields or {}).items()}
        encoded = json.dumps(safe_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload["field_selectors"] = sorted(safe_fields)
        payload["fields_sha256"] = hashlib.sha256(encoded).hexdigest()
        return payload
    raise ValueError(f"unsupported browser approval action: {action}")


def _approved_payload(approval: dict[str, Any]) -> dict[str, Any]:
    payload = dict(approval.get("payload", {}))
    payload.pop("_decision", None)
    return payload


def _skill_enable_approval_refs(orchestrator: Any) -> dict[str, str]:
    refs: dict[str, str] = {}
    for status in ("approved", "pending"):
        for approval in orchestrator.approvals.list(status=status):
            payload = approval.get("payload", {})
            if not isinstance(payload, dict) or payload.get("kind") != "skill_enable":
                continue
            skill_id = str(payload.get("skill_id", ""))
            if skill_id:
                refs[skill_id] = f"{status}:{_short_id(approval.get('id', ''))}"
    return refs


def _short_id(value: object) -> str:
    return str(value)[:8]


def _paint(text: str, code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"
