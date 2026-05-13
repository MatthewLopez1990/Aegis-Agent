"""Dependency-free terminal UI for Aegis Agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import cmd
import getpass
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import textwrap

from aegis.agent.orchestrator import build_orchestrator
from aegis.approvals.actions import approval_action_hints
from aegis.approvals.models import ApprovalRequest
from aegis.audit.logger import redact
from aegis.channels.base import ChannelResponse
from aegis.hooks.manager import HOOK_EVENTS
from aegis.memory.models import MemoryType
from aegis.migration.openclaw import inspect_hermes_home, inspect_openclaw_home, preview_hermes_memory_import, preview_openclaw_memory_import
from aegis.personality.context import ContextFileLoader
from aegis.product.capabilities import build_product_dashboard
from aegis.product.setup import build_setup_readiness
from aegis.remote_control import (
    RemoteControlPairingRegistry,
    build_remote_control_directory,
    build_remote_control_notification,
    build_remote_control_task_events,
    build_remote_control_task_status,
)
from aegis.research.harness import ResearchHarness
from aegis.security.policy_engine import PolicyRequest
from aegis.security.policy_profile import activate_due_policy_rollouts, apply_policy_bundle, diff_policy_bundle, import_policy_bundle, list_policy_bundles, list_policy_promotions, list_policy_rollouts, policy_profile_to_dict, promote_policy_bundle, rollback_policy_bundle, schedule_policy_bundle
from aegis.security.taint import RiskLevel, Sensitivity, TrustClass, now_utc
from aegis.skills.runtime import SkillRuntime
from aegis.skills.signing import DEFAULT_SKILL_SIGNING_KEY


TOP_LEVEL_COMMANDS = (
    "approval",
    "approvals",
    "app",
    "audit",
    "add-dir",
    "agents",
    "allowed-tools",
    "android",
    "autofix-pr",
    "approve",
    "backends",
    "batch",
    "background",
    "bg",
    "btw",
    "boards",
    "branch",
    "browser",
    "bashes",
    "bug",
    "busy",
    "cancel",
    "capabilities",
    "channel",
    "channels",
    "chrome",
    "claude-api",
    "clear",
    "checkpoint",
    "compact",
    "compress",
    "config",
    "connectors",
    "continue",
    "commands",
    "copy",
    "cost",
    "color",
    "cron",
    "context",
    "curator",
    "dashboard",
    "debug",
    "deny",
    "desktop",
    "details",
    "diff",
    "doctor",
    "evidence",
    "events",
    "evaluation",
    "exit",
    "effort",
    "export",
    "extra-usage",
    "fast",
    "feedback",
    "fewer-permission-prompts",
    "focus",
    "footer",
    "fork",
    "gateway",
    "goal",
    "gquota",
    "handoff",
    "help",
    "history",
    "hooks",
    "heapdump",
    "image",
    "ide",
    "indicator",
    "insights",
    "init",
    "install-github-app",
    "install-slack-app",
    "ios",
    "kanban",
    "keybindings",
    "login",
    "logout",
    "loop",
    "mcp",
    "memory",
    "menu",
    "menus",
    "migrate",
    "mobile",
    "model",
    "models",
    "mouse",
    "new",
    "pause",
    "paste",
    "plan",
    "platforms",
    "permissions",
    "personality",
    "passes",
    "profile",
    "process",
    "processes",
    "plugin",
    "plugins",
    "powerup",
    "proactive",
    "pr_comments",
    "privacy-settings",
    "provider",
    "prompt",
    "q",
    "quit",
    "queue",
    "radio",
    "rc",
    "recap",
    "redraw",
    "release-notes",
    "reload",
    "reload-plugins",
    "reload-mcp",
    "reload_mcp",
    "reload-skills",
    "reload_skills",
    "remote-control",
    "remote-env",
    "repair",
    "repairs",
    "reset",
    "reasoning",
    "restart",
    "resume",
    "retry",
    "review",
    "rename",
    "rewind",
    "rollback",
    "routines",
    "save",
    "sandbox",
    "schedule",
    "schedules",
    "scroll-speed",
    "security",
    "security-review",
    "session",
    "sessions",
    "setup",
    "setup-bedrock",
    "setup-vertex",
    "settings",
    "set-home",
    "sethome",
    "simplify",
    "skills",
    "skin",
    "snap",
    "snapshot",
    "sb",
    "status",
    "statusline",
    "statusbar",
    "stats",
    "steer",
    "stickers",
    "stop",
    "submit",
    "task",
    "tasks",
    "teleport",
    "terminal-setup",
    "team-onboarding",
    "theme",
    "timeline",
    "title",
    "topic",
    "toolsets",
    "tools",
    "tp",
    "tui",
    "ultraplan",
    "ultrareview",
    "undo",
    "upgrade",
    "update",
    "usage",
    "vim",
    "verbose",
    "voice",
    "web-setup",
    "whoami",
    "yolo",
)
MEMORY_COMMANDS = ("search", "health", "session-preview", "session-commit", "create", "review-queue", "review-digest", "review-action", "review-batch", "recertify", "update", "merge", "resolve-conflict", "expire", "cleanup-expired", "explain", "export", "delete")
MIGRATE_COMMANDS = ("openclaw", "hermes", "openclaw-memory-preview", "hermes-memory-preview", "openclaw-memory-commit", "hermes-memory-commit")
MODEL_COMMANDS = ("list", "route", "alias", "fallbacks", "usage", "auth", "providers")
MODEL_AUTH_COMMANDS = ("login", "logout", "methods", "targets", "doctor", "readiness-packet", "verify-readiness-packet")
TOOLS_COMMANDS = ("list", "run", "disable", "enable")
BACKEND_COMMANDS = ("list", "doctor", "select")
SKILLS_COMMANDS = ("hub", "search", "browse", "inspect", "install", "disable", "enable")
PLUGIN_COMMANDS = ("list", "install", "enable", "disable", "remove", "reload", "marketplace", "updates", "fetch-manifest", "fetch-bundle", "install-bundle", "install-marketplace", "update-marketplace", "prepare-update", "apply-prepared-update")
CURATOR_COMMANDS = ("status", "run", "pin", "unpin", "archive", "restore", "pause", "resume")
REPAIR_COMMANDS = ("readiness", "review", "approve", "reject", "candidate", "generate-candidate", "synthesis-prompt", "synthesize-candidate", "review-candidate", "apply-candidate", "rollback-candidate", "attempt")
SCHEDULE_COMMANDS = ("create", "script", "no-agent", "memory-review-digest", "memory-review-escalation", "evaluation-run", "evaluation-suite", "due", "approve", "activate", "pause", "run-due")
BROWSER_COMMANDS = (
    "status",
    "connect",
    "disconnect",
    "session",
    "sessions",
    "close",
    "navigate",
    "live-navigate",
    "live-screenshot",
    "live-click",
    "live-fill",
    "live-submit",
    "live-download",
    "live-upload",
    "live-evaluate",
    "extract",
    "inspect",
    "dom",
    "table",
    "screenshot",
    "render",
    "click",
    "fill",
    "submit",
    "activation-packet",
    "verify-activation-packet",
)
MCP_COMMANDS = ("list", "register", "auth", "call")
HOOK_COMMANDS = ("list", "add", "enable", "disable", "remove", "run")
AGENTS_COMMANDS = ("status", "autonomy-preflight", "profiles", "profile-create", "profile-disable", "delegate", "handoff", "review-packet", "verify-packet", "model-review", "run", "run-batch")
PROCESS_COMMANDS = ("list", "start", "input", "resize", "stop", "logs")
REMOTE_CONTROL_COMMANDS = ("pair", "directory", "revoke", "relay", "relay-directory", "relay-notify", "push-targets", "push-register", "push-disable", "push-rotate", "push", "relay-outbox", "relay-retry", "relay-confirm", "relay-pull", "relay-action")
SESSION_COMMANDS = ("new", "open", "rename", "set-model", "set-personality", "activate", "archive", "pause", "append", "history", "tasks", "compact")
TASK_COMMANDS = ("status", "resume", "pause", "cancel", "events", "timeline", "submit", "list", "all", "session")
TASKS_COMMANDS = ("all", "session")
QUEUE_COMMANDS = ("status", "show", "list", "active", "pending", "all", "session", "submit")
BUSY_COMMANDS = ("status", "queue", "steer", "interrupt", "pause", "resume")
ACTIVE_WORK_STATUSES_TUI = ("pending", "planned", "running", "waiting_approval", "paused")
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
CHANNEL_COMMANDS = ("render", "receive", "resolve-approval", "send-webhook", "send-email", "send-chat-webhook", "activation-packet", "verify-activation-packet", "events")
EVALUATION_COMMANDS = ("queue", "review", "trends", "delta", "readiness")
SLASH_COMMAND_ALIASES = {
    "add-dir": "add_dir",
    "allowed-tools": "allowed_tools",
    "app": "desktop",
    "android": "mobile",
    "bg": "background",
    "btw": "background",
    "claude-api": "claude_api",
    "extra-usage": "extra_usage",
    "fewer-permission-prompts": "fewer_permission_prompts",
    "feedback": "bug",
    "install-github-app": "install_github_app",
    "install-slack-app": "install_slack_app",
    "ios": "mobile",
    "pr-comments": "pr_comments",
    "proactive": "loop",
    "q": "queue",
    "rc": "remote_control",
    "remote-control": "remote_control",
    "remote-env": "remote_env",
    "security-review": "security_review",
    "reload-mcp": "reload_mcp",
    "reload_mcp": "reload_mcp",
    "reload-plugins": "reload_plugins",
    "reload-skills": "reload_skills",
    "reload_skills": "reload_skills",
    "settings": "config",
    "snap": "rollback",
    "snapshot": "rollback",
    "terminal-setup": "terminal_setup",
    "team-onboarding": "team_onboarding",
    "tp": "teleport",
    "web-setup": "web_setup",
    "set-home": "sethome",
}
TUI_HISTORY_LIMIT = 1000
AEGIS_AGENT_WORDMARK: tuple[str, ...] = (
    "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::",
    "\\                                                                                            \\",
    "\\  .d8b.  d88888b d888b  d888888b .d8888.     .d8b.  d888b  d88888b d8b   db d888888b  \\",
    "\\ d8' `8b 88'     88' Y8b   `88'   88'  YP    d8' `8b 88' Y8b 88'     888o  88 `~~88~~' \\",
    "\\ 88ooo88 88ooooo 88         88    `8bo.      88ooo88 88      88ooooo 88V8o 88    88     \\",
    "\\ 88~~~88 88~~~~~ 88  ooo    88      `Y8b.    88~~~88 88  ooo 88~~~~~ 88 V8o88    88     \\",
    "\\ 88   88 88.     88. ~8~   .88.   db   8D    88   88 88. ~8~ 88.     88  V888    88     \\",
    "\\ YP   YP Y88888P  Y888P  Y888888P `8888Y'    YP   YP  Y888P  Y88888P VP   V8P    YP     \\",
    "\\                                                                                            \\",
    "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::",
)
AEGIS_COMPACT_WORDMARK: tuple[str, ...] = (
    "::::::::::::::::::::::::::::::::::::::::::::::::::::",
    "\\  .d8b.  d88888b  d888b  d888888b .d8888.     \\",
    "\\ d8' `8b 88'     88' Y8b   `88'   88'  YP     \\",
    "\\ 88ooo88 88ooooo 88         88    `8bo.       \\",
    "\\ 88~~~88 88~~~~~ 88  ooo    88      `Y8b.     \\",
    "\\ 88   88 88.     88. ~8~   .88.   db   8D     \\",
    "\\ YP   YP Y88888P  Y888P  Y888888P `8888Y'     \\",
    "\\                 AEGIS AGENT                  \\",
    "::::::::::::::::::::::::::::::::::::::::::::::::::::",
)
AEGIS_WORDMARK_COLORS: tuple[str, ...] = (
    "38;2;255;0;110",
    "38;2;214;19;152",
    "38;2;172;37;194",
    "38;2;131;56;236",
    "38;2;107;82;242",
    "38;2;82;108;249",
    "38;2;58;134;255",
    "38;2;39;171;241",
    "38;2;19;208;226",
    "38;2;0;245;212",
)
SHIELD_FRAMES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "BOOT",
        "policy core online",
        (
            "+------------------------------------------------------+",
            "|  && POLICY ONLINE     %% RISK SCOPED     ## RECEIPTS  |",
            "|  @@ APPROVALS CLEAR   __ MEMORY LOCAL    // PALETTE   |",
            "+------------------------------------------------------+",
        ),
    ),
    (
        "VERIFY",
        "receipts and taint checks locked",
        (
            "+------------------------------------------------------+",
            "|  ## HASH CHAIN OK     @@ EVIDENCE HELD   %% TAINT     |",
            "|  __ CONTEXT SAFE      && POLICY CHECKED  // REVIEW    |",
            "+------------------------------------------------------+",
        ),
    ),
    (
        "GUARD",
        "approval gates armed",
        (
            "+------------------------------------------------------+",
            "|  @@ HUMAN GATE ARMED  && APPROVAL QUEUE  %% RISK      |",
            "|  ## ACTION HELD       __ AUDIT READY     // RESUME    |",
            "+------------------------------------------------------+",
        ),
    ),
    (
        "TRACE",
        "live evidence lanes streaming",
        (
            "+------------------------------------------------------+",
            "|  %% EVENTS STREAMING  ## TIMELINE LIVE   __ PROOF     |",
            "|  && MODEL ROUTED      @@ TOOL GATES      // REPLAY    |",
            "+------------------------------------------------------+",
        ),
    ),
    (
        "ASCEND",
        "operator command deck focused",
        (
            "+------------------------------------------------------+",
            "|  // SLASH PALETTE    __ NESTED MENUS    && OPERATE   |",
            "|  @@ GOVERN           ## BUILD           %% EXPLORE    |",
            "+------------------------------------------------------+",
        ),
    ),
)


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
        self.additional_dirs: list[Path] = []
        self.vim_mode_enabled = False
        self._shield_frame_index = 0
        self._quick_dispatch_stack: list[str] = []
        self._refresh_prompt()
        self.intro = self._render_home()

    def preloop(self) -> None:
        _load_tui_history(self.history_path)
        self._refresh_prompt()

    def postloop(self) -> None:
        _save_tui_history(self.history_path)

    def postcmd(self, stop: bool | None, line: str) -> bool | None:
        self._refresh_prompt()
        return stop

    def parseline(self, line: str) -> tuple[str | None, str | None, str]:
        stripped = line.lstrip()
        if stripped and not stripped.startswith("/"):
            name, separator, rest = stripped.partition(" ")
            canonical = SLASH_COMMAND_ALIASES.get(name)
            if canonical:
                prefix = line[: len(line) - len(stripped)]
                line = f"{prefix}{canonical}{separator}{rest}".strip()
        return super().parseline(line)

    def cmdloop(self, intro: str | None = None) -> None:
        """Run the TUI with a live slash palette when attached to a terminal."""
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            super().cmdloop(intro=intro)
            return
        self.preloop()
        try:
            if intro is not None:
                self.intro = intro
            if self.intro:
                print(self.intro)
            stop: bool | None = None
            while not stop:
                try:
                    line = self._read_live_line()
                except KeyboardInterrupt:
                    print("^C")
                    self._refresh_prompt()
                    continue
                except EOFError:
                    print()
                    break
                if line is None:
                    break
                if line.strip():
                    _add_tui_history(line)
                line = self.precmd(line)
                stop = self.onecmd(line)
                stop = self.postcmd(stop, line)
        finally:
            self.postloop()

    def emptyline(self) -> None:
        self._refresh_prompt()
        return None

    def completenames(self, text: str, *ignored: Any) -> list[str]:
        labels = tuple([*TOP_LEVEL_COMMANDS, *self._quick_slash_commands().keys(), *self._skill_slash_commands().keys()])
        return _complete_options(labels, text)

    def completedefault(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        path_labels = _complete_context_paths(text, line, begidx, self.workspace)
        if path_labels:
            return path_labels
        labels = _complete_slash(text, line, begidx, endidx)
        stripped = line.lstrip()
        if stripped.startswith("/") and " " not in stripped[:endidx].strip():
            for label in self._complete_skill_slash_labels(text.lstrip("/")):
                if label not in labels:
                    labels.append(label)
            for label in self._complete_quick_slash_labels(text.lstrip("/")):
                if label not in labels:
                    labels.append(label)
        return labels

    def complete_menu(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_options(_command_group_names(), text)

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

    def complete_hooks(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(HOOK_COMMANDS, text, line, begidx)

    def complete_agents(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(AGENTS_COMMANDS, text, line, begidx)

    def complete_remote_control(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(REMOTE_CONTROL_COMMANDS, text, line, begidx)

    def complete_task(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(TASK_COMMANDS, text, line, begidx)

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

    def complete_backends(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(BACKEND_COMMANDS, text, line, begidx)

    def complete_skills(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(SKILLS_COMMANDS, text, line, begidx)

    def complete_plugins(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(PLUGIN_COMMANDS, text, line, begidx)

    def complete_plugin(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(PLUGIN_COMMANDS, text, line, begidx)

    def complete_curator(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return _complete_subcommand(CURATOR_COMMANDS, text, line, begidx)

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

    def do_task(self, arg: str) -> None:
        """task status|resume|pause|cancel|events|timeline|submit|list -- compatibility task controls."""
        parts = shlex.split(arg)
        if not parts:
            self.do_tasks("")
            return
        action = parts[0]
        rest = " ".join(shlex.quote(part) for part in parts[1:])
        if action in {"list", "show"}:
            self.do_tasks(rest)
            return
        if action in {"all", "session"}:
            self.do_tasks(" ".join(shlex.quote(part) for part in parts))
            return
        if action == "status":
            self.do_status(rest)
            return
        if action in {"resume", "continue"}:
            self.do_resume(rest)
            return
        if action == "pause":
            self.do_pause(rest)
            return
        if action == "cancel":
            self.do_cancel(rest)
            return
        if action == "events":
            self.do_events(rest)
            return
        if action == "timeline":
            self.do_timeline(rest)
            return
        if action == "submit":
            self.do_submit(rest)
            return
        print("usage: task status|resume|pause|cancel|events|timeline|submit|list [args]")

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
        """connectors [doctor] -- list connector status or live activation preflight."""
        parts = shlex.split(arg)
        if parts and parts[0] == "doctor":
            dashboard = build_product_dashboard(self.orchestrator)
            gap = next((item for item in dashboard.get("live_gap_backlog", []) if item.get("area") == "provider_and_channel_live_connectors"), None)
            if not gap:
                print("connector doctor unavailable")
                return
            print(_paint("Connector Activation Doctor", "36;1"))
            print(f"status: {gap.get('status', 'unknown')}")
            print(_table(_live_adapter_preflight_rows(gap), (("adapter", "adapter", 22), ("kind", "kind", 10), ("preflight", "preflight", 24), ("blockers", "blockers", 70))))
            return
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
        """channel render|receive|resolve-approval|send-webhook|send-email|send-chat-webhook|activation-packet|verify-activation-packet|events -- inspect and exercise channel adapters."""
        parts = shlex.split(arg)
        if parts and parts[0] == "events":
            limit = int(parts[1]) if len(parts) > 1 else 20
            _print_json({"events": self.orchestrator.channels.events(limit=limit)})
            return
        if parts and parts[0] == "activation-packet":
            _print_json(self.orchestrator.create_channel_live_activation_packet(actor="tui-operator"))
            return
        if parts and parts[0] == "verify-activation-packet":
            if len(parts) < 2:
                print("usage: channel verify-activation-packet <packet-id-or-path>")
                return
            _print_json(self.orchestrator.verify_channel_live_activation_packet(parts[1], actor="tui-operator"))
            return
        if parts and parts[0] == "resolve-approval":
            if len(parts) < 3:
                print("usage: channel resolve-approval <event_id> <approval_id> [--actor name] [--reason text] [--admin]")
                return
            result = self.orchestrator.resolve_channel_approval_intent(
                event_id=parts[1],
                approval_id=parts[2],
                actor=_option_value(parts, "--actor") or "",
                reason=_flag_joined_value(parts, "--reason") or "",
                admin="--admin" in parts,
            )
            _print_json({**result, "approval": _approval_with_session(self.orchestrator, result["approval"])})
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
            print("usage: channel render <channel> <text> | channel receive <channel> <text> | channel resolve-approval <event_id> <approval_id> | channel send-webhook <text> --approved | channel send-email <subject> <text> --approved | channel send-chat-webhook <text> --approved | channel activation-packet | channel verify-activation-packet <packet> | channel events [limit]")
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
                    "auth_method": route.auth_method,
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
                if len(parts) >= 2 and parts[1] == "doctor":
                    _print_json({"auth_doctor": self.orchestrator.models.auth_doctor()})
                    return
                if len(parts) >= 2 and parts[1] == "readiness-packet":
                    _print_json(self.orchestrator.models.create_auth_readiness_packet(actor="tui-operator"))
                    return
                if len(parts) >= 2 and parts[1] == "verify-readiness-packet":
                    if len(parts) < 3:
                        print("usage: models auth verify-readiness-packet <packet-id-or-path>")
                        return
                    _print_json(self.orchestrator.models.verify_auth_readiness_packet(parts[2], actor="tui-operator"))
                    return
                if len(parts) >= 2 and parts[1] == "targets":
                    _print_json({"auth_targets": self.orchestrator.models.auth_targets()})
                    return
                if len(parts) >= 2 and parts[1] == "methods":
                    provider = parts[2] if len(parts) > 2 else None
                    _print_json({"auth": self.orchestrator.models.auth_status(provider)})
                    return
                if len(parts) >= 3 and parts[1] == "login":
                    if len(parts) >= 4 and parts[3] in {"subscription", "oauth", "oauth-device", "cloud-identity"}:
                        _print_json(
                            {
                                "auth": self.orchestrator.models.login_provider_external(
                                    parts[2],
                                    method=parts[3],
                                    run_external="--run-external" in parts,
                                    verify_external="--verify-external" in parts,
                                )
                            }
                        )
                    else:
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
            print("usage: models list|providers|route <identifier>|alias <alias> <identifier>|fallbacks <identifier> <fallback> [fallback...]|usage|auth [provider]|auth methods [provider]|auth targets|auth doctor|auth readiness-packet|auth verify-readiness-packet <packet>|auth login <provider> [subscription|oauth|oauth-device|cloud-identity] [--run-external] [--verify-external]|auth logout <provider>")
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
        """tools [list|run <name> <json-params> [--approved]|enable|disable <name>] -- list or run built-in tools."""
        parts = shlex.split(arg)
        if parts and parts[0] == "list":
            parts = []
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
        if parts and parts[0] in {"enable", "disable"}:
            if len(parts) < 2:
                print(f"usage: tools {parts[0]} <tool_name>")
                return
            tool_name = parts[1]
            tools = [*self.orchestrator.tool_catalog.list(), *self.orchestrator.mcp.virtual_tool_specs()]
            tool = next((row for row in tools if row.get("name") == tool_name), None)
            _print_json(
                {
                    "status": "policy_owned_tool_preference",
                    "tool": tool_name,
                    "known_tool": tool is not None,
                    "requested_enabled": parts[0] == "enable",
                    "persisted": False,
                    "raw_secret_values_included": False,
                    "detail": "Tool availability is governed by policy profiles, connector scope, and approval gates; this command reports the requested preference without mutating policy.",
                    "next_actions": ["allowed-tools", "security profile", "tools list"],
                }
            )
            return
        rows = [*self.orchestrator.tool_catalog.list(), *self.orchestrator.mcp.virtual_tool_specs()]
        print(
            _table(
                rows,
                (
                    ("name", "name", 24),
                    ("risk", "risk_level", 10),
                    ("approval", "approval_required", 10),
                    ("categories", "categories", 36),
                ),
            )
        )

    def do_skills(self, arg: str) -> None:
        """skills [hub|search|browse query|inspect skill_id|install skill_id|disable skill_id|enable skill_id] -- manage governed skills or inspect the read-only hub."""
        parts = shlex.split(arg)
        if parts and parts[0] in {"hub", "search", "browse"}:
            query = " ".join(parts[1:])
            _print_json(self.orchestrator.skill_hub.search(query))
            return
        if parts and parts[0] == "inspect":
            if len(parts) < 2:
                print("usage: skills inspect <skill_id>")
                return
            try:
                manifest, enabled = self.orchestrator.skills.get(parts[1])
                _print_json(
                    {
                        "status": "installed_skill",
                        "skill_id": manifest.id,
                        "enabled": enabled,
                        "name": manifest.name,
                        "risk_level": manifest.risk_level.value,
                        "approval_required": manifest.approval_required,
                        "permissions": manifest.permissions,
                        "connectors": manifest.connectors,
                        "raw_secret_values_included": False,
                    }
                )
            except KeyError:
                _print_json({**self.orchestrator.skill_hub.search(parts[1]), "status": "virtual_catalog_result"})
            return
        if parts and parts[0] == "install":
            if len(parts) < 2:
                print("usage: skills install <skill_id>")
                return
            _print_json(
                {
                    "status": "governed_install_required",
                    "skill_id": parts[1],
                    "raw_secret_values_included": False,
                    "detail": "Remote or local skill installation must flow through signed manifests, governed plugins, or an explicit local enable path.",
                    "next_actions": [f"skills inspect {parts[1]}", "plugins install <plugin.json>", f"skills enable {parts[1]}"],
                }
            )
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

    def do_curator(self, arg: str) -> None:
        """curator [status|run|pin|unpin|archive|restore|pause|resume] -- maintain local authored skills."""
        try:
            parts = shlex.split(arg) if arg else []
        except ValueError as exc:
            print(f"invalid curator command: {exc}")
            return
        curator = self.orchestrator.skill_curator
        action = parts[0] if parts else "status"
        try:
            if action == "status":
                _print_json(curator.status())
                return
            if action == "run":
                _print_json(curator.run(dry_run="--dry-run" in parts[1:]))
                return
            if action in {"pin", "unpin", "archive", "restore"}:
                if len(parts) < 2:
                    print(f"usage: curator {action} <skill_id>")
                    return
                _print_json(getattr(curator, action)(parts[1]))
                return
            if action == "pause":
                _print_json(curator.pause())
                return
            if action == "resume":
                _print_json(curator.resume())
                return
        except KeyError as exc:
            print(f"curator skill not found: {exc}")
            return
        except (PermissionError, ValueError) as exc:
            print(f"curator error: {exc}")
            return
        print("usage: curator [status|run [--dry-run]|pin <skill_id>|unpin <skill_id>|archive <skill_id>|restore <skill_id>|pause|resume]")

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
        if command == "health":
            try:
                _print_json(
                    self.orchestrator.memory.health_report(
                        limit=_flag_int(parts, "--limit", default=20) or 20,
                        owner=_flag_joined_value(parts, "--owner") or "local-user",
                        scope=_flag_joined_value(parts, "--scope") or str(self.workspace),
                    )
                )
            except ValueError as exc:
                print(f"memory health failed: {exc}")
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
        """mcp list|register|call -- inspect, register, discover, or call governed MCP servers."""
        parts = shlex.split(arg)
        command = parts[0] if parts else "list"
        if command == "list":
            _print_json({"servers": self.orchestrator.mcp.list_servers(), "virtual_tools": self.orchestrator.mcp.virtual_tools()})
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
            if len(parts) < 3:
                print("usage: mcp register <name> <command-or-endpoint> <tool,tool>|--discover [--transport stdio|streamable-http] [--token-secret name] [--tool name] [--exclude-tool name] [--no-resources] [--no-prompts] [--enable] [--no-approval]")
                return
            enabled = "--enable" in parts[3:]
            approval_required = "--no-approval" not in parts[3:]
            transport = (_option_values(parts, "--transport") or ["stdio"])[0]
            token_secret = (_option_values(parts, "--token-secret") or [None])[0]
            if "--discover" in parts[3:]:
                include_tools = tuple(_option_values(parts, "--tool"))
                exclude_tools = tuple(_option_values(parts, "--exclude-tool"))
                include_resources = "--no-resources" not in parts[3:]
                include_prompts = "--no-prompts" not in parts[3:]
                try:
                    _print_json(
                        self.orchestrator.mcp.register_discovered_server(
                            name=parts[1],
                            command=parts[2],
                            allowed_executables=self.orchestrator.config.allowed_shell_commands,
                            transport=transport,
                            network_allowlist=self.orchestrator.config.network_allowlist,
                            auth_token_secret=token_secret,
                            include_tools=include_tools,
                            exclude_tools=exclude_tools,
                            include_resources=include_resources,
                            include_prompts=include_prompts,
                            enabled=enabled,
                            approval_required=approval_required,
                            metadata={"source": "tui"},
                        )
                    )
                except (PermissionError, ValueError, RuntimeError, TimeoutError) as exc:
                    print(f"mcp discovery failed: {exc}")
                return
            if len(parts) < 4:
                print("usage: mcp register <name> <command-or-endpoint> <tool,tool>|--discover [--transport stdio|streamable-http] [--token-secret name] [--tool name] [--exclude-tool name] [--no-resources] [--no-prompts] [--enable] [--no-approval]")
                return
            tools = tuple(item.strip() for item in parts[3].split(",") if item.strip())
            _print_json(
                self.orchestrator.mcp.register_server(
                    name=parts[1],
                    command=parts[2],
                    allowed_tools=tools,
                    transport=transport,
                    enabled=enabled,
                    approval_required=approval_required,
                    metadata={"source": "tui"},
                    network_allowlist=self.orchestrator.config.network_allowlist,
                    auth_token_secret=token_secret,
                )
            )
            return
        if command == "auth":
            if len(parts) >= 4 and parts[1] == "token":
                _print_json(self.orchestrator.mcp.configure_auth_token(parts[2], token_secret=parts[3]))
                return
            print("usage: mcp auth token <server> <token-secret>")
            return
        print("usage: mcp list | mcp register <name> <command-or-endpoint> <tool,tool>|--discover [--transport stdio|streamable-http] [--token-secret name] [--tool name] [--exclude-tool name] [--no-resources] [--no-prompts] [--enable] [--no-approval] | mcp auth token <server> <token-secret> | mcp call <server> <tool> <json-arguments> [--approved]")

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

    def do_recap(self, arg: str) -> None:
        """recap -- show a one-line metadata-only active session recap."""
        session = self.orchestrator.sessions.get_session(self.session["id"])
        history = self.orchestrator.sessions.history(self.session["id"], limit=1000)
        user_count = sum(1 for row in history if row.get("role") == "user")
        assistant_count = sum(1 for row in history if row.get("role") == "assistant")
        task_count = len(self.orchestrator.store.list_tasks(limit=1000, session_id=self.session["id"]))
        title = str(session.get("title") or "Untitled session")
        status = str(session.get("status") or "active")
        _print_json(
            {
                "status": "session_recap",
                "recap": f"{title}: {status}, {user_count} user turn(s), {assistant_count} assistant turn(s), {task_count} linked task(s).",
                "active_session_id": session.get("id"),
                "raw_message_content_included": False,
                "next_actions": ["session history", "tasks session", "context", "compact"],
            }
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
        """schedule create|script|memory-review-digest|memory-review-escalation|evaluation-run|evaluation-suite|due|approve|activate|pause|run-due -- manage scheduled automations."""
        parts = shlex.split(arg)
        if not parts:
            print("schedule command required")
            return
        command = parts[0]
        try:
            if command == "create":
                if len(parts) < 4:
                    print("usage: schedule create <name> <cron> <task_request> [--natural-language text] [--channel name] [--context-from ref] [--deliver-to channel]")
                    return
                channel = _option_value(parts, "--channel") or "terminal"
                natural_language = _flag_joined_value(parts, "--natural-language")
                positional = _positional_without_flags(parts[1:], {"--natural-language": 1, "--channel": 1, "--context-from": 1, "--deliver-to": 1})
                if len(positional) < 3:
                    print("usage: schedule create <name> <cron> <task_request> [--natural-language text] [--channel name] [--context-from ref] [--deliver-to channel]")
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
                        context_from=tuple(_option_values(parts, "--context-from")),
                        delivery_targets=tuple(_option_values(parts, "--deliver-to")),
                    )
                )
                return
            if command in {"script", "no-agent"}:
                if "--" not in parts:
                    print("usage: schedule script <name> <cron> [--channel name] [--context-from ref] [--deliver-to channel] -- <argv...>")
                    return
                separator = parts.index("--")
                options = parts[1:separator]
                argv = parts[separator + 1 :]
                positional = _positional_without_flags(options, {"--channel": 1, "--context-from": 1, "--deliver-to": 1, "--hook-id": 1, "--timeout": 1, "--max-output-bytes": 1})
                if len(positional) < 2 or not argv:
                    print("usage: schedule script <name> <cron> [--channel name] [--context-from ref] [--deliver-to channel] -- <argv...>")
                    return
                _print_json(
                    self.orchestrator.create_script_schedule(
                        name=positional[0],
                        cron=positional[1],
                        command=argv,
                        channel=_option_value(options, "--channel") or "terminal",
                        hook_id=_option_value(options, "--hook-id"),
                        context_from=tuple(_option_values(options, "--context-from")),
                        delivery_targets=tuple(_option_values(options, "--deliver-to")),
                        timeout_seconds=int(_option_value(options, "--timeout") or "10"),
                        max_output_bytes=int(_option_value(options, "--max-output-bytes") or "4096"),
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
        """browser status|connect|disconnect|session|sessions|close|navigate|live-navigate|live-screenshot|live-click|live-fill|live-submit|live-download|live-upload|live-evaluate|extract|inspect|activation-packet|verify-activation-packet|dom|table|screenshot|render|click|fill|submit -- operate the governed browser sandbox."""
        raw_parts = arg.strip().split(maxsplit=1)
        raw_command = raw_parts[0] if raw_parts else "session"
        parts = [raw_command, raw_parts[1]] if raw_command == "fill" and len(raw_parts) > 1 else shlex.split(arg)
        command = parts[0] if parts else "session"
        try:
            if command == "status":
                _print_json(
                    {
                        "status": "local_browser_sandbox_ready",
                        "active_session_id": self.browser_session_id,
                        "sessions": self.orchestrator.browser.list_sessions(),
                        "live_browser_automation": "read_only_mutation_download_upload_or_javascript_available_if_configured",
                        "activation": self.orchestrator.browser.live_activation_status()["activation"],
                        "raw_secret_values_included": False,
                    }
                )
                return
            if command == "activation-packet":
                _print_json(self.orchestrator.browser.create_live_activation_packet(actor="tui-operator"))
                return
            if command == "verify-activation-packet":
                if len(parts) < 2:
                    print("usage: browser verify-activation-packet <packet-id-or-path>")
                    return
                _print_json(self.orchestrator.browser.verify_live_activation_packet(parts[1], actor="tui-operator"))
                return
            if command == "connect":
                session = self.orchestrator.browser.create_session(label="TUI browser")
                self.browser_session_id = session["id"]
                _print_json(
                    {
                        "status": "local_browser_session_connected",
                        "session": session,
                        "live_browser_automation": "read_only_mutation_download_upload_or_javascript_available_if_configured",
                        "raw_secret_values_included": False,
                    }
                )
                return
            if command == "disconnect":
                command = "close"
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
            if command == "live-navigate":
                if len(parts) < 2:
                    print("browser url required")
                    return
                if not self.browser_session_id:
                    self.browser_session_id = self.orchestrator.browser.create_session(label="TUI live browser")["id"]
                approval_id = _option_value(parts, "--approval-id")
                approval = _browser_action_approval(self.orchestrator, action="live_navigate", session_id=self.browser_session_id, url=parts[1], approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                result = self.orchestrator.browser.live_navigate(session_id=self.browser_session_id, url=parts[1], approved=True)
                self.browser_session_id = result.get("session", {}).get("id", self.browser_session_id)
                _print_json(result)
                return
            if not self.browser_session_id:
                print("browser session required")
                return
            if command == "live-screenshot":
                approval_id = _option_value(parts, "--approval-id")
                approval = _browser_action_approval(self.orchestrator, action="live_screenshot", session_id=self.browser_session_id, approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.live_screenshot(session_id=self.browser_session_id, approved=True))
                return
            if command == "live-click":
                if len(parts) < 2:
                    print("browser selector required")
                    return
                approval_id = _option_value(parts, "--approval-id")
                approval = _browser_action_approval(self.orchestrator, action="live_click", session_id=self.browser_session_id, selector=parts[1], approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.live_click(session_id=self.browser_session_id, selector=parts[1], approved=True))
                return
            if command == "live-fill":
                if len(parts) < 2:
                    print("browser fields JSON required")
                    return
                fields_text, approval_id = _split_json_approval_arg(parts[1])
                fields = json.loads(fields_text)
                if not isinstance(fields, dict):
                    raise ValueError("browser live-fill requires a JSON object")
                approval = _browser_action_approval(self.orchestrator, action="live_fill", session_id=self.browser_session_id, fields=fields, approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.live_fill(session_id=self.browser_session_id, fields=fields, approved=True))
                return
            if command == "live-submit":
                approval_id = _option_value(parts, "--approval-id")
                selector = parts[1] if len(parts) > 1 and parts[1] != "--approval-id" else None
                approval = _browser_action_approval(self.orchestrator, action="live_submit", session_id=self.browser_session_id, selector=selector, approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.live_submit(session_id=self.browser_session_id, selector=selector, approved=True))
                return
            if command == "live-download":
                if len(parts) < 2:
                    print("browser selector required")
                    return
                approval_id = _option_value(parts, "--approval-id")
                approval = _browser_action_approval(self.orchestrator, action="live_download", session_id=self.browser_session_id, selector=parts[1], approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.live_download(session_id=self.browser_session_id, selector=parts[1], approved=True))
                return
            if command == "live-upload":
                if len(parts) < 3:
                    print("usage: browser live-upload <file-input-selector> <workspace-file-path>")
                    return
                approval_id = _option_value(parts, "--approval-id")
                approval = _browser_action_approval(self.orchestrator, action="live_upload", session_id=self.browser_session_id, selector=parts[1], file_path=parts[2], approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.live_upload(session_id=self.browser_session_id, selector=parts[1], file_path=parts[2], approved=True))
                return
            if command == "live-evaluate":
                if len(parts) < 2:
                    print("usage: browser live-evaluate <javascript-with-return>")
                    return
                script, approval_id = _split_approval_arg(" ".join(parts[1:]))
                approval = _browser_action_approval(self.orchestrator, action="live_evaluate", session_id=self.browser_session_id, script=script, approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.live_evaluate(session_id=self.browser_session_id, script=script, approved=True))
                return
            if command == "extract":
                _print_json(self.orchestrator.browser.extract_text(session_id=self.browser_session_id))
                return
            if command == "inspect":
                _print_json(self.orchestrator.browser.inspect(session_id=self.browser_session_id))
                return
            if command == "dom":
                selector = parts[1] if len(parts) > 1 else None
                _print_json(self.orchestrator.browser.dom_snapshot(session_id=self.browser_session_id, selector=selector))
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
            if command == "submit":
                approval_id = _option_value(parts, "--approval-id")
                selector = parts[1] if len(parts) > 1 and parts[1] != "--approval-id" else None
                approval = _browser_action_approval(self.orchestrator, action="submit", session_id=self.browser_session_id, selector=selector, approval_id=approval_id)
                if not approval.get("approved"):
                    _print_json(approval["response"])
                    return
                _print_json(self.orchestrator.browser.submit(session_id=self.browser_session_id, selector=selector, approved=True))
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
        """backends [list|doctor|select] -- inspect or select execution backends."""
        parts = shlex.split(arg)
        if parts and parts[0] == "select":
            if len(parts) < 2:
                print("usage: backends select <name> [--approved]")
                return
            _print_json(self.orchestrator.tools.execute("terminal_backend", {"backend": parts[1]}, approved="--approved" in parts[2:]))
            return
        if parts and parts[0] == "doctor":
            dashboard = build_product_dashboard(self.orchestrator)
            gap = next((item for item in dashboard.get("live_gap_backlog", []) if item.get("area") == "remote_backend_activation"), None)
            if not gap:
                print("backend doctor unavailable")
                return
            print(_paint("Backend Activation Doctor", "36;1"))
            print(f"status: {gap.get('status', 'unknown')}")
            print(_table(_backend_preflight_rows(gap), (("backend", "backend", 18), ("preflight", "preflight", 24), ("blockers", "blockers", 70))))
            return
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
        model_auth_gap = next((item for item in dashboard.get("live_gap_backlog", []) if item.get("area") == "model_provider_auth_login_parity"), None)
        if model_auth_gap:
            print()
            print("Model Provider Auth Parity")
            print(
                _table(
                    model_auth_gap.get("target_providers", []),
                    (
                        ("target", "target", 34),
                        ("status", "status", 30),
                        ("auth", "required_auth", 24),
                        ("methods", "existing_auth_methods", 24),
                        ("bridge", "bridge_status", 28),
                    ),
                )
            )
            print()
            print("Model Auth Readiness")
            print(
                _table(
                    model_auth_gap.get("operator_checklist", []),
                    (("control", "control", 32), ("state", "state", 24), ("detail", "detail", 82)),
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
            backend_rows = _backend_preflight_rows(backend_gap)
            if backend_rows:
                print()
                print("Remote Backend Activation Preflight")
                print(
                    _table(
                        backend_rows,
                        (("backend", "backend", 18), ("preflight", "preflight", 24), ("blockers", "blockers", 70)),
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

    def do_clear(self, arg: str) -> None:
        """clear [title] -- clear the terminal screen and start a fresh session."""
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")
        else:
            print("screen cleared")
        self.do_new(arg)

    def do_new(self, arg: str) -> None:
        """new [title] -- start a fresh local session."""
        title = arg.strip() or "Aegis TUI"
        self.session = self.orchestrator.sessions.create_session(title=title, channel="terminal")
        self.last_task_id = None
        _print_json(self.session)

    def do_reset(self, arg: str) -> None:
        """reset [title] -- alias for new."""
        self.do_new(arg)

    def do_history(self, arg: str) -> None:
        """history [session_id] [--limit N] -- show conversation history."""
        self.do_session(f"history {arg}".strip())

    def do_title(self, arg: str) -> None:
        """title [name] -- show or rename the active session."""
        if arg.strip():
            self.do_session(f"rename {arg}")
            return
        self.do_session("")

    def do_topic(self, arg: str) -> None:
        """topic [off|help|session_id] -- show local topic-mode status or restore a session."""
        topic = arg.strip()
        if topic == "help":
            _print_json(
                {
                    "status": "topic_help",
                    "mode": "local_session_topic_boundary",
                    "usage": "topic [off|help|session_id]",
                    "local_restore": "topic <session_id>",
                    "title_command": "title [name]",
                    "raw_message_content_included": False,
                }
            )
            return
        if topic == "off":
            _print_json(
                {
                    "status": "topic_mode_off",
                    "mode": "local_session_topic_boundary",
                    "topic_bindings_cleared": False,
                    "gateway_topic_mode_enabled": False,
                    "raw_message_content_included": False,
                }
            )
            return
        if topic:
            try:
                self.session = self.orchestrator.sessions.get_session(topic)
            except KeyError:
                print(f"session not found: {topic}")
                return
            _print_json(
                {
                    "status": "topic_session_restored",
                    "mode": "local_session_topic_boundary",
                    "session": _session_public_summary(self.session),
                    "raw_message_content_included": False,
                }
            )
            return
        _print_json(
            {
                "status": "topic_status",
                "mode": "local_session_topic_boundary",
                "active_session": _session_public_summary(self.session),
                "gateway_topic_mode_enabled": False,
                "remote_topic_bindings": "not_enabled",
                "next_actions": ["topic help", "sessions", "topic <session_id>", "title <name>"],
                "raw_message_content_included": False,
            }
        )

    def do_compress(self, arg: str) -> None:
        """compress [keep_last] -- compact the active session history."""
        self.do_session(f"compact {arg}".strip())

    def do_compact(self, arg: str) -> None:
        """compact [keep_last] -- Claude-style alias for session compaction."""
        self.do_compress(arg)

    def do_background(self, arg: str) -> None:
        """background <request> -- submit a governed task from the active session."""
        if not arg.strip():
            print("usage: background <request>")
            return
        self.do_submit(arg)

    def do_rollback(self, arg: str) -> None:
        """rollback -- show guarded rollback status."""
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        print(
            _boxed_lines(
                "Rollback",
                [
                    "Filesystem checkpoint rollback is not enabled in this local runtime.",
                    "Available guarded rollback surfaces: policy rollback-bundle, repair rollback-candidate, and explicit SQLite backups through migrate backup.",
                    "A future filesystem rollback adapter must record changed files, approval, verification, and rollback receipts before it can mutate the workspace.",
                ],
                width,
            )
        )

    def do_checkpoint(self, arg: str) -> None:
        """checkpoint -- show checkpoint and rollback readiness."""
        self.do_rollback(arg)

    def do_rewind(self, arg: str) -> None:
        """rewind -- show rewind/rollback readiness."""
        self.do_rollback(arg)

    def do_remote_control(self, arg: str) -> None:
        """remote_control [name|pair|directory|revoke|relay|relay-directory|relay-notify|push-targets|push-register|push-disable|push-rotate|push|relay-confirm|relay-pull|relay-action] -- manage guarded remote-control readiness."""
        parts = shlex.split(arg) if arg else []
        if parts and parts[0] == "directory":
            pairing_id = _option_value(parts, "--pairing-id")
            if pairing_id is None and len(parts) > 1 and not parts[1].startswith("--"):
                pairing_id = parts[1]
            limit = _optional_int(_option_value(parts, "--limit")) or 10
            if not pairing_id:
                print("usage: remote-control directory --pairing-id <id> [--limit N]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                pairing = registry.public_pairing(pairing_id)
                result = build_remote_control_directory(
                    pairing,
                    store=self.orchestrator.store,
                    limit=limit,
                )
            except (KeyError, ValueError) as exc:
                print(f"remote-control directory error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.directory_viewed",
                {
                    "pairing_id": pairing["id"],
                    "scope": result["scope"]["type"],
                    "task_count": result["task_count"],
                    "pairing_token_relayed": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "relay-directory":
            pairing_id = _option_value(parts, "--pairing-id")
            relay_secret = _option_value(parts, "--relay-auth-secret")
            approved = "--approved" in parts
            limit = _optional_int(_option_value(parts, "--limit")) or 10
            if not pairing_id or not relay_secret:
                print("usage: remote-control relay-directory --pairing-id <id> --relay-auth-secret <secret_name> --approved [--limit N]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                handle = self.orchestrator.secrets_broker.request_handle(
                    name=relay_secret,
                    requester="remote_control_relay",
                    reason="publish scoped remote-control directory to relay",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                pairing = registry.public_pairing(pairing_id)
                directory = build_remote_control_directory(
                    pairing,
                    store=self.orchestrator.store,
                    limit=limit,
                )
                result = registry.publish_relay_directory(
                    pairing_id,
                    directory=directory,
                    relay_auth_token=relay_auth_token,
                    allowlist=self.orchestrator.config.network_allowlist,
                    approved=approved,
                )
            except (KeyError, PermissionError, ValueError) as exc:
                print(f"remote-control relay-directory error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.relay_directory_published",
                {
                    "pairing_id": result["pairing"]["id"],
                    "relay_target": result["relay_target"],
                    "scope": result["directory_scope"].get("type"),
                    "task_count": result["directory_task_count"],
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "relay-notify":
            pairing_id = _option_value(parts, "--pairing-id")
            relay_secret = _option_value(parts, "--relay-auth-secret")
            event = _option_value(parts, "--event") or "directory-updated"
            task_id = _option_value(parts, "--task-id")
            approved = "--approved" in parts
            if not pairing_id or not relay_secret:
                print("usage: remote-control relay-notify --pairing-id <id> --relay-auth-secret <secret_name> --approved [--event event] [--task-id id]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                handle = self.orchestrator.secrets_broker.request_handle(
                    name=relay_secret,
                    requester="remote_control_relay",
                    reason="publish scoped remote-control notification to relay",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                pairing = registry.public_pairing(pairing_id)
                notification = build_remote_control_notification(
                    pairing,
                    store=self.orchestrator.store,
                    event=event,
                    task_id=task_id,
                )
                result = registry.publish_relay_notification(
                    pairing_id,
                    notification=notification,
                    relay_auth_token=relay_auth_token,
                    allowlist=self.orchestrator.config.network_allowlist,
                    approved=approved,
                )
            except (KeyError, PermissionError, ValueError) as exc:
                print(f"remote-control relay-notify error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.relay_notification_published",
                {
                    "pairing_id": result["pairing"]["id"],
                    "relay_target": result["relay_target"],
                    "event": result["notification_event"],
                    "task_id": result["notification"].get("task_id"),
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "push-targets":
            target_id = _option_value(parts, "--target-id")
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                if target_id:
                    result = {
                        "status": "native_push_target",
                        "target": registry.native_push_target(target_id),
                        "raw_secret_values_included": False,
                    }
                else:
                    result = registry.native_push_targets()
            except KeyError as exc:
                print(f"remote-control push-targets error: {exc}")
                return
            _print_json(result)
            return
        if parts and parts[0] == "push-register":
            provider = _option_value(parts, "--provider") or ""
            push_auth_secret = _option_value(parts, "--push-auth-secret")
            device_token_secret = _option_value(parts, "--device-token-secret")
            if provider not in {"apns", "fcm"} or not push_auth_secret or not device_token_secret:
                print("usage: remote-control push-register --provider apns|fcm --push-auth-secret <secret_name> --device-token-secret <secret_name> --approved [--label label] [--apns-topic topic] [--fcm-project-id project]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                result = registry.register_native_push_target(
                    label=_option_value(parts, "--label") or "native push",
                    provider=provider,
                    push_auth_secret=push_auth_secret,
                    device_token_secret=device_token_secret,
                    approved="--approved" in parts,
                    apns_topic=_option_value(parts, "--apns-topic"),
                    fcm_project_id=_option_value(parts, "--fcm-project-id"),
                )
            except (PermissionError, ValueError) as exc:
                print(f"remote-control push-register error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.native_push_target_registered",
                {
                    "target_id": result["target"]["id"],
                    "provider": result["target"]["provider"],
                    "push_auth_secret_captured": False,
                    "device_token_secret_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "push-disable":
            target_id = _option_value(parts, "--target-id")
            if not target_id:
                print("usage: remote-control push-disable --target-id <id> --approved")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                result = registry.disable_native_push_target(target_id, approved="--approved" in parts)
            except (KeyError, PermissionError) as exc:
                print(f"remote-control push-disable error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.native_push_target_disabled",
                {
                    "target_id": result["target"]["id"],
                    "provider": result["target"]["provider"],
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "push-rotate":
            target_id = _option_value(parts, "--target-id")
            if not target_id:
                print("usage: remote-control push-rotate --target-id <id> --approved [--push-auth-secret name] [--device-token-secret name] [--apns-topic topic] [--fcm-project-id project]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                result = registry.rotate_native_push_target(
                    target_id,
                    push_auth_secret=_option_value(parts, "--push-auth-secret"),
                    device_token_secret=_option_value(parts, "--device-token-secret"),
                    apns_topic=_option_value(parts, "--apns-topic"),
                    fcm_project_id=_option_value(parts, "--fcm-project-id"),
                    approved="--approved" in parts,
                )
            except (KeyError, PermissionError, ValueError) as exc:
                print(f"remote-control push-rotate error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.native_push_target_rotated",
                {
                    "target_id": result["target"]["id"],
                    "provider": result["target"]["provider"],
                    "rotated_fields": result["rotated_fields"],
                    "push_auth_secret_captured": False,
                    "device_token_secret_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "push":
            pairing_id = _option_value(parts, "--pairing-id")
            target_id = _option_value(parts, "--target-id")
            provider = _option_value(parts, "--provider") or ""
            push_auth_secret = _option_value(parts, "--push-auth-secret")
            device_token_secret = _option_value(parts, "--device-token-secret")
            event = _option_value(parts, "--event") or "directory-updated"
            task_id = _option_value(parts, "--task-id")
            approved = "--approved" in parts
            if not pairing_id or (not target_id and (provider not in {"apns", "fcm"} or not push_auth_secret or not device_token_secret)):
                print("usage: remote-control push --pairing-id <id> (--target-id <id> | --provider apns|fcm --push-auth-secret <secret_name> --device-token-secret <secret_name>) --approved [--apns-topic topic] [--fcm-project-id project] [--event event] [--task-id id]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                if target_id:
                    target_refs = registry.native_push_target_secret_refs(target_id)
                    provider = str(target_refs["provider"])
                    push_auth_secret = str(target_refs["push_auth_secret"])
                    device_token_secret = str(target_refs["device_token_secret"])
                    apns_topic = _option_value(parts, "--apns-topic") or target_refs.get("apns_topic")
                    fcm_project_id = _option_value(parts, "--fcm-project-id") or target_refs.get("fcm_project_id")
                else:
                    apns_topic = _option_value(parts, "--apns-topic")
                    fcm_project_id = _option_value(parts, "--fcm-project-id")
                auth_handle = self.orchestrator.secrets_broker.request_handle(
                    name=push_auth_secret,
                    requester="remote_control_push",
                    reason=f"publish scoped remote-control {provider} notification",
                    scopes=("remote_control:push",),
                )
                device_handle = self.orchestrator.secrets_broker.request_handle(
                    name=device_token_secret,
                    requester="remote_control_push",
                    reason=f"resolve brokered remote-control {provider} device token",
                    scopes=("remote_control:push",),
                )
                push_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(auth_handle, requester="remote_control_push")
                device_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(device_handle, requester="remote_control_push")
                pairing = registry.public_pairing(pairing_id)
                notification = build_remote_control_notification(
                    pairing,
                    store=self.orchestrator.store,
                    event=event,
                    task_id=task_id,
                )
                result = registry.publish_native_push_notification(
                    pairing_id,
                    notification=notification,
                    provider=provider,
                    push_auth_token=push_auth_token,
                    device_token=device_token,
                    allowlist=self.orchestrator.config.network_allowlist,
                    approved=approved,
                    apns_topic=apns_topic,
                    fcm_project_id=fcm_project_id,
                    target_id=target_id,
                )
            except (KeyError, PermissionError, ValueError) as exc:
                print(f"remote-control push error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.native_push_published",
                {
                    "pairing_id": result["pairing"]["id"],
                    "provider": result["provider"],
                    "target_id": result.get("target_id"),
                    "push_target": result["push_target"],
                    "event": result["notification_event"],
                    "task_id": result["notification"].get("task_id"),
                    "pairing_token_relayed": False,
                    "push_auth_token_captured": False,
                    "raw_device_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "relay-outbox":
            status_filter = _option_value(parts, "--status")
            limit = _optional_int(_option_value(parts, "--limit")) or 20
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            _print_json(registry.relay_outbox(status=status_filter, limit=limit))
            return
        if parts and parts[0] == "relay-retry":
            pairing_id = _option_value(parts, "--pairing-id")
            relay_secret = _option_value(parts, "--relay-auth-secret")
            approved = "--approved" in parts
            limit = _optional_int(_option_value(parts, "--limit")) or 10
            if not pairing_id or not relay_secret:
                print("usage: remote-control relay-retry --pairing-id <id> --relay-auth-secret <secret_name> --approved [--limit N]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                handle = self.orchestrator.secrets_broker.request_handle(
                    name=relay_secret,
                    requester="remote_control_relay",
                    reason="retry scoped remote-control relay notification outbox",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                result = registry.retry_relay_notifications(
                    pairing_id,
                    relay_auth_token=relay_auth_token,
                    allowlist=self.orchestrator.config.network_allowlist,
                    approved=approved,
                    limit=limit,
                )
            except (KeyError, PermissionError, ValueError) as exc:
                print(f"remote-control relay-retry error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.relay_notification_outbox_retried",
                {
                    "pairing_id": result["pairing"]["id"],
                    "relay_target": result["relay_target"],
                    "attempted_count": result["attempted_count"],
                    "acknowledged_count": result["acknowledged_count"],
                    "failed_count": result["failed_count"],
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "relay-confirm":
            pairing_id = _option_value(parts, "--pairing-id")
            outbox_id = _option_value(parts, "--outbox-id")
            relay_secret = _option_value(parts, "--relay-auth-secret")
            approved = "--approved" in parts
            if not pairing_id or not outbox_id or not relay_secret:
                print("usage: remote-control relay-confirm --pairing-id <id> --outbox-id <id> --relay-auth-secret <secret_name> --approved")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                handle = self.orchestrator.secrets_broker.request_handle(
                    name=relay_secret,
                    requester="remote_control_relay",
                    reason="confirm scoped remote-control relay notification delivery",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                result = registry.confirm_relay_delivery(
                    pairing_id,
                    outbox_id=outbox_id,
                    relay_auth_token=relay_auth_token,
                    allowlist=self.orchestrator.config.network_allowlist,
                    approved=approved,
                )
            except (KeyError, PermissionError, ValueError) as exc:
                print(f"remote-control relay-confirm error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.relay_delivery_confirmed",
                {
                    "pairing_id": result["pairing"]["id"],
                    "outbox_id": result["outbox_id"],
                    "relay_target": result["relay_target"],
                    "relay_acknowledged": result["relay_acknowledged"],
                    "outbox_updated": result["outbox_updated"],
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "relay-pull":
            pairing_id = _option_value(parts, "--pairing-id")
            relay_secret = _option_value(parts, "--relay-auth-secret")
            approved = "--approved" in parts
            dry_run = "--dry-run" in parts
            limit = _optional_int(_option_value(parts, "--limit")) or 10
            if not pairing_id or not relay_secret:
                print("usage: remote-control relay-pull --pairing-id <id> --relay-auth-secret <secret_name> --approved [--limit N] [--dry-run]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                handle = self.orchestrator.secrets_broker.request_handle(
                    name=relay_secret,
                    requester="remote_control_relay",
                    reason="pull queued scoped remote-control relay actions",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                pulled = registry.pull_relay_actions(
                    pairing_id,
                    relay_auth_token=relay_auth_token,
                    allowlist=self.orchestrator.config.network_allowlist,
                    approved=approved,
                    limit=limit,
                )
            except (KeyError, PermissionError, ValueError) as exc:
                print(f"remote-control relay-pull error: {exc}")
                return
            actor = f"remote-control-relay:{pulled['pairing'].get('label') or pulled['pairing']['id']}"
            executed_actions = []
            if not dry_run:
                for action_row in pulled["actions"]:
                    if not action_row["accepted"]:
                        continue
                    action_result = self._execute_remote_control_action(action_row, actor=actor)
                    self.orchestrator.audit_logger.append(
                        "remote_control.relay_action",
                        {
                            "pairing_id": pulled["pairing"]["id"],
                            "relay_target": pulled["relay_target"],
                            "task_id": action_row["task_id"],
                            "action": action_row["action"],
                            "actor": actor,
                            "request_id": action_row.get("request_id"),
                            "pairing_token_relayed": False,
                            "relay_auth_token_captured": False,
                            "raw_secret_values_included": False,
                            "source": "tui_pull",
                        },
                    )
                    executed_actions.append(
                        {
                            "request_id": action_row.get("request_id"),
                            "action": action_row["action"],
                            "task_id": action_row["task_id"],
                            "status": "executed",
                            "result": action_result,
                        }
                    )
            self.orchestrator.audit_logger.append(
                "remote_control.relay_actions_pulled",
                {
                    "pairing_id": pulled["pairing"]["id"],
                    "relay_target": pulled["relay_target"],
                    "action_count": pulled["action_count"],
                    "executable_action_count": pulled["executable_action_count"],
                    "executed_action_count": len(executed_actions),
                    "dry_run": dry_run,
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json({**pulled, "dry_run": dry_run, "executed_action_count": len(executed_actions), "executed_actions": executed_actions})
            return
        if parts and parts[0] == "relay-action":
            pairing_id = _option_value(parts, "--pairing-id")
            task_id = _option_value(parts, "--task-id")
            action = (_option_value(parts, "--action") or "").strip().lower().replace("-", "_")
            relay_secret = _option_value(parts, "--relay-auth-secret")
            if not pairing_id or not task_id or action not in {"status", "events", "resume", "pause", "cancel"} or not relay_secret:
                print("usage: remote-control relay-action --pairing-id <id> --task-id <task_id> --action status|events|resume|pause|cancel --relay-auth-secret <secret_name>")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            try:
                handle = self.orchestrator.secrets_broker.request_handle(
                    name=relay_secret,
                    requester="remote_control_relay",
                    reason="authorize registered remote-control relay action proxy",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                relay_auth = registry.authorize_relay_action(
                    pairing_id,
                    relay_auth_token,
                    action=action,
                    task_id=task_id,
                )
                if relay_auth is None:
                    raise PermissionError("missing or invalid remote-control relay authorization")
            except (KeyError, PermissionError, ValueError) as exc:
                print(f"remote-control relay-action error: {exc}")
                return
            actor = f"remote-control-relay:{relay_auth['pairing'].get('label') or relay_auth['pairing']['id']}"
            if action == "status":
                action_result = build_remote_control_task_status(self.orchestrator.status(task_id))
            elif action == "events":
                action_result = build_remote_control_task_events(self.orchestrator.evidence.run_events(task_id))
            elif action == "resume":
                self.orchestrator.resume_task(task_id, session_id=_option_value(parts, "--session-id"), actor=actor)
                action_result = build_remote_control_task_status(self.orchestrator.status(task_id))
            elif action == "pause":
                self.orchestrator.pause_task(
                    task_id,
                    session_id=_option_value(parts, "--session-id"),
                    actor=actor,
                    reason=_option_value(parts, "--reason") or "remote control relay pause",
                )
                action_result = build_remote_control_task_status(self.orchestrator.status(task_id))
            else:
                self.orchestrator.cancel_task(
                    task_id,
                    session_id=_option_value(parts, "--session-id"),
                    actor=actor,
                    reason=_option_value(parts, "--reason") or "remote control relay cancel",
                )
                action_result = build_remote_control_task_status(self.orchestrator.status(task_id))
            self.orchestrator.audit_logger.append(
                "remote_control.relay_action",
                {
                    "pairing_id": relay_auth["pairing"]["id"],
                    "relay_target": relay_auth["relay_target"],
                    "task_id": task_id,
                    "action": action,
                    "actor": actor,
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "tui",
                },
            )
            _print_json(
                {
                    "status": "relay_action_proxied",
                    "mode": "approved_relay_action_proxy",
                    "action": action,
                    "task_id": task_id,
                    "pairing": relay_auth["pairing"],
                    "relay_target": relay_auth["relay_target"],
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "result": action_result,
                }
            )
            return
        if parts and parts[0] == "relay":
            relay_url = _option_value(parts, "--relay-url")
            if relay_url is None and len(parts) > 1 and not parts[1].startswith("--"):
                relay_url = parts[1]
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            if "--approved" in parts or _option_value(parts, "--pairing-id") or _option_value(parts, "--relay-auth-secret"):
                pairing_id = _option_value(parts, "--pairing-id")
                relay_secret = _option_value(parts, "--relay-auth-secret")
                if not relay_url or not pairing_id or not relay_secret:
                    print("usage: remote-control relay --relay-url <https-url> --pairing-id <id> --relay-auth-secret <secret_name> --approved")
                    return
                try:
                    handle = self.orchestrator.secrets_broker.request_handle(
                        name=relay_secret,
                        requester="remote_control_relay",
                        reason="register scoped remote-control pairing with relay",
                        scopes=("remote_control:relay",),
                    )
                    relay_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                    result = registry.relay_pairing(
                        pairing_id,
                        relay_url=relay_url,
                        allowlist=self.orchestrator.config.network_allowlist,
                        relay_auth_token=relay_auth_token,
                        approved="--approved" in parts,
                    )
                except (KeyError, PermissionError, ValueError) as exc:
                    print(f"remote-control relay error: {exc}")
                    return
                self.orchestrator.audit_logger.append(
                    "remote_control.relay_registered",
                    {
                        "pairing_id": result["pairing"]["id"],
                        "relay_target": result["relay_target"],
                        "relay_auth_secret": "[REDACTED]",
                        "pairing_token_relayed": result["pairing_token_relayed"],
                        "raw_secret_values_included": False,
                        "source": "tui",
                    },
                )
                _print_json(result)
                return
            _print_json(registry.relay_preflight(relay_url=relay_url))
            return
        if parts and parts[0] == "pair":
            label = _option_value(parts, "--label")
            if label is None and len(parts) > 1 and not parts[1].startswith("--"):
                label = parts[1]
            allowed_actions = _comma_separated(
                _option_value(parts, "--allowed-actions") or "status,events,resume,pause,cancel"
            )
            expires_in_seconds = _optional_int(_option_value(parts, "--expires-in-seconds"))
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            result = registry.create_pairing(
                label=label or "tui remote control",
                session_id=_option_value(parts, "--session-id") or self.session.get("id"),
                task_id=_option_value(parts, "--task-id") or self.last_task_id,
                allowed_actions=allowed_actions,
                ttl_seconds=expires_in_seconds,
            )
            self.orchestrator.audit_logger.append(
                "remote_control.pairing_created",
                {
                    "pairing_id": result["pairing"]["id"],
                    "label": result["pairing"]["label"],
                    "session_id": result["pairing"].get("session_id"),
                    "task_id": result["pairing"].get("task_id"),
                    "allowed_actions": result["pairing"].get("allowed_actions"),
                    "expires_at": result["pairing"]["expires_at"],
                    "token_header": result["token_header"],
                    "token_captured": False,
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        if parts and parts[0] == "revoke":
            if len(parts) < 2:
                print("usage: remote-control revoke <pairing_id> [--relay-auth-secret <secret_name> --approved]")
                return
            registry = RemoteControlPairingRegistry(
                self.orchestrator.config.data_dir / "remote_control_pairings.json"
            )
            relay_auth_token = None
            relay_secret = _option_value(parts, "--relay-auth-secret")
            if relay_secret or "--approved" in parts:
                if not relay_secret or "--approved" not in parts:
                    print("usage: remote-control revoke <pairing_id> [--relay-auth-secret <secret_name> --approved]")
                    return
                try:
                    handle = self.orchestrator.secrets_broker.request_handle(
                        name=relay_secret,
                        requester="remote_control_relay",
                        reason="propagate scoped remote-control relay revocation",
                        scopes=("remote_control:relay",),
                    )
                    relay_auth_token = self.orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                except KeyError as exc:
                    print(f"remote-control revoke error: {exc}")
                    return
            try:
                result = registry.revoke(parts[1], relay_auth_token=relay_auth_token, notify_relay=bool(relay_auth_token))
            except (PermissionError, ValueError, KeyError) as exc:
                print(f"remote-control revoke error: {exc}")
                return
            self.orchestrator.audit_logger.append(
                "remote_control.pairing_revoked",
                {
                    "pairing_id": result["pairing"]["id"],
                    "label": result["pairing"]["label"],
                    "session_id": result["pairing"].get("session_id"),
                    "token_captured": False,
                    "relay_revocation_propagated": result["relay_revocation_propagated"],
                    "source": "tui",
                },
            )
            _print_json(result)
            return
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        title = arg.strip() or self.session.get("title") or "Aegis TUI"
        print(
            _boxed_lines(
                "Remote Control",
                [
                    f"Session: {title}",
                    "Status: local control plane available with short-lived pairing tokens.",
                    "Current secure surface: aegis serve --host 127.0.0.1 --port 8765",
                    "Pairing endpoint: POST /remote-control/pair returns one token for X-Aegis-Remote-Token.",
                    "Relay: remote-control relay can register an approved pairing; relay-directory publishes one sanitized scoped directory snapshot; relay-notify publishes one metadata-only mobile/gateway notification; relay-confirm reconciles one delivery receipt; push-register records brokered APNS/FCM targets; push-rotate rotates brokered target references; push publishes one approved native notification; relay-pull polls queued relay actions; relay-action proxies one scoped task action through the registered bearer.",
                    "Security posture: host/origin checks still apply; no subscription token capture; pairing creation needs the local API token.",
                    "Remaining live gap: broad cloud relay delivery.",
                ],
                width,
            )
        )

    def _execute_remote_control_action(self, action_row: dict[str, Any], *, actor: str) -> dict[str, Any]:
        task_id = str(action_row["task_id"])
        action = str(action_row["action"])
        session_id = action_row.get("session_id")
        reason = str(action_row.get("reason") or "")
        if action == "status":
            return build_remote_control_task_status(self.orchestrator.status(task_id))
        if action == "events":
            return build_remote_control_task_events(self.orchestrator.evidence.run_events(task_id))
        if action == "resume":
            self.orchestrator.resume_task(task_id, session_id=session_id, actor=actor)
            return build_remote_control_task_status(self.orchestrator.status(task_id))
        if action == "pause":
            self.orchestrator.pause_task(task_id, session_id=session_id, actor=actor, reason=reason or "remote control relay pause")
            return build_remote_control_task_status(self.orchestrator.status(task_id))
        if action == "cancel":
            self.orchestrator.cancel_task(task_id, session_id=session_id, actor=actor, reason=reason or "remote control relay cancel")
            return build_remote_control_task_status(self.orchestrator.status(task_id))
        raise PermissionError("remote-control relay action is not allowed")

    def do_mobile(self, arg: str) -> None:
        """mobile -- show mobile/remote-control readiness."""
        self.do_remote_control(arg)

    def do_provider(self, arg: str) -> None:
        """provider -- show model providers."""
        self.do_models("providers")

    def do_usage(self, arg: str) -> None:
        """usage -- show model usage summary."""
        self.do_models("usage")

    def do_insights(self, arg: str) -> None:
        """insights [days] -- show sanitized model usage analytics."""
        parts = shlex.split(arg)
        try:
            days = int(parts[0]) if parts else 30
        except ValueError:
            print("usage: insights [days]")
            return
        _print_json(self.orchestrator.models.usage_insights(days=days))

    def do_gquota(self, arg: str) -> None:
        """gquota [google-gemini-oauth/model] -- show Google Gemini Code Assist quota metadata."""
        identifier = arg.strip() or str(self.session.get("model") or "")
        if not identifier or not identifier.startswith("google-gemini-oauth/"):
            _print_json(
                {
                    "status": "not_enabled",
                    "provider_required": "google-gemini-oauth",
                    "active_model": self.session.get("model") or "alias/smart",
                    "detail": "Gemini Code Assist quota is available after selecting a google-gemini-oauth/<model-id> route.",
                    "next_actions": [
                        "models auth login google-gemini-oauth --method oauth --run-external",
                        "model google-gemini-oauth/gemini-2.5-flash",
                        "gquota google-gemini-oauth/gemini-2.5-flash",
                    ],
                }
            )
            return
        try:
            route = self.orchestrator.models.route(identifier)
            _print_json(self.orchestrator.model_client.google_gemini_oauth_quota(route))
        except (KeyError, ValueError, RuntimeError) as exc:
            _print_json(
                {
                    "status": "quota_unavailable",
                    "provider": "google-gemini-oauth",
                    "error": str(exc),
                    "raw_secret_values_included": False,
                    "next_actions": ["models auth status google-gemini-oauth", "models auth login google-gemini-oauth --method oauth --run-external"],
                }
            )

    def do_stats(self, arg: str) -> None:
        """stats -- Hermes-style alias for usage."""
        self.do_usage(arg)

    def do_cost(self, arg: str) -> None:
        """cost -- Claude-style alias for model usage and estimated cost."""
        self.do_models("usage")

    def do_reasoning(self, arg: str) -> None:
        """reasoning [level] -- alias for effort."""
        self.do_effort(arg)

    def do_gateway(self, arg: str) -> None:
        """gateway -- show channels, connectors, and remote-control surfaces."""
        self.do_platforms(arg)

    def do_kanban(self, arg: str) -> None:
        """kanban -- alias for boards."""
        self.do_boards(arg)

    def do_continue(self, arg: str) -> None:
        """continue <task_id> -- alias for resume."""
        self.do_resume(arg)

    def do_add_dir(self, arg: str) -> None:
        """add_dir <path> -- record an additional working directory request for the active session."""
        raw_path = arg.strip()
        if not raw_path:
            print("usage: add-dir <path>")
            return
        requested = Path(raw_path).expanduser()
        resolved = (self.workspace / requested).resolve() if not requested.is_absolute() else requested.resolve()
        exists = resolved.exists()
        if resolved not in self.additional_dirs:
            self.additional_dirs.append(resolved)
        self.orchestrator.sessions.add_message(
            self.session["id"],
            role="user",
            content=f"Additional working directory requested: {resolved}",
            trust_class=TrustClass.USER_DIRECTIVE,
            metadata={"source": "tui_add_dir", "submitted": False, "path": str(resolved), "exists": exists},
        )
        self.orchestrator.audit_logger.append(
            "tui.add_dir_requested",
            {"session_id": self.session["id"], "path": str(resolved), "exists": exists, "active_filesystem_scope": False},
        )
        _print_json(
            {
                "status": "recorded_for_session_context",
                "path": str(resolved),
                "exists": exists,
                "active_filesystem_scope": False,
                "additional_dirs": [str(path) for path in self.additional_dirs],
                "detail": "Aegis recorded the extra directory as trusted session context; multi-root filesystem connector scopes remain a governed backend gap.",
            }
        )

    def do_model(self, arg: str) -> None:
        """model [identifier|args] -- set active session model or inspect models."""
        raw = arg.strip()
        if not raw:
            self.do_models("providers")
            return
        parts = shlex.split(raw)
        if parts and parts[0] in MODEL_COMMANDS:
            self.do_models(raw)
            return
        if len(parts) != 1:
            print("usage: model <identifier>|list|providers|route <identifier>|auth ...")
            return
        identifier = parts[0]
        try:
            route = self.orchestrator.models.route(identifier)
            self.session = self.orchestrator.sessions.update_session(self.session["id"], model=identifier)
        except (KeyError, ValueError) as exc:
            print(f"model route failed: {exc}")
            return
        _print_json(
            {
                "status": "session_model_updated",
                "session_id": self.session["id"],
                "model": identifier,
                "provider": route.provider.provider,
                "resolved_model": route.model,
                "auth_method": route.auth_method,
            }
        )

    def do_login(self, arg: str) -> None:
        """login [provider [subscription]] -- model auth login alias."""
        parts = shlex.split(arg)
        if not parts:
            self.do_models("auth targets")
            return
        self.do_models(f"auth login {' '.join(shlex.quote(part) for part in parts)}")

    def do_logout(self, arg: str) -> None:
        """logout <provider> -- model auth logout alias."""
        provider = arg.strip()
        if not provider:
            print("usage: logout <provider>")
            return
        self.do_models(f"auth logout {shlex.quote(provider)}")

    def do_setup(self, arg: str) -> None:
        """setup -- show guided local setup readiness."""
        _print_json(build_setup_readiness(self.orchestrator, config_path=self.orchestrator.config.data_dir / "config.toml"))

    def do_setup_bedrock(self, arg: str) -> None:
        """setup_bedrock -- show AWS Bedrock cloud-identity setup bridge."""
        _print_json(
            {
                "status": "provider_setup_bridge",
                "provider": "aws-bedrock",
                "auth_method": "cloud_identity",
                "interactive_browser_from_tui": False,
                "next_actions": [
                    "models auth login aws-bedrock cloud-identity --run-external",
                    "models auth login aws-bedrock cloud-identity --verify-external",
                    "model aws-bedrock/<model-id>",
                ],
                "raw_secret_values_included": False,
            }
        )

    def do_setup_vertex(self, arg: str) -> None:
        """setup_vertex -- show Google Vertex cloud-identity setup bridge."""
        _print_json(
            {
                "status": "provider_setup_bridge",
                "provider": "google-vertex",
                "auth_method": "cloud_identity",
                "interactive_browser_from_tui": False,
                "next_actions": [
                    "models auth login google cloud-identity --run-external",
                    "models auth login google cloud-identity --verify-external",
                    "model google-vertex/<model-id>",
                ],
                "raw_secret_values_included": False,
            }
        )

    def do_doctor(self, arg: str) -> None:
        """doctor -- diagnose local runtime posture."""
        dashboard = build_product_dashboard(self.orchestrator)
        _print_json(
            {
                "ok": True,
                "audit_chain_ok": dashboard["runtime"]["audit_chain_ok"],
                "pending_approvals": dashboard["runtime"]["pending_approvals"],
                "model_providers": dashboard["runtime"]["model_providers"],
                "live_gap_areas": [item["area"] for item in dashboard.get("live_gap_backlog", [])],
                "security_controls": dashboard["security_controls"],
            }
        )

    def do_bug(self, arg: str) -> None:
        """bug [summary] -- capture a local bug report without sending telemetry."""
        summary = arg.strip()
        if not summary:
            print("usage: bug <summary>")
            return
        self.orchestrator.audit_logger.append(
            "tui.bug_report_captured",
            {"session_id": self.session["id"], "summary": summary, "telemetry_sent": False},
        )
        _print_json(
            {
                "status": "captured_local_only",
                "telemetry_sent": False,
                "summary": summary,
                "next_actions": ["repair readiness", "repair generate-candidate <proposal_id>", "review"],
            }
        )

    def do_config(self, arg: str) -> None:
        """config -- show local config paths and runtime flags."""
        config = self.orchestrator.config
        _print_json(
            {
                "data_dir": str(config.data_dir),
                "database": str(config.database_path),
                "audit_log": str(config.audit_log_path),
                "secrets": str(config.secrets_path),
                "workspace": str(self.workspace),
                "default_read_only": config.default_read_only,
                "network_allowlist": list(config.network_allowlist),
            }
        )

    def do_commands(self, arg: str) -> None:
        """commands [prefix] -- show the slash command palette."""
        prefix = arg.strip()
        if prefix == "all":
            print(_command_reference())
            return
        print(self._render_slash_palette(prefix))

    def do_copy(self, arg: str) -> None:
        """copy -- show explicit copy surfaces without mutating the clipboard."""
        try:
            task = self.orchestrator.status(self.last_task_id) if self.last_task_id else None
        except KeyError:
            task = None
        model_content = _model_content(task) if task is not None else None
        _print_json(
            {
                "status": "operator_action_required",
                "mode": "metadata_only",
                "clipboard_mutated": False,
                "last_task_id": self.last_task_id,
                "model_response_available": model_content is not None,
                "model_response_character_count": len(model_content) if model_content is not None else 0,
                "raw_message_content_included": False,
                "next_actions": ["session history", "task evidence <task_id>", "copy from terminal selection"],
            }
        )

    def do_paste(self, arg: str) -> None:
        """paste [content] -- append explicit pasted context without reading the clipboard."""
        pasted = arg.strip()
        if pasted:
            message = self.orchestrator.sessions.add_message(
                self.session["id"],
                role="user",
                content=pasted,
                trust_class=TrustClass.CHAT_CONTENT,
                metadata={
                    "source": "tui_paste",
                    "submitted": False,
                    "clipboard_read": False,
                    "raw_clipboard_content_rendered": False,
                },
            )
            _print_json(
                {
                    "status": "pasted_context_appended",
                    "mode": "explicit_session_context",
                    "message_id": message["id"],
                    "active_session_id": self.session["id"],
                    "character_count": len(pasted),
                    "trust_class": TrustClass.CHAT_CONTENT.value,
                    "clipboard_read": False,
                    "clipboard_mutated": False,
                    "raw_clipboard_content_included": False,
                    "submitted": False,
                    "next_actions": ["submit <request>", "session history", "context"],
                }
            )
            return
        _print_json(
            {
                "status": "operator_action_required",
                "mode": "metadata_only",
                "clipboard_read": False,
                "clipboard_mutated": False,
                "raw_clipboard_content_included": False,
                "detail": "Aegis does not read clipboard content implicitly; paste text into the prompt or append explicit session context.",
                "next_actions": ["session append <content> --trust-class USER_DIRECTIVE", "submit <request>", "copy from terminal selection"],
            }
        )

    def do_image(self, arg: str) -> None:
        """image <path> -- attach explicit local image metadata to the active session."""
        image_arg = arg.strip()
        if image_arg:
            image_path = Path(image_arg).expanduser()
            if not image_path.is_absolute():
                image_path = self.workspace / image_path
            resolved = image_path.resolve()
            try:
                workspace_scoped = resolved.is_relative_to(self.workspace)
            except ValueError:
                workspace_scoped = False
            exists = resolved.exists()
        else:
            resolved = None
            workspace_scoped = False
            exists = False
        if resolved and workspace_scoped and exists and resolved.is_file():
            vision = self.orchestrator.tools.execute("vision_analyze", {"image_path": str(resolved)})
            image_metadata = vision.get("metadata", {}) if isinstance(vision.get("metadata", {}), dict) else {}
            content = (
                "Local image metadata attached: "
                f"{Path(str(vision.get('path') or resolved)).name}; "
                f"format={image_metadata.get('format') or 'unknown'}; "
                f"dimensions={image_metadata.get('width') or 0}x{image_metadata.get('height') or 0}; "
                f"bytes={vision.get('bytes') or 0}."
            )
            message = self.orchestrator.sessions.add_message(
                self.session["id"],
                role="user",
                content=content,
                trust_class=TrustClass.DOCUMENT_CONTENT,
                metadata={
                    "source": "tui_image",
                    "submitted": False,
                    "image_path": str(resolved),
                    "vision_tool": "vision_analyze",
                    "raw_image_bytes_included": False,
                    "raw_ocr_content_included": False,
                    "format": image_metadata.get("format"),
                    "width": image_metadata.get("width"),
                    "height": image_metadata.get("height"),
                    "size_bytes": vision.get("bytes"),
                },
            )
            _print_json(
                {
                    "status": "image_metadata_attached",
                    "mode": "local_image_metadata",
                    "message_id": message["id"],
                    "active_session_id": self.session["id"],
                    "image_path": str(resolved),
                    "exists": True,
                    "workspace_scoped": True,
                    "format": image_metadata.get("format"),
                    "width": image_metadata.get("width"),
                    "height": image_metadata.get("height"),
                    "size_bytes": vision.get("bytes"),
                    "raw_image_bytes_included": False,
                    "raw_ocr_content_included": False,
                    "submitted": False,
                    "next_actions": ["submit describe the attached image metadata", "session history", "browser screenshot"],
                }
            )
            return
        _print_json(
            {
                "status": "image_attachment_rejected" if resolved else "operator_action_required",
                "mode": "metadata_only",
                "image_path": str(resolved) if resolved else None,
                "exists": exists,
                "workspace_scoped": workspace_scoped,
                "raw_image_bytes_included": False,
                "raw_ocr_content_included": False,
                "detail": "Provide an existing workspace-scoped image path to attach local metadata; raw image bytes are never rendered.",
                "next_actions": ["image <workspace-image-path>", "browser screenshot", "submit describe explicit image path"],
            }
        )

    def do_export(self, arg: str) -> None:
        """export -- show explicit export surfaces and redaction boundaries."""
        _print_json(
            {
                "status": "operator_action_required",
                "mode": "metadata_only",
                "automatic_workspace_write": False,
                "raw_message_content_included": False,
                "raw_secret_values_included": False,
                "available_exports": [
                    "memory export",
                    "audit export-siem",
                    "session history <session_id>",
                    "task evidence <task_id>",
                ],
                "next_actions": ["memory export", "audit export-siem", "session history", "evidence <task_id>"],
            }
        )

    def do_rename(self, arg: str) -> None:
        """rename [title] -- rename the active session through the governed session store."""
        title = arg.strip()
        if not title:
            _print_json(
                {
                    "status": "operator_action_required",
                    "active_session_id": self.session.get("id"),
                    "current_title": self.session.get("title"),
                    "next_actions": ["rename <title>", "title <title>", "session rename <title>"],
                    "raw_message_content_included": False,
                }
            )
            return
        self.do_session(f"rename {shlex.quote(title)}")

    def do_permissions(self, arg: str) -> None:
        """permissions -- Claude-style alias for policy posture."""
        self.do_security("profile")

    def do_privacy_settings(self, arg: str) -> None:
        """privacy_settings -- show local privacy and telemetry posture."""
        profile = policy_profile_to_dict(self.orchestrator.config.policy_profile)
        _print_json(
            {
                "status": "local_privacy_settings",
                "telemetry_enabled": False,
                "transcript_upload_enabled": False,
                "raw_secret_exposure": profile.get("raw_secret_exposure"),
                "audit_redaction": "enabled",
                "context_firewall": "enabled",
                "local_state_dir": str(self.orchestrator.config.data_dir),
                "raw_message_content_included": False,
                "raw_secret_values_included": False,
                "next_actions": ["security profile", "audit export-siem", "memory health", "channels"],
            }
        )

    def do_whoami(self, arg: str) -> None:
        """whoami -- show local actor, session, and policy posture metadata."""
        profile = policy_profile_to_dict(self.orchestrator.config.policy_profile)
        _print_json(
            {
                "status": "metadata_only",
                "actor": getpass.getuser(),
                "workspace": str(self.workspace),
                "active_session_id": self.session.get("id"),
                "active_session_title": self.session.get("title"),
                "session_status": self.session.get("status"),
                "model": self.session.get("model") or "alias/smart",
                "personality": self.session.get("personality") or "default",
                "admin_mode_enabled": False,
                "approval_bypass_enabled": False,
                "policy": {
                    "read_only": profile.get("read_only"),
                    "network_allowlist": profile.get("network_allowlist", []),
                    "shell_allowlist": profile.get("shell_allowlist", []),
                },
                "raw_secret_values_included": False,
                "next_actions": ["permissions", "security profile", "session", "models auth targets"],
            }
        )

    def do_yolo(self, arg: str) -> None:
        """yolo -- report that approval bypass is intentionally not enabled."""
        _print_json(
            {
                "status": "not_enabled",
                "approval_bypass_enabled": False,
                "dangerous_command_auto_approval": False,
                "detail": "Aegis keeps high-impact actions behind policy and approval gates; yolo mode is not implemented as an approval bypass.",
                "next_actions": ["permissions", "security profile", "allowed-tools", "toolsets"],
            }
        )

    def do_profile(self, arg: str) -> None:
        """profile -- show active policy profile."""
        self.do_security("profile")

    def do_sandbox(self, arg: str) -> None:
        """sandbox -- show execution backend sandbox posture."""
        self.do_backends(arg)

    def do_effort(self, arg: str) -> None:
        """effort [level] -- show guarded model-effort status."""
        level = arg.strip()
        _print_json(
            {
                "status": "metadata_only",
                "requested_effort": level or None,
                "current_model": self.session.get("model"),
                "detail": "Aegis routes model identifiers and context budgets today; provider-specific reasoning effort controls need per-provider request adapters before mutation.",
            }
        )

    def do_fast(self, arg: str) -> None:
        """fast [request] -- use or inspect the fast model alias."""
        if arg.strip():
            self.do_submit(arg)
            return
        self.do_models("route alias/fast")

    def do_agents(self, arg: str) -> None:
        """agents [status|autonomy-preflight|profiles|profile-create|profile-disable|delegate|handoff|review-packet|verify-packet|model-review|run|run-batch] -- manage subagent delegations."""
        parts = shlex.split(arg)
        if parts and parts[0] == "autonomy-preflight":
            _print_json(self.orchestrator.kanban.subagent_autonomy_preflight(actor="tui-operator", limit=20))
            return
        if parts and parts[0] == "profiles":
            _print_json({"profiles": self.orchestrator.kanban.list_subagent_profiles(), "subagents": self.orchestrator.kanban.subagent_status(limit=20)})
            return
        if parts and parts[0] == "profile-create":
            if len(parts) < 2:
                print("usage: agents profile-create <name> [--role role] [--tool tool]")
                return
            options = _parse_subagent_profile_options(parts[2:])
            result = self.orchestrator.kanban.create_subagent_profile(parts[1], actor="tui-operator", **options)
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20)})
            return
        if parts and parts[0] == "profile-disable":
            if len(parts) < 2:
                print("usage: agents profile-disable <profile-id>")
                return
            result = self.orchestrator.kanban.disable_subagent_profile(parts[1], actor="tui-operator")
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20)})
            return
        if parts and parts[0] == "delegate":
            approved = "--approved" in parts[1:]
            delegate_parts = [part for part in parts[1:] if part != "--approved"]
            if len(delegate_parts) < 2:
                print("usage: agents delegate <role> <task> [--approved]")
                return
            result = self.orchestrator.tools.execute(
                "subagent_delegate",
                {"role": delegate_parts[0], "task": " ".join(delegate_parts[1:])},
                approved=approved,
                task_id=self.last_task_id,
            )
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20)})
            return
        if parts and parts[0] == "handoff":
            if len(parts) < 3:
                print("usage: agents handoff <card-id> <lane> [reason]")
                return
            result = self.orchestrator.kanban.move_subagent_delegation(
                parts[1],
                parts[2],
                actor="tui-operator",
                reason=" ".join(parts[3:]),
            )
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20)})
            return
        if parts and parts[0] == "review-packet":
            if len(parts) < 2:
                print("usage: agents review-packet <card-id>")
                return
            result = self.orchestrator.kanban.create_subagent_review_packet(
                parts[1],
                actor="tui-operator",
            )
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20, include_previews=False)})
            return
        if parts and parts[0] == "verify-packet":
            if len(parts) < 2:
                print("usage: agents verify-packet <packet-id-or-path>")
                return
            result = self.orchestrator.kanban.verify_subagent_review_packet(
                parts[1],
                actor="tui-operator",
            )
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20, include_previews=False)})
            return
        if parts and parts[0] == "model-review":
            if len(parts) < 2:
                print("usage: agents model-review <card-id> [--approved]")
                return
            result = self.orchestrator.model_review_subagent(
                parts[1],
                actor="tui-operator",
                approved="--approved" in parts[2:],
            )
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20, include_previews=False)})
            return
        if parts and parts[0] == "run":
            if len(parts) < 2:
                print("usage: agents run <card-id> [--approved]")
                return
            result = self.orchestrator.kanban.run_subagent_delegation(
                parts[1],
                actor="tui-operator",
                approved="--approved" in parts[2:],
            )
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20)})
            return
        if parts and parts[0] == "run-batch":
            options = _parse_subagent_run_batch_options(parts[1:])
            result = self.orchestrator.kanban.run_subagent_batch(
                card_ids=options["card_ids"],
                actor="tui-operator",
                approved=options["approved"],
                limit=options["limit"],
            )
            _print_json({**result, "subagents": self.orchestrator.kanban.subagent_status(limit=20)})
            return
        dashboard = build_product_dashboard(self.orchestrator)
        _print_json(
            {
                "status": "coordination_surfaces_ready",
                "boards": dashboard["runtime"]["boards"],
                "schedules": dashboard["runtime"]["schedules"],
                "skills": len(self.orchestrator.skills.list_public()),
                "subagent_tool": next((tool for tool in self.orchestrator.tool_catalog.list() if tool["name"] == "subagent_delegate"), None),
                "subagent_delegations": dashboard["subagent_delegations"],
                "remaining_depth_work": dashboard["subagent_delegations"]["remaining_depth_work"],
            }
        )

    def do_batch(self, arg: str) -> None:
        """batch -- show batch/evaluation work queues."""
        self.do_evaluation("queue")

    def do_goal(self, arg: str) -> None:
        """goal -- show current task and scheduling goal surfaces."""
        _print_json(
            {
                "last_task_id": self.last_task_id,
                "active_session_id": self.session.get("id"),
                "schedules": self.orchestrator.schedules.list_schedules(),
            }
        )

    def do_loop(self, arg: str) -> None:
        """loop -- show self-improvement and evaluation readiness."""
        _print_json(
            {
                "repair_readiness": self.orchestrator.repair_readiness_summary(limit=20),
                "evaluation_readiness": ResearchHarness(data_dir=self.orchestrator.config.data_dir).release_readiness_summary(limit=20),
            }
        )

    def do_queue(self, arg: str) -> None:
        """queue [status|all|session <id>|submit <request>|request] -- show or submit governed work."""
        parts = shlex.split(arg)
        if parts and parts[0] == "submit":
            request = " ".join(parts[1:]).strip()
            if not request:
                print("queue submit requires a request")
                return
            self._submit_queued_task(request)
            return
        queue_words = {"status", "show", "list", "active", "pending", "all", "session"}
        status_words = {"pending", "planned", "running", "waiting", "waiting_approval", "paused"}
        if not parts or parts[0] in queue_words or parts[0] in status_words or parts[0].startswith("--"):
            self._print_queue(parts)
            return
        self._submit_queued_task(arg.strip())

    def _submit_queued_task(self, request: str) -> None:
        result = self.orchestrator.submit_task(request, session_id=self.session["id"])
        self.last_task_id = result["id"]
        _print_json(
            {
                "status": "queued_task_submitted",
                "task_id": result["id"],
                "active_session_id": self.session.get("id"),
                "raw_task_request_included": False,
                "next_actions": [f"status {result['id']}", f"events {result['id']}", "queue"],
            }
        )
        _print_task_result(result)

    def _print_queue(self, parts: list[str]) -> None:
        limit = int(_option_value(parts, "--limit") or "12")
        requested_status = _option_value(parts, "--status")
        positional = _positional_without_flags(parts, {"--limit": 1, "--status": 1})
        if positional and positional[0] in {"status", "show", "list", "active"}:
            positional = positional[1:]
        session_id: str | None = self.session["id"]
        scope = "session"
        statuses: set[str] = set(ACTIVE_WORK_STATUSES_TUI)
        if requested_status:
            statuses = {_normalize_queue_status(requested_status)}
        if positional:
            head = positional[0]
            if head == "all":
                session_id = None
                scope = "all"
            elif head == "session":
                session_id = positional[1] if len(positional) > 1 else self.session["id"]
                scope = "session"
            elif head in {"pending", "planned", "running", "waiting", "waiting_approval", "paused"}:
                statuses = set(ACTIVE_WORK_STATUSES_TUI) if head == "pending" else {_normalize_queue_status(head)}
        rows = _queue_rows(self.orchestrator, limit=limit, session_id=session_id, statuses=statuses)
        counts = _status_counts(rows)
        _print_json(
            {
                "status": "active_queue",
                "scope": scope,
                "active_session_id": self.session.get("id"),
                "queue_task_count": len(rows),
                "status_counts": counts,
                "raw_task_requests_included": False,
                "next_actions": ["busy status", "busy interrupt <task_id>", "approve <approval_id>", "resume <task_id>"],
            }
        )
        if rows:
            print(
                _table(
                    [_queue_task_row(self.orchestrator, row) for row in rows],
                    (
                        ("id", "short_id", 10),
                        ("status", "status", 18),
                        ("risk", "risk_level", 10),
                        ("session", "session_label", 20),
                        ("next", "next_actions", 120),
                        ("updated", "updated_at", 22),
                    ),
                )
            )
        else:
            print("queue empty")

    def do_routines(self, arg: str) -> None:
        """routines -- show scheduled automation surfaces."""
        _print_json(
            {
                "status": "metadata_only",
                "routines": self.orchestrator.schedules.list_schedules(),
                "next_actions": ["schedule create <name> <cron> <task>", "schedule due", "cron"],
                "raw_secret_values_included": False,
            }
        )

    def do_branch(self, arg: str) -> None:
        """branch -- show guarded conversation branch readiness."""
        session = self.orchestrator.sessions.get_session(self.session["id"])
        _print_json(
            {
                "status": "metadata_only",
                "feature": "conversation_branch",
                "mutation": "disabled_by_command",
                "active_session_id": session["id"],
                "title": session.get("title"),
                "message_count": session.get("message_count", 0),
                "task_count": session.get("task_count", 0),
                "raw_message_content_included": False,
                "next_actions": ["session new <title>", f"session history {session['id']}", "session compact"],
                "remaining_depth_work": ["branch_lineage_model", "branch_diff_receipts", "merge_or_archive_controls"],
            }
        )

    def do_fork(self, arg: str) -> None:
        """fork -- alias for guarded conversation branch readiness."""
        self.do_branch(arg)

    def do_context(self, arg: str) -> None:
        """context -- show active session context metadata without raw transcript content."""
        session = self.orchestrator.sessions.get_session(self.session["id"])
        project_context = ContextFileLoader(self.workspace).manifest()
        _print_json(
            {
                "status": "metadata_only",
                "active_session_id": session["id"],
                "title": session.get("title"),
                "channel": session.get("channel"),
                "session_status": session.get("status"),
                "model": session.get("model") or "alias/smart",
                "personality": session.get("personality") or "default",
                "message_count": session.get("message_count", 0),
                "task_count": session.get("task_count", 0),
                "waiting_task_count": session.get("waiting_task_count", 0),
                "steering": _session_steering_summary(session),
                "ui_preferences": session.get("metadata", {}).get("tui_preferences", {}),
                "workspace": str(self.workspace),
                "additional_dirs": [str(path) for path in self.additional_dirs],
                "project_context_files": project_context,
                "trust_boundary": "raw transcript content stays behind session history and context firewall processing",
                "raw_message_content_included": False,
                "raw_steering_instruction_included": False,
                "next_actions": ["history", "compact", "memory health", "session tasks"],
            }
        )

    def do_debug(self, arg: str) -> None:
        """debug -- show safe runtime diagnostics without dumping logs."""
        dashboard = build_product_dashboard(self.orchestrator)
        _print_json(
            {
                "status": "metadata_only",
                "debug_readiness": "local_diagnostics_available",
                "audit_chain_ok": dashboard["runtime"]["audit_chain_ok"],
                "pending_approvals": dashboard["runtime"]["pending_approvals"],
                "recent_task_count": int(dashboard["runtime"].get("recent_tasks", 0)),
                "session_count": dashboard["runtime"]["sessions"],
                "model_providers": dashboard["runtime"]["model_providers"],
                "live_gap_areas": [item["area"] for item in dashboard.get("live_gap_backlog", [])],
                "raw_audit_log_included": False,
                "raw_secret_values_included": False,
                "next_actions": ["doctor", "dashboard", "audit", "capabilities"],
            }
        )

    def do_save(self, arg: str) -> None:
        """save -- show explicit export/save surfaces without writing arbitrary files."""
        _print_json(
            {
                "status": "operator_action_required",
                "mode": "metadata_only",
                "active_session_id": self.session.get("id"),
                "automatic_workspace_write": False,
                "raw_message_content_included": False,
                "next_actions": ["session history", "memory export", "audit export-siem", "task evidence <task_id>"],
                "detail": "Aegis does not silently save transcripts from the TUI; use an explicit export/history command and review redaction boundaries.",
            }
        )

    def do_prompt(self, arg: str) -> None:
        """prompt -- show prompt/personality surfaces without mutating system prompts."""
        session = self.orchestrator.sessions.get_session(self.session["id"])
        _print_json(
            {
                "status": "metadata_only",
                "prompt_mutation": "session_metadata_only",
                "active_session_id": session.get("id"),
                "model": session.get("model") or "alias/smart",
                "personality": session.get("personality") or "default",
                "steering": _session_steering_summary(session),
                "context_firewall": "enabled_for_untrusted_history_and_tool_outputs",
                "raw_system_prompt_included": False,
                "raw_message_content_included": False,
                "raw_steering_instruction_included": False,
                "next_actions": ["personality", "session set-model <model>", "context", "models auth targets"],
            }
        )

    def do_plan(self, arg: str) -> None:
        """plan -- show no-mutation planning/readiness context."""
        _print_json(
            {
                "status": "plan_mode_readiness",
                "mutation": "disabled_by_command",
                "active_session_id": self.session.get("id"),
                "model": self.session.get("model") or "alias/smart",
                "next_actions": ["dashboard", "tasks", "approvals", "repair readiness", "evaluation readiness"],
            }
        )

    def do_ultraplan(self, arg: str) -> None:
        """ultraplan [prompt] -- show governed plan handoff readiness."""
        prompt = arg.strip()
        _print_json(
            {
                "status": "ultraplan_readiness",
                "cloud_plan_session_started": False,
                "local_plan_mode_available": True,
                "prompt_received": bool(prompt),
                "prompt_chars": len(prompt),
                "raw_prompt_included": False,
                "next_actions": ["plan", "batch", "repair synthesis-prompt <proposal_id>", "evaluation readiness"],
            }
        )

    def do_remote_env(self, arg: str) -> None:
        """remote_env -- show remote environment readiness."""
        self.do_remote_control(arg)

    def do_teleport(self, arg: str) -> None:
        """teleport -- show guarded remote handoff readiness."""
        self.do_remote_control(arg)

    def do_web_setup(self, arg: str) -> None:
        """web_setup -- show local web control-plane setup."""
        _print_json(
            {
                "status": "local_web_available",
                "command": "PYTHONPATH=src python3 -m aegis.cli.main serve --workspace . --host 127.0.0.1 --port 8765",
                "remote_control": "blocked_until_pairing_relay_and_audit_receipts",
            }
        )

    def do_terminal_setup(self, arg: str) -> None:
        """terminal_setup -- show multiline and terminal keybinding readiness."""
        _print_json(
            {
                "status": "inline_terminal_ready",
                "prompt_wrapping": "enabled",
                "slash_autocomplete": "enabled",
                "literal_newline_input": "enabled",
                "newline_keybinding": "Ctrl+V",
                "alt_enter": "supported_when_terminal_emits_escape_enter",
                "detail": "The live TUI wraps long input lines in-place and supports literal multiline prompts with Ctrl+V before final Enter submits.",
            }
        )

    def do_keybindings(self, arg: str) -> None:
        """keybindings -- show terminal keybinding readiness."""
        self.do_terminal_setup(arg)

    def do_mouse(self, arg: str) -> None:
        """mouse -- show mouse interaction readiness."""
        _print_json(
            {
                "status": "metadata_only",
                "mouse_support": "not_enabled",
                "terminal_backend_required": True,
                "selection_mode": "terminal_native",
                "raw_message_content_included": False,
                "detail": "Mouse-aware selection and click targets need terminal backend support before Aegis can safely bind them.",
            }
        )

    def do_scroll_speed(self, arg: str) -> None:
        """scroll_speed [value] -- record scroll preference metadata for this session."""
        value = arg.strip()
        preferences = dict(self.session.get("metadata", {}).get("tui_preferences") or {})
        if value:
            preferences["scroll_speed"] = value[:40]
            self.session = self.orchestrator.sessions.update_metadata(
                self.session["id"],
                {"scroll_speed": preferences["scroll_speed"]},
                namespace="tui_preferences",
            )
        _print_json(
            {
                "status": "ui_preference_updated" if value else "metadata_only",
                "preference": "scroll_speed",
                "value": preferences.get("scroll_speed"),
                "terminal_backend_required": True,
                "raw_message_content_included": False,
                "next_actions": ["mouse", "terminal-setup", "tui fullscreen"],
            }
        )

    def do_tui(self, arg: str) -> None:
        """tui [default|fullscreen] -- show terminal renderer status."""
        requested = arg.strip() or "default"
        _print_json(
            {
                "status": "renderer_metadata",
                "requested_renderer": requested,
                "active_renderer": "inline",
                "fullscreen_renderer_available": False,
                "prompt_wrapping": "enabled",
                "literal_newline_input": "enabled",
                "raw_message_content_included": False,
                "next_actions": ["terminal-setup", "redraw", "dashboard"],
            }
        )

    def do_chrome(self, arg: str) -> None:
        """chrome -- show guarded browser/Chrome integration readiness."""
        _print_json(
            {
                "status": "browser_integration_readiness",
                "chrome_extension_connected": False,
                "static_browser_sandbox": "available",
                "live_browser_automation": "read_only_mutation_download_upload_or_javascript_available_if_configured",
                "next_actions": ["browser status", "browser inspect", "browser render", "browser live-navigate https://example.com", "browser live-click <selector>", "browser live-download <selector>", "browser live-upload <selector> <path>", "browser live-evaluate <script>", "capabilities"],
                "raw_browser_content_included": False,
                "raw_secret_values_included": False,
            }
        )

    def _print_claude_style_readiness(self, *, command: str, feature: str, next_actions: list[str], status: str = "metadata_only") -> None:
        _print_json(
            {
                "status": status,
                "command": command,
                "feature": feature,
                "external_action_started": False,
                "local_controls_only": True,
                "raw_message_content_included": False,
                "raw_secret_values_included": False,
                "next_actions": next_actions,
            }
        )

    def do_claude_api(self, arg: str) -> None:
        """claude_api [migrate|managed-agents-onboard] -- show API migration readiness."""
        mode = shlex.split(arg)[0] if arg.strip() else "reference"
        self._print_claude_style_readiness(
            command="claude-api",
            feature=f"claude_api_{mode}_readiness",
            status="claude_api_readiness",
            next_actions=["models auth targets", "capabilities", "mcp list", "skills hub"],
        )

    def do_extra_usage(self, arg: str) -> None:
        """extra_usage -- show account/usage boundary metadata."""
        self._print_claude_style_readiness(
            command="extra-usage",
            feature="account_extra_usage_boundary",
            status="account_boundary_metadata",
            next_actions=["usage", "models auth targets", "upgrade"],
        )

    def do_fewer_permission_prompts(self, arg: str) -> None:
        """fewer_permission_prompts -- show permission-hardening readiness."""
        self._print_claude_style_readiness(
            command="fewer-permission-prompts",
            feature="permission_prompt_reduction_review",
            status="permission_review_readiness",
            next_actions=["permissions", "allowed-tools", "security evaluate"],
        )

    def do_focus(self, arg: str) -> None:
        """focus -- show focused-view readiness."""
        self._print_claude_style_readiness(
            command="focus",
            feature="focused_view_metadata",
            status="focus_view_readiness",
            next_actions=["tui fullscreen", "details", "statusbar"],
        )

    def do_heapdump(self, arg: str) -> None:
        """heapdump -- show diagnostics boundary metadata."""
        self._print_claude_style_readiness(
            command="heapdump",
            feature="diagnostic_heap_snapshot_boundary",
            status="diagnostic_boundary_metadata",
            next_actions=["debug", "doctor", "audit export-siem"],
        )

    def do_ide(self, arg: str) -> None:
        """ide -- show IDE integration readiness."""
        self._print_claude_style_readiness(
            command="ide",
            feature="ide_integration_readiness",
            status="ide_readiness",
            next_actions=["terminal-setup", "web-setup", "capabilities"],
        )

    def do_install_github_app(self, arg: str) -> None:
        """install_github_app -- show governed GitHub app setup boundary."""
        self._print_claude_style_readiness(
            command="install-github-app",
            feature="github_app_setup_boundary",
            status="external_install_boundary",
            next_actions=["connectors", "web-setup", "autofix-pr"],
        )

    def do_install_slack_app(self, arg: str) -> None:
        """install_slack_app -- show governed Slack app setup boundary."""
        self._print_claude_style_readiness(
            command="install-slack-app",
            feature="slack_app_setup_boundary",
            status="external_install_boundary",
            next_actions=["channels", "handoff slack", "web-setup"],
        )

    def do_passes(self, arg: str) -> None:
        """passes -- show subscription/account boundary metadata."""
        self._print_claude_style_readiness(
            command="passes",
            feature="subscription_share_boundary",
            status="account_boundary_metadata",
            next_actions=["usage", "upgrade", "models auth targets"],
        )

    def do_powerup(self, arg: str) -> None:
        """powerup -- show local feature discovery surfaces."""
        self._print_claude_style_readiness(
            command="powerup",
            feature="feature_discovery",
            status="feature_discovery_ready",
            next_actions=["commands", "capabilities", "menu"],
        )

    def do_team_onboarding(self, arg: str) -> None:
        """team_onboarding -- show sanitized onboarding export readiness."""
        self._print_claude_style_readiness(
            command="team-onboarding",
            feature="team_onboarding_report_readiness",
            status="onboarding_report_readiness",
            next_actions=["insights 30", "commands", "memory export"],
        )

    def do_desktop(self, arg: str) -> None:
        """desktop -- show desktop wrapper readiness."""
        self.do_remote_control(arg)

    def do_statusbar(self, arg: str) -> None:
        """statusbar -- show status-bar metadata and active flags."""
        dashboard = build_product_dashboard(self.orchestrator)
        session = self.orchestrator.sessions.get_session(self.session["id"])
        _print_json(
            {
                "status": "metadata_only",
                "mode": "session_ui_metadata",
                "active_flags": _dashboard_status_flags(dashboard["runtime"], session, workspace=self.workspace),
                "ui_preferences": session.get("metadata", {}).get("tui_preferences", {}),
                "visible_in_prompt": True,
                "raw_secret_values_included": False,
            }
        )

    def do_sb(self, arg: str) -> None:
        """sb -- alias for statusbar."""
        self.do_statusbar(arg)

    def do_statusline(self, arg: str) -> None:
        """statusline -- alias for statusbar."""
        self.do_statusbar(arg)

    def do_footer(self, arg: str) -> None:
        """footer -- show footer/status metadata."""
        self._print_ui_surface("footer")

    def do_indicator(self, arg: str) -> None:
        """indicator -- show active indicator metadata."""
        self._print_ui_surface("indicator")

    def do_details(self, arg: str) -> None:
        """details -- show safe runtime detail metadata."""
        dashboard = build_product_dashboard(self.orchestrator)
        _print_json(
            {
                "status": "metadata_only",
                "runtime": {
                    "audit_chain_ok": dashboard["runtime"]["audit_chain_ok"],
                    "pending_approvals": dashboard["runtime"]["pending_approvals"],
                    "sessions": dashboard["runtime"]["sessions"],
                    "recent_tasks": dashboard["runtime"]["recent_tasks"],
                    "model_providers": dashboard["runtime"]["model_providers"],
                },
                "auth_parity_status": dashboard["model_provider_auth_parity"]["status"],
                "live_gap_areas": [item["area"] for item in dashboard.get("live_gap_backlog", [])],
                "raw_audit_log_included": False,
                "raw_message_content_included": False,
                "raw_secret_values_included": False,
                "next_actions": ["dashboard", "capabilities", "debug"],
            }
        )

    def do_busy(self, arg: str) -> None:
        """busy [status|queue|steer|interrupt|pause|resume] -- inspect or control active work."""
        parts = shlex.split(arg)
        action = parts[0] if parts else "status"
        if action in {"status", "show"}:
            self._print_busy_status()
            return
        if action == "queue":
            self._print_queue(parts[1:])
            return
        if action == "steer":
            instruction = " ".join(parts[1:]).strip()
            if not instruction:
                self.do_steer("")
                return
            self.do_steer(instruction)
            return
        if action in {"interrupt", "cancel", "stop"}:
            self._busy_task_control(parts[1:], control="cancel")
            return
        if action == "pause":
            self._busy_task_control(parts[1:], control="pause")
            return
        if action == "resume":
            self._busy_task_control(parts[1:], control="resume")
            return
        print("usage: busy [status|queue|steer <instruction>|interrupt [task_id] [reason]|pause [task_id] [reason]|resume [task_id]]")

    def _print_busy_status(self) -> None:
        dashboard = build_product_dashboard(self.orchestrator)
        runtime = dashboard["runtime"]
        active_rows = dashboard.get("active_work_tasks", [])
        _print_json(
            {
                "status": "active_work_status",
                "busy": bool(runtime.get("active_work_count")),
                "active_task_count": runtime.get("active_work_count", 0),
                "running_task_count": runtime.get("running_task_count", 0),
                "waiting_task_count": runtime.get("waiting_task_count", 0),
                "paused_task_count": runtime.get("paused_task_count", 0),
                "active_task_ids": [_short_id(row.get("id", "")) for row in active_rows[:8]],
                "raw_task_requests_included": False,
                "next_actions": ["busy queue", "busy interrupt <task_id>", "approvals", "events <task_id>"],
            }
        )

    def _busy_task_control(self, parts: list[str], *, control: str) -> None:
        task_id = parts[0] if parts else _default_busy_task_id(self.orchestrator, session_id=self.session.get("id"))
        reason = " ".join(parts[1:]) if parts else ""
        if not task_id:
            print("no active task")
            return
        try:
            task = self.orchestrator.status(task_id)
            task_session_id = task.get("session_id") or self.session["id"]
            if control == "cancel":
                result = self.orchestrator.cancel_task(task_id, session_id=task_session_id, actor="tui-user", reason=reason or "busy interrupt")
                status = "busy_interrupt_applied"
            elif control == "pause":
                result = self.orchestrator.pause_task(task_id, session_id=task_session_id, actor="tui-user", reason=reason or "busy pause")
                status = "busy_pause_applied"
            else:
                result = self.orchestrator.resume_task(task_id, session_id=task_session_id)
                status = "busy_resume_requested"
        except KeyError:
            print(f"task not found: {task_id}")
            return
        except PermissionError as exc:
            print(f"busy {control} blocked: {exc}")
            return
        _print_json(
            {
                "status": status,
                "task_id": task_id,
                "control": control,
                "raw_task_request_included": False,
                "next_actions": ["busy queue", f"events {task_id}", f"timeline {task_id}"],
            }
        )
        _print_task_result(result)

    def do_theme(self, arg: str) -> None:
        """theme -- show UI theme metadata."""
        self._print_ui_preference("theme", arg)

    def do_skin(self, arg: str) -> None:
        """skin -- show UI skin metadata."""
        self._print_ui_preference("skin", arg)

    def do_color(self, arg: str) -> None:
        """color -- show UI color metadata."""
        self._print_ui_preference("color", arg)

    def do_verbose(self, arg: str) -> None:
        """verbose -- show verbosity metadata."""
        self._print_ui_preference("verbose", arg)

    def do_steer(self, arg: str) -> None:
        """steer [instruction] -- store a redacted session steering receipt."""
        requested = arg.strip()
        if requested:
            steering = {
                "active": True,
                "instruction_sha256": hashlib.sha256(requested.encode("utf-8")).hexdigest(),
                "instruction_character_count": len(requested),
                "updated_at": now_utc(),
                "raw_instruction_stored": False,
            }
            self.session = self.orchestrator.sessions.update_metadata(
                self.session["id"],
                steering,
                namespace="tui_steering",
            )
        else:
            steering = self.orchestrator.sessions.get_session(self.session["id"]).get("metadata", {}).get("tui_steering", {})
        _print_json(
            {
                "status": "steering_updated" if requested else "steering_status",
                "mode": "session_metadata_only",
                "steer_mutation": "session_metadata_receipt",
                "requested_instruction_character_count": len(requested),
                "instruction_captured": bool(requested),
                "steering_active": bool(steering.get("active")),
                "instruction_sha256": steering.get("instruction_sha256"),
                "raw_instruction_included": False,
                "raw_instruction_stored": False,
                "active_session_id": self.session.get("id"),
                "next_actions": ["prompt", "personality", "session set-personality <name>", "context"],
            }
        )

    def do_sethome(self, arg: str) -> None:
        """sethome -- show guarded home-channel readiness."""
        _print_json(
            {
                "status": "not_enabled",
                "mode": "metadata_only",
                "home_channel_readiness": "tracked_gap",
                "active_session_id": self.session.get("id"),
                "workspace": str(self.workspace),
                "mutation": "disabled_by_command",
                "next_actions": ["session rename <title>", "web-setup", "remote-control pair"],
                "detail": "Home workspace/channel mutation needs explicit profile storage, rollback receipts, and channel identity checks before it can change defaults.",
            }
        )

    def _print_ui_surface(self, name: str) -> None:
        dashboard = build_product_dashboard(self.orchestrator)
        _print_json(
            {
                "status": "metadata_only",
                "surface": name,
                "active_flags": _dashboard_status_flags(dashboard["runtime"], self.session, workspace=self.workspace),
                "raw_message_content_included": False,
                "raw_secret_values_included": False,
            }
        )

    def _print_ui_preference(self, name: str, arg: str) -> None:
        requested = arg.strip() or ("enabled" if name == "verbose" else None)
        session = self.orchestrator.sessions.get_session(self.session["id"])
        preferences = dict(session.get("metadata", {}).get("tui_preferences") or {})
        if requested is not None:
            preferences[name] = _clean_session_preference_value(requested)
            self.session = self.orchestrator.sessions.update_metadata(
                self.session["id"],
                preferences,
                namespace="tui_preferences",
            )
        current_preferences = self.session.get("metadata", {}).get("tui_preferences", {})
        _print_json(
            {
                "status": "ui_preference_updated" if requested is not None else "ui_preference_status",
                "mode": "session_ui_metadata",
                "preference": name,
                "requested_value": _safe_display_value(requested),
                "current_value": current_preferences.get(name),
                "ui_preferences": current_preferences,
                "current_theme": "aegis-shield",
                "persisted": requested is not None,
                "raw_secret_values_included": False,
                "detail": "UI preferences are stored as active-session metadata and do not mutate global config.",
            }
        )

    def do_plugin(self, arg: str) -> None:
        """plugin -- alias for plugins."""
        self.do_plugins(arg)

    def do_allowed_tools(self, arg: str) -> None:
        """allowed_tools -- show policy-visible tool inventory."""
        _print_json(
            {
                "status": "metadata_only",
                "tools": [
                    {
                        "name": tool.get("name"),
                        "permission": tool.get("permission"),
                        "risk_level": tool.get("risk_level"),
                        "approval_required": tool.get("approval_required"),
                    }
                    for tool in self.orchestrator.tool_catalog.list()
                ],
                "raw_secret_values_included": False,
            }
        )

    def do_bashes(self, arg: str) -> None:
        """bashes [list|start|input|resize|stop|logs] -- manage governed background processes."""
        try:
            parts = shlex.split(arg)
        except ValueError as exc:
            _print_json({"ok": False, "error": str(exc)})
            return
        command = parts[0] if parts else "list"
        rest = parts[1:] if parts else []
        try:
            if command in {"list", "status"}:
                _print_json(self.orchestrator.processes.status())
                return
            if command == "start":
                approved = False
                actor = "operator"
                label = ""
                pty = False
                rows = 24
                cols = 80
                argv: list[str] = []
                index = 0
                while index < len(rest):
                    part = rest[index]
                    if part == "--":
                        argv = rest[index + 1 :]
                        break
                    if part == "--approved":
                        approved = True
                        index += 1
                        continue
                    if part == "--actor":
                        actor = _next_required(rest, index, "--actor")
                        index += 2
                        continue
                    if part == "--label":
                        label = _next_required(rest, index, "--label")
                        index += 2
                        continue
                    if part == "--pty":
                        pty = True
                        index += 1
                        continue
                    if part == "--rows":
                        rows = int(_next_required(rest, index, "--rows"))
                        index += 2
                        continue
                    if part == "--cols":
                        cols = int(_next_required(rest, index, "--cols"))
                        index += 2
                        continue
                    argv = rest[index:]
                    break
                _print_json(self.orchestrator.processes.start(argv, approved=approved, actor=actor, label=label, pty=pty, rows=rows, cols=cols))
                return
            if command == "input":
                if len(rest) < 2:
                    _print_json({"ok": False, "error": "usage: bashes input <process-id> <text> [--no-newline]"})
                    return
                process_id = rest[0]
                append_newline = "--no-newline" not in rest[2:]
                text_parts = [part for part in rest[1:] if part != "--no-newline"]
                _print_json(self.orchestrator.processes.send_input(process_id, " ".join(text_parts), append_newline=append_newline))
                return
            if command == "resize":
                if not rest:
                    _print_json({"ok": False, "error": "usage: bashes resize <process-id> --rows N --cols N"})
                    return
                process_id = rest[0]
                rows = 24
                cols = 80
                index = 1
                while index < len(rest):
                    if rest[index] == "--rows":
                        rows = int(_next_required(rest, index, "--rows"))
                        index += 2
                        continue
                    if rest[index] == "--cols":
                        cols = int(_next_required(rest, index, "--cols"))
                        index += 2
                        continue
                    index += 1
                _print_json(self.orchestrator.processes.resize(process_id, rows=rows, cols=cols))
                return
            if command == "stop":
                if not rest:
                    _print_json({"ok": False, "error": "usage: bashes stop <process-id>"})
                    return
                _print_json(self.orchestrator.processes.stop(rest[0]))
                return
            if command == "logs":
                if not rest:
                    _print_json({"ok": False, "error": "usage: bashes logs <process-id> [--max-bytes N]"})
                    return
                max_bytes = 4096
                if len(rest) >= 3 and rest[1] == "--max-bytes":
                    max_bytes = int(rest[2])
                _print_json(self.orchestrator.processes.logs(rest[0], max_bytes=max_bytes))
                return
        except Exception as exc:  # noqa: BLE001 - TUI command should report structured local errors.
            _print_json({"ok": False, "error": str(exc), "raw_secret_values_included": False})
            return
        _print_json({"ok": False, "error": "usage: bashes [list|start|input|resize|stop|logs]", "raw_secret_values_included": False})

    def do_processes(self, arg: str) -> None:
        """processes -- alias for bashes."""
        self.do_bashes(arg)

    def do_process(self, arg: str) -> None:
        """process -- alias for bashes."""
        self.do_bashes(arg)

    def do_pr_comments(self, arg: str) -> None:
        """pr_comments -- show pull request comment integration readiness."""
        github = next((row for row in self.orchestrator.connectors.status() if row.get("name") == "github"), None)
        _print_json(
            {
                "status": "connector_surface_ready" if github else "not_configured",
                "github_connector": github,
                "telemetry_sent": False,
                "live_gap": "Live PR provider writes still require a configured governed GitHub credential, repository scope, approval, and receipt redaction.",
                "read_surface": "github_pr operation=comments supports mock comments and allowlisted GitHub-compatible PR comments JSON endpoints.",
                "autofix_surface": "github_pr operation=autofix_plan converts review comments into local, human-reviewed patch plans without provider writes.",
                "autofix_patch_surface": "github_pr operation=autofix_apply applies an approved operator-supplied unified diff linked to review action items and still performs no provider writes.",
                "autofix_response_surface": "github_pr operation=autofix_response posts an approved redacted autofix response through the same governed comment connector when live writes are configured.",
                "next_actions": [
                    "connectors",
                    "tools run github_pr '{\"operation\":\"comments\"}' --approved",
                    "tools run github_pr '{\"operation\":\"autofix_plan\"}' --approved",
                    "tools run github_pr '{\"operation\":\"autofix_apply\",\"action_items\":[{\"path\":\"src/example.py\",\"comment_id\":101}],\"patch\":\"...\"}' --approved",
                    "tools run github_pr '{\"operation\":\"autofix_response\",\"action_items\":[]}' --approved",
                    "tools run github_pr '{\"operation\":\"comments\",\"provider_url\":\"https://api.github.com/repos/OWNER/REPO/pulls/NUMBER/comments\"}' --approved",
                ],
            }
        )

    def do_autofix_pr(self, arg: str) -> None:
        """autofix_pr [prompt] -- show governed PR autofix workflow."""
        prompt = arg.strip()
        _print_json(
            {
                "status": "autofix_pr_readiness",
                "cloud_session_started": False,
                "prompt_received": bool(prompt),
                "prompt_chars": len(prompt),
                "raw_prompt_included": False,
                "autofix_plan_available": True,
                "autofix_apply_requires_approved_patch": True,
                "next_actions": [
                    "pr_comments",
                    "tools run github_pr '{\"operation\":\"comments\"}' --approved",
                    "tools run github_pr '{\"operation\":\"autofix_plan\"}' --approved",
                    "tools run github_pr '{\"operation\":\"autofix_apply\",\"action_items\":[],\"patch\":\"...\"}' --approved",
                ],
                "raw_secret_values_included": False,
            }
        )

    def do_reload_plugins(self, arg: str) -> None:
        """reload_plugins -- reload private local plugin inventory."""
        self.do_plugins("reload")

    def do_reload_skills(self, arg: str) -> None:
        """reload_skills -- show governed skill inventory refresh readiness."""
        _print_json(
            {
                "ok": True,
                "mode": "skill_inventory_metadata",
                "skills": self.orchestrator.skills.list_public(),
                "raw_secret_values_included": False,
            }
        )

    def do_reload(self, arg: str) -> None:
        """reload -- show combined local extension refresh metadata."""
        _print_json(
            {
                "ok": True,
                "mode": "metadata_only",
                "plugins": _plugin_inventory_payload(self.orchestrator),
                "mcp_servers": self.orchestrator.mcp.list_servers(),
                "skills": self.orchestrator.skills.list_public(),
                "raw_secret_values_included": False,
            }
        )

    def do_hooks(self, arg: str) -> None:
        """hooks list|add|enable|disable|remove|run -- manage governed local lifecycle hooks."""
        try:
            parts = shlex.split(arg) if arg else []
        except ValueError as exc:
            print(f"invalid hook command: {exc}")
            return
        manager = self.orchestrator.hooks
        try:
            if not parts or parts[0] == "list":
                _print_json(_hook_inventory_payload(self.orchestrator))
                return
            if parts[0] == "add":
                spec = _parse_hook_add_args(parts[1:])
                _print_json({"hook": manager.register_hook(**spec)})
                return
            if parts[0] == "enable" and len(parts) >= 2:
                _print_json({"hook": manager.set_enabled(parts[1], True)})
                return
            if parts[0] == "disable" and len(parts) >= 2:
                _print_json({"hook": manager.set_enabled(parts[1], False)})
                return
            if parts[0] == "remove" and len(parts) >= 2:
                _print_json({"hook": manager.remove_hook(parts[1]), "removed": True})
                return
            if parts[0] == "run" and len(parts) >= 2:
                event, approved, context = _parse_hook_run_args(parts[1:])
                _print_json(manager.run_event(event, approved=approved, context=context))
                return
        except (KeyError, PermissionError, ValueError) as exc:
            print(f"hook error: {exc}")
            return
        print("usage: hooks list | hooks add <event> [--id id] [--enabled] [--no-approval-required] -- <command...> | hooks enable|disable|remove <id> | hooks run <event> [--approved] [--context-json JSON]")

    def do_update(self, arg: str) -> None:
        """update -- show guarded update readiness."""
        _print_json({"status": "operator_action_required", "detail": "Package self-update is not automatic; review git changes and run the installer/update command explicitly."})

    def do_release_notes(self, arg: str) -> None:
        """release_notes -- show local release/version metadata."""
        _print_json(
            {
                "status": "local_release_metadata",
                "package": "Aegis-Agent",
                "release_channel": "local_git",
                "changelog_file": "README.md",
                "raw_git_log_included": False,
                "next_actions": ["git log --oneline -5", "git status --short", "update"],
            }
        )

    def do_upgrade(self, arg: str) -> None:
        """upgrade -- show subscription/plan upgrade boundaries."""
        _print_json(
            {
                "status": "operator_action_required",
                "account_upgrade_started": False,
                "detail": "Aegis does not open provider billing or subscription pages from the TUI. Use provider-owned account portals and then run the matching models auth login/doctor command.",
                "next_actions": ["models auth targets", "models auth doctor", "login <provider> subscription"],
                "raw_secret_values_included": False,
            }
        )

    def do_restart(self, arg: str) -> None:
        """restart -- show guarded restart readiness."""
        _print_json({"status": "operator_action_required", "detail": "No daemon restart is running from the TUI; restart your local service manager or dev server explicitly."})

    def do_redraw(self, arg: str) -> None:
        """redraw -- refresh prompt metadata and render the compact home surface."""
        self._refresh_prompt()
        print(self._render_home())

    def do_stop(self, arg: str) -> None:
        """stop [task_id] -- alias for cancel."""
        self.do_cancel(arg)

    def do_retry(self, arg: str) -> None:
        """retry -- resubmit the latest user message in the active session."""
        history = self.orchestrator.sessions.history(self.session["id"], limit=1000)
        last_user = next((message for message in reversed(history) if message.get("role") == "user" and str(message.get("content") or "").strip()), None)
        if last_user is None:
            _print_json({"status": "no_user_message", "session_id": self.session["id"], "raw_message_content_included": False})
            return
        result = self.orchestrator.submit_task(str(last_user["content"]), session_id=self.session["id"])
        self.last_task_id = result["id"]
        _print_json(
            {
                "status": "retry_submitted",
                "session_id": self.session["id"],
                "retry_of_message_id": last_user.get("id"),
                "task_id": result["id"],
                "raw_message_content_included": False,
            }
        )
        _print_task_result(result)

    def do_undo(self, arg: str) -> None:
        """undo -- remove the latest user/assistant exchange from the active session history."""
        result = self.orchestrator.sessions.undo_last_exchange(self.session["id"])
        self.last_task_id = self._latest_session_task_id()
        _print_json(result)

    def do_handoff(self, arg: str) -> None:
        """handoff [platform] -- show guarded cross-platform handoff readiness."""
        platform = arg.strip()
        _print_json(
            {
                "status": "handoff_blocked_preflight",
                "platform": platform or None,
                "active_session_id": self.session.get("id"),
                "active_session_title": self.session.get("title"),
                "raw_messages_included": False,
                "detail": "Cross-platform handoff needs a configured home channel and gateway delivery confirmation before Aegis will replay session context outside the local terminal.",
                "next_actions": ["platforms", "sethome", "channel render <channel> <text>", "remote-control pair"],
            }
        )

    def do_init(self, arg: str) -> None:
        """init -- show project initialization status."""
        _print_json(
            {
                "workspace": str(self.workspace),
                "agents_md": (self.workspace / "AGENTS.md").exists(),
                "data_dir": str(self.orchestrator.config.data_dir),
                "status": "initialized" if self.orchestrator.config.data_dir.exists() else "data_dir_missing",
            }
        )

    def do_personality(self, arg: str) -> None:
        """personality [name] -- show or set active session personality."""
        if arg.strip():
            self.do_session(f"set-personality {arg.strip()}")
            return
        _print_json({"session_id": self.session.get("id"), "personality": self.session.get("personality")})

    def do_vim(self, arg: str) -> None:
        """vim -- toggle vim-mode readiness metadata for the current TUI session."""
        self.vim_mode_enabled = not self.vim_mode_enabled
        _print_json(
            {
                "status": "enabled" if self.vim_mode_enabled else "disabled",
                "mode": "metadata_only",
                "detail": "Aegis records vim-mode preference for this TUI session; full modal readline editing is still terminal-backend work.",
            }
        )

    def do_diff(self, arg: str) -> None:
        """diff -- show guarded diff workflow status."""
        _print_json({"status": "operator_action_required", "detail": "Use git diff or an approved shell tool run; Aegis does not read arbitrary workspace diffs from this command without an explicit operator action."})

    def do_review(self, arg: str) -> None:
        """review -- show review workflow surfaces."""
        self.do_repair("readiness")

    def do_simplify(self, arg: str) -> None:
        """simplify [focus] -- show governed simplify workflow readiness."""
        focus = arg.strip()
        _print_json(
            {
                "status": "simplify_readiness",
                "auto_mutation_enabled": False,
                "focus_received": bool(focus),
                "focus_chars": len(focus),
                "raw_focus_included": False,
                "review_agents_spawned": 0,
                "next_actions": ["review", "security-review", "repair readiness", "batch <instruction>"],
                "raw_secret_values_included": False,
            }
        )

    def do_security_review(self, arg: str) -> None:
        """security_review -- show security review surfaces."""
        self.do_security("profile")

    def do_ultrareview(self, arg: str) -> None:
        """ultrareview [PR] -- show governed deep review readiness."""
        _print_json(
            {
                "status": "ultrareview_readiness",
                "cloud_review_session_started": False,
                "local_review_surfaces": ["review", "security-review", "pr_comments", "repair readiness"],
                "pr_argument_received": bool(arg.strip()),
                "raw_argument_included": False,
                "next_actions": ["review", "security-review", "pr_comments"],
                "raw_secret_values_included": False,
            }
        )

    def do_platforms(self, arg: str) -> None:
        """platforms -- show connector and channel platform status."""
        _print_json(
            {
                "connectors": self.orchestrator.connectors.status(),
                "channels": self.orchestrator.channels.list_channels(),
                "remote_control": {"status": "local_only", "command": "remote-control"},
            }
        )

    def do_voice(self, arg: str) -> None:
        """voice -- show guarded voice-mode status."""
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        print(
            _boxed_lines(
                "Voice",
                [
                    "Voice mode is not enabled in this dependency-light runtime.",
                    "A secure implementation needs explicit microphone capture consent, local artifact sandboxing, provider selection, and redacted audio receipts.",
                ],
                width,
            )
        )

    def do_radio(self, arg: str) -> None:
        """radio -- show external media launch boundary."""
        _print_json(
            {
                "status": "operator_action_required",
                "external_media_opened": False,
                "detail": "Aegis does not open external media streams from the TUI. Use a browser explicitly if you want ambient audio.",
                "raw_secret_values_included": False,
            }
        )

    def do_stickers(self, arg: str) -> None:
        """stickers -- show non-runtime merchandise boundary."""
        _print_json(
            {
                "status": "not_applicable",
                "detail": "Sticker ordering is outside the local governed runtime.",
                "external_checkout_opened": False,
                "raw_secret_values_included": False,
            }
        )

    def do_plugins(self, arg: str) -> None:
        """plugins list|install|enable|disable|remove|reload|marketplace|updates|fetch-manifest|fetch-bundle|install-bundle|install-marketplace|update-marketplace|prepare-update|apply-prepared-update -- manage governed local plugins."""
        try:
            parts = shlex.split(arg) if arg else []
        except ValueError as exc:
            print(f"invalid plugin command: {exc}")
            return
        manager = self.orchestrator.plugins
        try:
            if not parts or parts[0] == "list":
                _print_json(_plugin_inventory_payload(self.orchestrator))
                return
            if parts[0] == "install" and len(parts) >= 2:
                _print_json(
                    {
                        "plugin": manager.install_plugin(
                            parts[1],
                            enable="--enable" in parts[2:],
                            unsigned_local="--unsigned-local" in parts[2:],
                        )
                    }
                )
                return
            if parts[0] == "enable" and len(parts) >= 2:
                _print_json(manager.enable_plugin(parts[1]))
                return
            if parts[0] == "disable" and len(parts) >= 2:
                _print_json(manager.disable_plugin(parts[1]))
                return
            if parts[0] == "remove" and len(parts) >= 2:
                _print_json(manager.remove_plugin(parts[1]))
                return
            if parts[0] == "reload":
                _print_json({"ok": True, "mode": "private_plugin_inventory", **_plugin_inventory_payload(self.orchestrator)})
                return
            if parts[0] == "marketplace":
                _print_json(
                    manager.marketplace(
                        query=_option_value(parts, "--query") or _option_value(parts, "-q") or "",
                        catalog_path=_option_value(parts, "--catalog-path"),
                    )
                )
                return
            if parts[0] == "updates":
                _print_json(manager.update_plan(catalog_path=_option_value(parts, "--catalog-path")))
                return
            if parts[0] == "fetch-manifest" and len(parts) >= 2:
                _print_json(
                    manager.fetch_marketplace_manifest(
                        parts[1],
                        catalog_path=_option_value(parts, "--catalog-path"),
                        allowlist=self.orchestrator.config.network_allowlist,
                    )
                )
                return
            if parts[0] == "fetch-bundle" and len(parts) >= 2:
                _print_json(
                    manager.fetch_marketplace_bundle(
                        parts[1],
                        catalog_path=_option_value(parts, "--catalog-path"),
                        allowlist=self.orchestrator.config.network_allowlist,
                        key_name=_option_value(parts, "--key-name") or DEFAULT_SKILL_SIGNING_KEY,
                    )
                )
                return
            if parts[0] == "install-bundle" and len(parts) >= 2:
                _print_json(
                    manager.install_marketplace_bundle(
                        parts[1],
                        catalog_path=_option_value(parts, "--catalog-path"),
                        allowlist=self.orchestrator.config.network_allowlist,
                        key_name=_option_value(parts, "--key-name") or DEFAULT_SKILL_SIGNING_KEY,
                        enable="--enable" in parts[2:],
                    )
                )
                return
            if parts[0] == "install-marketplace" and len(parts) >= 2:
                _print_json(
                    manager.install_marketplace_plugin(
                        parts[1],
                        catalog_path=_option_value(parts, "--catalog-path"),
                        allowlist=self.orchestrator.config.network_allowlist,
                        enable="--enable" in parts[2:],
                    )
                )
                return
            if parts[0] == "update-marketplace" and len(parts) >= 2:
                if "--enable" in parts[2:] and "--disable" in parts[2:]:
                    raise ValueError("use either --enable or --disable, not both")
                _print_json(
                    manager.update_marketplace_plugin(
                        parts[1],
                        approved="--approved" in parts[2:],
                        catalog_path=_option_value(parts, "--catalog-path"),
                        allowlist=self.orchestrator.config.network_allowlist,
                        enable=True if "--enable" in parts[2:] else False if "--disable" in parts[2:] else None,
                        force="--force" in parts[2:],
                    )
                )
                return
            if parts[0] == "prepare-update" and len(parts) >= 2:
                _print_json(
                    manager.prepare_marketplace_update(
                        parts[1],
                        catalog_path=_option_value(parts, "--catalog-path"),
                        allowlist=self.orchestrator.config.network_allowlist,
                        force="--force" in parts[2:],
                    )
                )
                return
            if parts[0] == "apply-prepared-update" and len(parts) >= 2:
                if "--enable" in parts[2:] and "--disable" in parts[2:]:
                    raise ValueError("use either --enable or --disable, not both")
                _print_json(
                    manager.apply_prepared_marketplace_update(
                        parts[1],
                        approved="--approved" in parts[2:],
                        enable=True if "--enable" in parts[2:] else False if "--disable" in parts[2:] else None,
                    )
                )
                return
        except (KeyError, PermissionError, ValueError) as exc:
            print(f"plugin error: {exc}")
            return
        print("usage: plugins list | plugins install <plugin.json> [--enable] [--unsigned-local] | plugins enable|disable|remove <plugin_id> | plugins reload | plugins marketplace [--query q] [--catalog-path file] | plugins updates [--catalog-path file] | plugins fetch-manifest <plugin_id> [--catalog-path file] | plugins fetch-bundle <plugin_id> [--catalog-path file] [--key-name name] | plugins install-bundle <plugin_id> [--catalog-path file] [--key-name name] [--enable] | plugins install-marketplace <plugin_id> [--catalog-path file] [--enable] | plugins update-marketplace <plugin_id> --approved [--catalog-path file] [--enable|--disable] [--force] | plugins prepare-update <plugin_id> [--catalog-path file] [--force] | plugins apply-prepared-update <candidate_id> --approved [--enable|--disable]")

    def do_toolsets(self, arg: str) -> None:
        """toolsets -- summarize governed tools by permission and risk."""
        rows: dict[str, dict[str, Any]] = {}
        for tool in [*self.orchestrator.tool_catalog.list(), *self.orchestrator.mcp.virtual_tool_specs()]:
            key = f"{tool.get('permission')}:{tool.get('risk_level')}"
            row = rows.setdefault(key, {"key": key, "permission": tool.get("permission"), "risk_level": tool.get("risk_level"), "tools": []})
            row["tools"].append(tool.get("name"))
        _print_json({"toolsets": list(rows.values())})

    def do_cron(self, arg: str) -> None:
        """cron [subcommand] -- alias for schedules."""
        self.do_schedule(arg or "due")

    def do_reload_mcp(self, arg: str) -> None:
        """reload_mcp -- reload governed MCP registry metadata."""
        _print_json({"ok": True, "mode": "one_shot_stdio_registry", "servers": self.orchestrator.mcp.list_servers(), "virtual_tools": self.orchestrator.mcp.virtual_tools()})

    def do_help(self, arg: str) -> None:
        """help -- show command reference."""
        print(_command_reference())

    def do_menu(self, arg: str) -> None:
        """menu [group] -- show the grouped command menu or one nested group."""
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        dashboard = build_product_dashboard(self.orchestrator)
        group = arg.strip().lower() or None
        print(_command_menu(width, _dashboard_status_flags(dashboard["runtime"], self.session, workspace=self.workspace), group=group))

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
            if not command or command == "?":
                print(self._render_slash_palette(""))
                return
            name = command.split(maxsplit=1)[0]
            if name == "quit":
                return self.do_quit("")
            canonical = SLASH_COMMAND_ALIASES.get(name, name.replace("-", "_"))
            if hasattr(self, f"do_{canonical}"):
                rest = command[len(name) :].strip()
                return bool(self.onecmd(f"{canonical} {rest}".strip()))
            rest = command[len(name) :].strip()
            if self._dispatch_quick_slash(name, rest):
                return
            if self._dispatch_skill_slash(name, rest):
                return
            matches = _slash_matches(name)
            if matches:
                print(self._render_slash_palette(name))
                return
            print(f"unknown slash command: /{name}")
            print(self._render_slash_palette(name))
            return
        self.do_submit(stripped)

    def _latest_session_task_id(self) -> str | None:
        for message in reversed(self.orchestrator.sessions.history(self.session["id"], limit=1000)):
            metadata = message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
            task_id = metadata.get("task_id") if isinstance(metadata, dict) else None
            if isinstance(task_id, str) and task_id:
                return task_id
        return None

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

    def _render_home(self) -> str:
        dashboard = build_product_dashboard(self.orchestrator)
        runtime = dashboard["runtime"]
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        return "\n".join(
            [
                _aegis_logo(width, self._next_shield_frame(), compact=True),
                _section(
                    "Live Flags",
                    _dashboard_status_flags(runtime, self.session, workspace=self.workspace),
                    width,
                ),
                _section(
                    "Start",
                    [
                        "Type a plain request to submit a governed task.",
                        "Type / and press Enter for the command palette; type /mem or /app to filter options.",
                        "Use menu operate, menu govern, menu build, or menu explore for nested command groups.",
                    ],
                    width,
                ),
            ]
        )

    def _render_slash_palette(self, prefix: str) -> str:
        dashboard = build_product_dashboard(self.orchestrator)
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        flags = _dashboard_status_flags(dashboard["runtime"], self.session, workspace=self.workspace)
        return _slash_palette(
            width,
            prefix=prefix,
            status_flags=flags,
            quick_matches=self._dynamic_quick_palette_matches(prefix),
            dynamic_matches=self._dynamic_skill_palette_matches(prefix),
        )

    def _quick_slash_commands(self) -> dict[str, Any]:
        commands: dict[str, Any] = {}
        reserved = {command.replace("_", "-") for command in TOP_LEVEL_COMMANDS}
        reserved.update(SLASH_COMMAND_ALIASES.keys())
        reserved.update(self._skill_slash_commands().keys())
        for label, command in self.orchestrator.config.quick_commands.items():
            normalized = label.strip().lower()
            if not normalized or normalized in reserved:
                continue
            commands[normalized] = command
        return dict(sorted(commands.items()))

    def _complete_quick_slash_labels(self, prefix: str) -> list[str]:
        normalized = prefix.strip().lstrip("/").lower()
        labels: list[str] = []
        for label in self._quick_slash_commands():
            if not normalized or _fuzzy_match(normalized, label):
                labels.append(f"/{label}")
        return labels

    def _dynamic_quick_palette_matches(self, prefix: str) -> list[tuple[str, str]]:
        normalized = prefix.strip().lstrip("/").lower()
        rows: list[tuple[str, str]] = []
        for label, command in self._quick_slash_commands().items():
            if command.kind == "alias":
                detail = f"quick alias - {command.target}"
                haystack = " ".join((label, detail))
            else:
                detail = "quick exec - approval gated"
                haystack = " ".join((label, detail, command.command))
            if normalized and not _fuzzy_match(normalized, haystack):
                continue
            rows.append((label, detail))
        return sorted(rows, key=lambda row: (0 if row[0].startswith(normalized) else 1, row[0]))[:6]

    def _dispatch_quick_slash(self, command_name: str, arg: str) -> bool:
        normalized = command_name.lower()
        quick_command = self._quick_slash_commands().get(normalized)
        if quick_command is None:
            return False
        if normalized in self._quick_dispatch_stack:
            print(f"quick command recursion blocked: /{normalized}")
            return True
        if quick_command.kind == "alias":
            target = quick_command.target.strip()
            if not target.startswith("/"):
                print(f"quick command invalid alias target: /{normalized}")
                return True
            self._quick_dispatch_stack.append(normalized)
            try:
                self.onecmd(" ".join(part for part in (target, arg.strip()) if part))
            finally:
                self._quick_dispatch_stack.pop()
            return True
        if quick_command.kind == "exec":
            try:
                parts = shlex.split(arg)
            except ValueError as exc:
                print(f"quick command args invalid: {exc}")
                return True
            approved = "--approved" in parts
            extras = [part for part in parts if part != "--approved"]
            if extras:
                print("quick command exec only accepts --approved; edit config.toml to change the command")
                return True
            try:
                result = self.orchestrator.tools.execute("shell", {"command": quick_command.command}, approved=approved)
            except (PermissionError, ValueError, RuntimeError) as exc:
                print(f"quick command exec blocked: {exc}")
                return True
            _print_json(
                {
                    "status": "quick_command_executed",
                    "command": f"/{normalized}",
                    "kind": "exec",
                    "approved": approved,
                    "result": redact(result),
                    "raw_secret_values_included": False,
                }
            )
            return True
        print(f"quick command type unsupported: {quick_command.kind}")
        return True

    def _skill_slash_commands(self) -> dict[str, str]:
        commands: dict[str, str] = {}
        reserved = {command.replace("_", "-") for command in TOP_LEVEL_COMMANDS}
        reserved.update(SLASH_COMMAND_ALIASES.keys())
        for row in self.orchestrator.skills.list_public():
            if not row.get("enabled"):
                continue
            skill_id = str(row.get("id") or "")
            for label in _skill_slash_labels(skill_id):
                if not label or label in reserved:
                    continue
                commands.setdefault(label, skill_id)
        return dict(sorted(commands.items()))

    def _complete_skill_slash_labels(self, prefix: str) -> list[str]:
        normalized = prefix.strip().lstrip("/").lower()
        labels: list[str] = []
        for label in self._skill_slash_commands():
            if not normalized or _fuzzy_match(normalized, label):
                labels.append(f"/{label}")
        return labels

    def _dynamic_skill_palette_matches(self, prefix: str) -> list[tuple[str, str]]:
        normalized = prefix.strip().lstrip("/").lower()
        rows: list[tuple[str, str]] = []
        command_to_skill = self._skill_slash_commands()
        public = {str(row.get("id") or ""): row for row in self.orchestrator.skills.list_public()}
        for label, skill_id in command_to_skill.items():
            row = public.get(skill_id, {})
            haystack = " ".join([label, skill_id, str(row.get("name", "")), str(row.get("description", ""))])
            if normalized and not _fuzzy_match(normalized, haystack):
                continue
            detail = f"skill - {row.get('name') or skill_id}"
            rows.append((label, detail))
        return sorted(rows, key=lambda row: (0 if row[0].startswith(normalized) else 1, row[0]))[:6]

    def _dispatch_skill_slash(self, command_name: str, arg: str) -> bool:
        skill_id = self._skill_slash_commands().get(command_name.lower())
        if skill_id is None:
            return False
        try:
            inputs = _parse_skill_slash_inputs(self.orchestrator.skills.get(skill_id)[0].input_schema, arg)
            result = SkillRuntime(self.orchestrator.skills, self.orchestrator.connectors, self.orchestrator.audit_logger).invoke(skill_id, inputs)
        except (KeyError, PermissionError, ValueError, RuntimeError, TimeoutError) as exc:
            print(f"skill slash error: {exc}")
            return True
        _print_json(
            {
                "status": "skill_slash_invoked",
                "command": f"/{command_name}",
                "skill_id": skill_id,
                "inputs_schema_mode": "json_object_or_single_string_property",
                "result": redact(result),
                "raw_secret_values_included": False,
            }
        )
        return True

    def _render_dashboard(self) -> str:
        dashboard = build_product_dashboard(self.orchestrator)
        runtime = dashboard["runtime"]
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        lines = [
            _aegis_logo(width, self._next_shield_frame()),
            _banner(
                "Aegis Agent Control Plane",
                width,
                "governed local runtime :: evidence-first operations :: slash-command deck",
            ),
            _section(
                "Active Status Flags",
                _dashboard_status_flags(runtime, self.session, workspace=self.workspace),
                width,
            ),
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
                    ("active work", runtime.get("active_work_count", 0)),
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
                    f"{item['area']}: {item['status']} - gates {', '.join(item.get('verification_gates', [])[:3]) or 'none'} - hardened {', '.join(control.get('control', 'unknown') for control in item.get('implemented_hardening_controls', [])[:8]) or 'none'} - remaining {', '.join(item.get('remaining_depth_work', [])[:3]) or 'none'} - evals {', '.join(item.get('evaluation_scenarios', [])[:2]) or 'none'} - live adapters {', '.join(adapter.get('name', 'unknown') for adapter in item.get('implemented_live_adapters', [])[:3]) or 'none'} - backend adapters {', '.join(adapter.get('name', 'unknown') for adapter in item.get('implemented_backend_adapters', [])[:3]) or 'none'} - backend preflight {_backend_preflight_summary(item)}"
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

    def _next_shield_frame(self) -> int:
        frame = self._shield_frame_index
        self._shield_frame_index = (self._shield_frame_index + 1) % len(SHIELD_FRAMES)
        return frame

    def _refresh_prompt(self) -> None:
        pending = len(self.orchestrator.approvals.list(status="pending"))
        session_ref = _short_id(self.session.get("id", ""))
        model = str(self.session.get("model") or "alias/smart").replace(" ", "_")
        approval = "clear" if pending == 0 else f"wait{pending}"
        self.prompt = _paint_prompt(f"aegis[{session_ref}|{model}|{approval}]> ", "36;1")

    def _read_live_line(self) -> str | None:
        try:
            import select
            import termios
            import tty
        except ImportError:
            return input(_readline_prompt(self.prompt))

        fd = sys.stdin.fileno()
        old_attrs = termios.tcgetattr(fd)
        buffer = ""
        rendered_height = 0
        history = _read_tui_history_lines(self.history_path)
        history_index = len(history)

        def redraw() -> None:
            nonlocal rendered_height
            width = min(max(shutil.get_terminal_size((100, 24)).columns, 60), 140)
            block, height = _live_input_block(self.prompt, buffer, width, workspace=self.workspace)
            if rendered_height:
                sys.stdout.write("\r")
                if rendered_height > 1:
                    sys.stdout.write(f"\033[{rendered_height - 1}A")
                sys.stdout.write("\033[J")
            sys.stdout.write(block)
            sys.stdout.flush()
            rendered_height = height

        try:
            tty.setcbreak(fd)
            redraw()
            while True:
                char = sys.stdin.read(1)
                if char in {"\r", "\n"}:
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    return buffer
                if char == "\x04":
                    if buffer:
                        continue
                    raise EOFError
                if char == "\x03":
                    buffer = ""
                    raise KeyboardInterrupt
                if char in {"\x7f", "\b"}:
                    buffer = buffer[:-1]
                    redraw()
                    continue
                if char == "\x15":
                    buffer = ""
                    redraw()
                    continue
                if char == "\x16":
                    buffer += "\n"
                    redraw()
                    continue
                if char == "\x1b":
                    sequence = ""
                    while select.select([sys.stdin], [], [], 0.001)[0]:
                        sequence += sys.stdin.read(1)
                        if len(sequence) >= 4:
                            break
                    if sequence in {"\r", "\n"}:
                        buffer += "\n"
                        redraw()
                    elif sequence == "[A" and history:
                        history_index = max(0, history_index - 1)
                        buffer = history[history_index]
                        redraw()
                    elif sequence == "[B" and history:
                        history_index = min(len(history), history_index + 1)
                        buffer = history[history_index] if history_index < len(history) else ""
                        redraw()
                    continue
                if char == "\t":
                    if buffer.startswith("/"):
                        completion_text, begidx, endidx = _live_completion_context(buffer)
                        completions = _complete_context_paths(completion_text, buffer, begidx, self.workspace)
                        if not completions:
                            completions = _complete_slash(completion_text, buffer, begidx, endidx)
                    else:
                        completion_text, begidx, endidx = _word_completion_context(buffer)
                        completions = _complete_context_paths(completion_text, buffer, begidx, self.workspace)
                        if not completions:
                            completion_text, begidx, endidx = buffer, 0, len(buffer)
                            completions = self.completenames(buffer)
                    if len(completions) == 1:
                        buffer = _apply_live_completion(buffer, completions[0], begidx, endidx)
                    elif completions:
                        sys.stdout.write("\n" + _inline_completion_line(completions, width=shutil.get_terminal_size((100, 24)).columns) + "\n")
                        rendered_height = 0
                    redraw()
                    continue
                if char.isprintable():
                    buffer += char
                    redraw()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)


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
    _print_approval_action_hints(approval)
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
    _print_approval_action_hints(approval)
    print()


def _print_approval_action_hints(approval: dict[str, Any]) -> None:
    hints = approval.get("action_hints", [])
    if not isinstance(hints, list) or not hints:
        return
    commands = [str(hint.get("command")) for hint in hints if isinstance(hint, dict) and hint.get("command")]
    phrases = []
    for hint in hints:
        if not isinstance(hint, dict):
            continue
        for phrase in hint.get("utterances", []):
            if isinstance(phrase, str) and phrase not in phrases:
                phrases.append(phrase)
    if commands:
        print(_paint(f"next     {'  OR  '.join(commands[:3])}", "33;1"))
    if phrases:
        print(textwrap.fill(f"say      {', '.join(phrases[:12])}", width=min(shutil.get_terminal_size((100, 24)).columns, 100), subsequent_indent="         "))


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


def _session_public_summary(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(session.get("id") or ""),
        "short_id": _short_id(session.get("id", "")),
        "title": str(redact(str(session.get("title") or ""))),
        "channel": str(redact(str(session.get("channel") or ""))),
        "status": str(session.get("status") or ""),
        "model": str(session.get("model") or ""),
        "personality": str(session.get("personality") or ""),
    }


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


def _hook_inventory_payload(orchestrator: Any) -> dict[str, Any]:
    return {
        "status": "governed_local_ready",
        "hooks": orchestrator.hooks.list_hooks(),
        "supported_events": list(HOOK_EVENTS),
        "allowed_executables": list(orchestrator.config.allowed_shell_commands),
        "raw_secret_values_included": False,
    }


def _plugin_inventory_payload(orchestrator: Any) -> dict[str, Any]:
    return {
        "status": "governed_local_ready",
        "plugins": orchestrator.plugins.list_plugins(),
        "skills": orchestrator.skills.list_public(),
        "mcp_servers": orchestrator.mcp.list_servers(),
        "hooks": orchestrator.hooks.list_hooks(),
        "raw_secret_values_included": False,
    }


def _parse_subagent_profile_options(parts: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {
        "role": None,
        "tool_allowlist": [],
        "max_parallel_cards": 1,
        "recursive_depth_limit": 0,
        "max_tool_calls": 0,
        "max_runtime_seconds": 0,
        "network_policy": "disabled",
        "workspace_scope": "current_workspace",
    }
    index = 0
    while index < len(parts):
        part = parts[index]
        if part == "--role":
            options["role"] = _next_required(parts, index, "--role")
            index += 2
            continue
        if part == "--tool":
            options["tool_allowlist"].append(_next_required(parts, index, "--tool"))
            index += 2
            continue
        if part == "--max-parallel-cards":
            options["max_parallel_cards"] = int(_next_required(parts, index, "--max-parallel-cards"))
            index += 2
            continue
        if part == "--recursive-depth-limit":
            options["recursive_depth_limit"] = int(_next_required(parts, index, "--recursive-depth-limit"))
            index += 2
            continue
        if part == "--max-tool-calls":
            options["max_tool_calls"] = int(_next_required(parts, index, "--max-tool-calls"))
            index += 2
            continue
        if part == "--max-runtime-seconds":
            options["max_runtime_seconds"] = int(_next_required(parts, index, "--max-runtime-seconds"))
            index += 2
            continue
        if part == "--network-policy":
            options["network_policy"] = _next_required(parts, index, "--network-policy")
            index += 2
            continue
        if part == "--workspace-scope":
            options["workspace_scope"] = _next_required(parts, index, "--workspace-scope")
            index += 2
            continue
        raise ValueError(f"unknown profile option: {part}")
    return options


def _parse_subagent_run_batch_options(parts: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {"approved": False, "limit": 5, "card_ids": []}
    index = 0
    while index < len(parts):
        part = parts[index]
        if part == "--approved":
            options["approved"] = True
            index += 1
            continue
        if part == "--limit":
            options["limit"] = int(_next_required(parts, index, "--limit"))
            index += 2
            continue
        if part == "--card-id":
            options["card_ids"].append(_next_required(parts, index, "--card-id"))
            index += 2
            continue
        options["card_ids"].append(part)
        index += 1
    return options


def _parse_hook_add_args(parts: list[str]) -> dict[str, Any]:
    if not parts:
        raise ValueError("hook event required")
    event = parts[0]
    if event not in HOOK_EVENTS:
        raise ValueError(f"unsupported hook event: {event}")
    hook_id: str | None = None
    enabled = False
    approval_required = True
    timeout_seconds = 10
    max_output_bytes = 4096
    command: list[str] = []
    index = 1
    while index < len(parts):
        part = parts[index]
        if part == "--":
            command = parts[index + 1 :]
            break
        if part == "--id":
            hook_id = _next_required(parts, index, "--id")
            index += 2
            continue
        if part == "--enabled":
            enabled = True
            index += 1
            continue
        if part == "--disabled":
            enabled = False
            index += 1
            continue
        if part == "--approval-required":
            approval_required = True
            index += 1
            continue
        if part == "--no-approval-required":
            approval_required = False
            index += 1
            continue
        if part == "--timeout":
            timeout_seconds = int(_next_required(parts, index, "--timeout"))
            index += 2
            continue
        if part == "--max-output-bytes":
            max_output_bytes = int(_next_required(parts, index, "--max-output-bytes"))
            index += 2
            continue
        command = parts[index:]
        break
    if not command:
        raise ValueError("hook command required")
    return {
        "event": event,
        "command": command,
        "hook_id": hook_id,
        "enabled": enabled,
        "approval_required": approval_required,
        "timeout_seconds": timeout_seconds,
        "max_output_bytes": max_output_bytes,
    }


def _parse_hook_run_args(parts: list[str]) -> tuple[str, bool, dict[str, Any]]:
    event = parts[0]
    if event not in HOOK_EVENTS:
        raise ValueError(f"unsupported hook event: {event}")
    approved = "--approved" in parts[1:]
    context: dict[str, Any] = {}
    if "--context-json" in parts:
        raw_context = _next_required(parts, parts.index("--context-json"), "--context-json")
        decoded = json.loads(raw_context)
        if not isinstance(decoded, dict):
            raise ValueError("--context-json must decode to a JSON object")
        context = decoded
    return event, approved, context


def _next_required(parts: list[str], index: int, flag: str) -> str:
    if index + 1 >= len(parts):
        raise ValueError(f"{flag} requires a value")
    return parts[index + 1]


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
            "task status|resume|pause|cancel|events|timeline|submit|list",
            "tasks [all|session <id>]  Recent active-session tasks, all tasks, or another session",
            "session                Show active session context",
            "session new|open       Create or switch conversation sessions",
            "session history|tasks  Show active session transcript or tasks",
            "recap                  Metadata-only active-session recap",
            "branch|fork|context    Branch readiness and context metadata",
            "copy|export|rename     Explicit copy/export and session rename surfaces",
            "paste|image <path>     Safe clipboard and image attachment boundaries",
            "save|prompt|steer      Explicit save, prompt, and steering readiness",
            "new|reset|clear        Session reset and screen controls",
            "add-dir <path>         Record extra working directory context",
            "history|title|topic|compress Active session transcript helpers",
            "checkpoint|rewind      Guarded rollback readiness aliases",
            "retry|undo             Resubmit or remove the latest session exchange",
            "background|bg|btw <req>  Submit a governed task from the deck",
            "fast [request]         Inspect fast route or submit a quick governed task",
            "goal|batch|queue|q|loop|proactive Goal, queue, and self-improvement readiness",
            "remote-control|rc      Local-first remote-control readiness",
            "handoff|remote-env|teleport|tp Guarded remote environment handoff readiness",
            "mobile|ios|android|desktop|app Mobile/desktop control-plane readiness",
            "evidence [task_id]     Show receipt and audit evidence",
            "timeline [task_id]     Show plan, receipt, and audit sequence",
            "events [task_id]       Show grouped run-event progress",
            "approvals              Pending approvals",
            "approval <id>          Inspect approval payload before action",
            "approve <id> [--admin] Approve a gated action",
            "deny <id> [--admin]    Deny a gated action",
            "permissions            Claude-style policy posture alias",
            "fewer-permission-prompts Permission prompt review readiness",
            "privacy-settings       Local privacy, redaction, and telemetry posture",
            "whoami|yolo            Identity posture and approval-bypass refusal",
            "security-review        Security review posture alias",
            "setup                 Guided local setup readiness",
            "doctor|debug|config|settings|heapdump Runtime diagnosis, safe debug, and config paths",
            "bug|feedback <summary> Capture a local-only bug report",
            "hooks list|add|run     Governed local lifecycle hooks",
            "dashboard              Runtime command deck",
            "menu                   Grouped command menu",
            "security               Security controls",
            "capabilities           Capability groups",
            "connectors             Connector health",
            "channels               Channel adapters",
            "pr_comments|autofix-pr Pull request comment and autofix readiness",
            "channel render <c> <t>  Render outbound channel payload",
            "channel receive <c> <t> Normalize inbound channel payload",
            "channel resolve-approval <event> <approval>",
            "channel send-chat-webhook <text> --approved",
            "channel events [limit]  Recent channel activity",
            "models|model           Model providers",
            "login|logout <provider> Model auth aliases",
            "setup|setup-bedrock|setup-vertex Guided setup and cloud identity setup bridges",
            "upgrade|extra-usage|passes Provider account and usage boundaries",
            "usage|stats|insights   Model usage and local analytics",
            "effort [level]         Guarded reasoning-effort status",
            "cost                   Model usage and estimated cost",
            "statusbar|statusline   UI status metadata",
            "theme|skin|color       UI preference metadata",
            "commands|keybindings|powerup|focus|ide Slash command and integration surfaces",
            "claude-api             Claude API migration and managed-agent reference readiness",
            "provider|usage         Model provider and usage aliases",
            "gquota [model]         Google Gemini Code Assist quota metadata",
            "models auth methods|targets|doctor|readiness-packet|verify-readiness-packet|login|logout <provider>",
            "tools                  Governed tool catalog",
            "toolsets               Group tools by permission and risk",
            "allowed-tools|bashes|processes Policy-visible tools and governed process controls",
            "tools list|run|enable|disable  Governed tool catalog and policy-owned preferences",
            "agents status|autonomy-preflight|profiles|delegate|handoff|review-packet|verify-packet|model-review|run|run-batch  Subagent coordination and runtime preflight",
            "skills hub|search|browse|inspect|install  Governed skills and virtual Skill Hub",
            "curator status|run|pin|archive  Local authored skill maintenance",
            "plugins list|install|enable|disable|remove|reload|marketplace|updates|fetch-manifest|fetch-bundle|install-bundle|install-marketplace|update-marketplace|prepare-update|apply-prepared-update",
            "plugin|reload|reload-plugins|reload-skills|reload_skills  Extension inventory aliases",
            "memory health|search|session-preview|create|update|merge|expire",
            "mcp list|register|call Governed MCP registry",
            "reload-mcp             Refresh governed one-shot MCP registry status",
            "repairs [status]       List self-repair proposals",
            "repair <id>            Inspect self-repair proposal evidence",
            "repair review|approve|reject <id>",
            "repair synthesis-prompt <id>",
            "repair synthesize-candidate <id> <json_file>",
            "repair review-candidate <id> <candidate_id> <approved|rejected>",
            "repair apply-candidate|rollback-candidate <id> <candidate_id>",
            "repair attempt <id> <outcome> [--candidate-id id] [--test-command cmd]",
            "schedules              Scheduled automations",
            "schedule create <n> <c> <task> [--context-from ref]",
            "schedule script <n> <c> -- <argv>",
            "schedule memory-review-digest <n> <c>",
            "schedule evaluation-run <n> <c> <scenario>",
            "schedule evaluation-suite <n> <c>",
            "schedule due",
            "schedule approve|activate|pause <id>",
            "schedule run-due",
            "cron                   Alias for scheduled automation",
            "voice|radio            Guarded voice and external media readiness",
            "stickers               Non-runtime merchandise boundary",
            "browser status|connect|disconnect|session|sessions|close|navigate <url>|live-navigate <url>|live-screenshot|live-click|live-fill|live-submit|live-download|live-upload|live-evaluate",
            "browser activation-packet|verify-activation-packet <packet>  Live adapter activation receipts",
            "browser extract|inspect|dom [selector]|screenshot|render|click <selector>|fill <json>|submit [selector]",
            "boards                 Work boards and cards",
            "backends|sandbox       Execution backend sandbox posture",
            "terminal-setup|vim|mouse Terminal keybinding, vim, and mouse readiness",
            "tui|scroll-speed       Renderer and scroll preference metadata",
            "footer|busy|indicator|details Runtime UI indicators and safe details",
            "redraw                 Refresh compact home surface",
            "snapshot|snap|rollback Guarded snapshot and rollback status",
            "sethome|set-home       Home workspace/channel readiness",
            "install-github-app|install-slack-app External app setup boundaries",
            "team-onboarding        Sanitized onboarding report readiness",
            "diff|review|simplify   Guarded diff, review, and simplify surfaces",
            "ultraplan|ultrareview  Governed plan and deep-review readiness",
            "release-notes          Local release metadata",
            "update|restart         Operator-controlled update/restart readiness",
            "audit                  Audit tail",
            "exit                   Quit",
            "",
            "Plain text submits a task. Slash aliases such as /tasks, /model, /settings, /debug, /rc, /tp, and /bg also work.",
        )
    )


def _aegis_logo(width: int, frame_index: int = 0, *, compact: bool = False) -> str:
    frame_name, frame_detail, frame_art = SHIELD_FRAMES[frame_index % len(SHIELD_FRAMES)]
    wordmark = _aegis_wordmark_lines(width)
    art = [
        f"AEGIS SHIELD :: local-first governed runtime :: SHIELD FRAME {frame_index % len(SHIELD_FRAMES) + 1:02d}/{len(SHIELD_FRAMES):02d} [{frame_name}]",
        f"FRAME STATUS :: {frame_detail}",
        "SYMBOL BUS   :: && policy  %% risk  ## receipts  @@ approvals  __ memory",
        "",
        *wordmark,
        "",
        *frame_art,
        "",
        "COMMAND BUS  :: > plain request  //  / opens palette  //  /dashboard  /tasks  /approvals",
    ]
    if compact:
        art = [art[0], art[1], art[2], "", *wordmark, "", *frame_art, "", "COMMAND BUS  :: / palette  //  menu operate  //  dashboard for full posture"]
    return _boxed_lines("Aegis Shield Identity", art, width)


def _aegis_wordmark_lines(width: int) -> list[str]:
    inner = max(20, width - 4)
    raw_lines = AEGIS_AGENT_WORDMARK
    if max(len(line) for line in raw_lines) > inner:
        raw_lines = AEGIS_COMPACT_WORDMARK
    colors = AEGIS_WORDMARK_COLORS
    return [_paint(line, colors[index % len(colors)]) for index, line in enumerate(raw_lines)]


COMMAND_MENU_GROUPS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    (
        "Operate",
        (
            ("new|reset|clear", "session reset and screen controls"),
            ("add-dir <path>", "record extra working directory context"),
            ("submit <request>", "start a governed task"),
            ("background|bg|btw <request>", "start a governed task without leaving the deck"),
            ("dashboard", "runtime command deck"),
            ("tasks [all|session <id>]", "recent task lanes"),
            ("session|history|title|topic|compress", "active transcript context"),
            ("branch|fork|context", "conversation branch and context metadata"),
            ("copy|export|rename", "explicit copy/export and session rename surfaces"),
            ("paste|image <path>", "safe clipboard and image attachment boundaries"),
            ("save|prompt|steer", "explicit save, prompt, and steering readiness"),
            ("status|resume|continue|pause|cancel", "task controls"),
            ("fast [request]", "quick route alias or governed task submission"),
            ("goal|batch|queue|q|loop", "goal state, evaluation queue, and self-improvement readiness"),
            ("checkpoint|rewind|stop|retry|undo", "checkpoint readiness, cancel alias, session replay, and undo"),
        ),
    ),
    (
        "Govern",
        (
            ("approvals", "pending gates"),
            ("approval <id>", "inspect before action"),
            ("approve|deny <id>", "decide gated work"),
            ("security", "policy posture"),
            ("permissions|security-review", "Claude-style policy and security review aliases"),
            ("fewer-permission-prompts", "permission prompt review readiness"),
            ("privacy-settings", "local privacy, redaction, and telemetry posture"),
            ("whoami|yolo", "identity posture and approval-bypass refusal"),
            ("setup", "guided local setup readiness"),
            ("doctor|debug|config|settings|init|heapdump", "runtime diagnostics, local paths, and initialization status"),
            ("bug|feedback <summary>", "local-only bug report capture"),
            ("hooks", "governed local lifecycle hooks"),
            ("audit|evidence|timeline|events", "receipts and replay"),
        ),
    ),
    (
        "Build",
        (
            ("model|models|provider|usage", "provider routes, auth, and usage"),
            ("insights [days]", "sanitized local usage analytics"),
            ("gquota [model]", "Google Gemini Code Assist quota metadata"),
            ("login|logout <provider>", "model auth login/logout aliases"),
            ("setup|setup-bedrock|setup-vertex|upgrade|extra-usage|passes", "guided setup, cloud identity setup, and account boundary"),
            ("effort|cost", "guarded reasoning-effort metadata and usage cost"),
            ("statusbar|statusline|sb|theme|skin|color|verbose", "UI preference and status metadata"),
            ("commands|keybindings|powerup|focus|ide", "slash command, feature discovery, and terminal integration surfaces"),
            ("claude-api", "Claude API migration and managed-agent reference readiness"),
            ("allowed-tools|bashes|processes", "policy-visible tools and governed process controls"),
            ("tools list|run|enable|disable", "safe tool execution and policy-owned preferences"),
            ("toolsets", "tool catalog grouped by permission and risk"),
            ("skills hub|search|browse|inspect|install", "governed skill hub"),
            ("curator status|run|pin|archive", "local authored skill maintenance"),
            ("plugin|plugins|reload|reload-plugins|reload-skills", "extension inventory and reload readiness"),
            ("reload_skills", "extension inventory and reload readiness"),
            ("memory search|create|review", "durable memory"),
            ("mcp|reload-mcp|reload_mcp|repair|schedules|cron", "extensions, schedules, and self-repair"),
        ),
    ),
    (
        "Explore",
        (
            ("capabilities", "parity and readiness"),
            ("agents status|autonomy-preflight|delegate|review-packet|verify-packet|model-review|run", "multi-agent coordination and runtime preflight"),
            ("remote-control|rc|handoff|remote-env|teleport|tp|mobile|ios|android|desktop|app", "local-first remote-control readiness"),
            ("web-setup", "local web control-plane setup"),
            ("connectors|channels|platforms", "integration surfaces"),
            ("pr_comments|autofix-pr", "pull request comment and autofix readiness"),
            ("browser status|connect|disconnect|render|live-navigate|live-screenshot|live-click|live-fill|live-submit|live-download|live-upload|live-evaluate|activation-packet|verify-activation-packet|chrome", "sandboxed browser work"),
            ("boards|backends|sandbox", "work and execution planes"),
            ("voice|radio|terminal-setup|vim|mouse|tui|scroll-speed", "optional interaction and terminal readiness"),
            ("footer|busy|indicator|details|redraw", "runtime UI indicators and safe details"),
            ("rollback|snapshot|snap|diff|review|simplify", "guarded rollback, snapshot, diff, and review status"),
            ("ultraplan|ultrareview", "governed plan and deep-review readiness"),
            ("sethome|set-home", "home workspace/channel readiness"),
            ("install-github-app|install-slack-app|team-onboarding", "external app setup and onboarding readiness"),
            ("release-notes|update|restart", "operator-controlled update and release readiness"),
        ),
    ),
)


def _command_palette_lines(*, compact: bool = False) -> list[str]:
    if compact:
        return [
            "Codex-style command surface: Plain text submits a governed task; /command dispatches directly.",
            "Prompt   > summarize this repo safely  -> submit governed task",
            "Slash    /dashboard /tasks /approvals /security /menu",
            "Inspect  /status <id> /events <id> /timeline <id> /evidence <id>",
            "Act      /approve <id> /deny <id> /resume <id> /pause <id> /cancel <id>",
            "Complete Tab completes command and subcommand names; ? or help opens the reference.",
        ]
    lines: list[str] = []
    for group, commands in COMMAND_MENU_GROUPS:
        command_names = ", ".join(_slash_command_label(command) for command, _detail in commands)
        lines.append(f"{group:<8} {command_names}")
    return lines


def _command_menu(width: int, status_flags: list[str] | None = None, *, group: str | None = None) -> str:
    if group:
        selected = _command_group(group)
        if selected is None:
            return _boxed_lines(
                "Shield Command Menu",
                [
                    f"Unknown menu group: {group}",
                    f"Available groups: {', '.join(_command_group_names())}",
                    "Use menu with no argument for the command deck.",
                ],
                width,
            )
        group_name, commands = selected
        lines = [
            f"{group_name} command group",
            "Slash dispatch works for every command below; Tab completes command and subcommand names.",
        ]
        if status_flags:
            lines.extend(("", "Active flags:", *status_flags))
        lines.append("")
        for command, detail in commands:
            lines.append(f"{_slash_command_label(command):<38} {detail}")
            lines.append(f"    next: {_next_command_hint(command)}")
        return _boxed_lines(f"{group_name} Menu", lines, width)

    lines: list[str] = [
        "AEGIS SHIELD command deck",
        "Minimal by default: pick a lane, then open the nested menu only when you need detail.",
        "Codex-style affordances: plain text submits; / opens the palette; /command dispatches; Tab completes.",
    ]
    if status_flags:
        lines.extend(("", "Active flags:", *status_flags))
    lines.append("")
    for group, commands in COMMAND_MENU_GROUPS:
        command_lane = " ".join(_slash_command_label(command).split()[0] for command, _detail in commands[:4])
        lines.append(f"[{group:<7}] {command_lane}")
        lines.append(f"          open nested menu: menu {group.lower()}  |  slash filter: /{commands[0][0].split()[0]}")
    if lines and not lines[-1]:
        lines.pop()
    return _boxed_lines("Shield Command Menu", lines, width)


def _slash_palette(
    width: int,
    *,
    prefix: str = "",
    status_flags: list[str] | None = None,
    quick_matches: list[tuple[str, str]] | None = None,
    dynamic_matches: list[tuple[str, str]] | None = None,
) -> str:
    prefix = prefix.strip().lstrip("/")
    matches = _slash_matches(prefix)
    quick_matches = quick_matches or []
    dynamic_matches = dynamic_matches or []
    lines: list[str] = [
        "Slash Command Palette",
        "Type /<command> to run it, /<prefix> to filter, or menu <group> for nested command lanes.",
    ]
    if status_flags:
        lines.extend(("", "Active flags:", *status_flags))
    if prefix:
        lines.append("")
        lines.append(f"Filter: /{prefix}")
    lines.append("")
    if matches:
        for command, detail in matches[:12]:
            lines.append(f"{_slash_palette_label(command, prefix):<38} {detail}  -> {_next_command_hint(command)}")
    if quick_matches:
        if matches:
            lines.append("")
        lines.append("Quick commands:")
        for command, detail in quick_matches:
            next_hint = "/tools" if "exec" in detail else detail.removeprefix("quick alias - ")
            lines.append(f"/{command:<37} {detail}  -> {next_hint}")
    if dynamic_matches:
        if matches or quick_matches:
            lines.append("")
        lines.append("Enabled skill commands:")
        for command, detail in dynamic_matches:
            lines.append(f"/{command:<37} {detail}  -> /skills")
    else:
        if not matches and not quick_matches:
            lines.append("No direct matches. Try /dashboard, /tasks, /memory, /approvals, or /menu.")
    lines.extend(("", "Nested menus:", "  /menu operate   /menu govern   /menu build   /menu explore"))
    return _boxed_lines("Slash Command Palette", lines, width)


def _command_group_names() -> tuple[str, ...]:
    return tuple(group.lower() for group, _commands in COMMAND_MENU_GROUPS)


def _command_group(name: str) -> tuple[str, tuple[tuple[str, str], ...]] | None:
    normalized = name.lower().strip()
    for group, commands in COMMAND_MENU_GROUPS:
        if group.lower().startswith(normalized):
            return group, commands
    return None


def _slash_matches(prefix: str) -> list[tuple[str, str]]:
    normalized = prefix.strip().lstrip("/").lower()
    rows: list[tuple[str, str]] = []
    for group, commands in COMMAND_MENU_GROUPS:
        for command, detail in commands:
            roots = command.split()[0].split("|")
            labels = [command, group, *roots]
            if not normalized or any(_fuzzy_match(normalized, label) for label in labels):
                rows.append((command, f"{group.lower()} - {detail}"))
    if not normalized or _fuzzy_match(normalized, "menu"):
        rows.append(("menu [operate|govern|build|explore]", "open a nested command lane"))
    if not normalized or _fuzzy_match(normalized, "help"):
        rows.append(("help", "full command reference"))
    if not normalized:
        return rows
    return sorted(rows, key=lambda row: _slash_match_rank(normalized, row))


def _slash_completion_labels(prefix: str) -> list[str]:
    normalized = prefix.strip().lstrip("/").lower()
    labels: list[str] = []
    seen: set[str] = set()
    for command, detail in _slash_matches(normalized):
        roots = command.split()[0].split("|")
        for root in roots:
            label = f"/{root}"
            if label in seen:
                continue
            if not normalized or _fuzzy_match(normalized, root):
                labels.append(label)
                seen.add(label)
    return labels


def _fuzzy_match(needle: str, value: object) -> bool:
    haystack = str(value).lower()
    return haystack.startswith(needle) or needle in haystack


def _slash_match_rank(prefix: str, row: tuple[str, str]) -> tuple[int, str]:
    if not prefix:
        return (0, row[0])
    command, detail = row
    roots = command.split()[0].split("|")
    if any(root.lower().startswith(prefix) for root in roots):
        return (0, command)
    if command.lower().startswith(prefix):
        return (1, command)
    if any(prefix in root.lower() for root in roots):
        return (2, command)
    if prefix in command.lower():
        return (3, command)
    if prefix in detail.lower():
        return (4, command)
    return (5, command)


def _session_steering_summary(session: dict[str, Any]) -> dict[str, Any]:
    steering = session.get("metadata", {}).get("tui_steering", {})
    if not isinstance(steering, dict):
        steering = {}
    return {
        "active": bool(steering.get("active")),
        "instruction_sha256": steering.get("instruction_sha256"),
        "instruction_character_count": int(steering.get("instruction_character_count") or 0),
        "updated_at": steering.get("updated_at"),
        "raw_instruction_included": False,
    }


def _clean_session_preference_value(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.:-]+", "-", value.strip()).strip("-")
    return (cleaned or "default")[:80]


def _safe_display_value(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = redact(value)
    return "[REDACTED]" if redacted != value else _clean_session_preference_value(value)


def _dashboard_status_flags(runtime: dict[str, Any], session: dict[str, Any], *, workspace: Path | None = None) -> list[str]:
    pending = int(runtime.get("pending_approvals") or 0)
    approval_state = "CLEAR" if pending == 0 else f"WAIT:{pending}"
    active_work = int(runtime.get("active_work_count") or 0)
    work_state = "CLEAR" if active_work == 0 else str(active_work)
    audit_state = "OK" if runtime.get("audit_chain_ok") else "FAILED"
    session_id = _short_id(session.get("id", ""))
    session_state = str(session.get("status") or "active").upper()
    model = str(session.get("model") or "alias/smart")
    personality = str(session.get("personality") or "default")
    workspace_label = workspace.name if workspace is not None else "workspace"
    return [
        " ".join(
            (
                _status_flag("AUDIT", audit_state, "32;1" if audit_state == "OK" else "31;1"),
                _status_flag("APPROVALS", approval_state, "32;1" if pending == 0 else "33;1"),
                _status_flag("WORK", work_state, "32;1" if active_work == 0 else "33;1"),
                _status_flag("SESSION", f"{session_id}:{session_state}", "36;1"),
                _status_flag("MODE", "LOCAL-FIRST", "32;1"),
            )
        ),
        " ".join(
            (
                _status_flag("CHANNELS", runtime.get("channels", 0), "36;1"),
                _status_flag("TOOLS", runtime.get("tools", 0), "36;1"),
                _status_flag("GATED", runtime.get("approval_gated_tools", 0), "33;1"),
                _status_flag("PROVIDERS", runtime.get("model_providers", 0), "36;1"),
            )
        ),
        " ".join(
            (
                _status_flag("MODEL", model, "36;1"),
                _status_flag("PERSONA", personality, "36;1"),
                _status_flag("WORKSPACE", workspace_label, "36;1"),
            )
        ),
    ]


def _status_flag(label: str, value: object, color: str) -> str:
    return _paint(f"[{label}:{value}]", color)


def _slash_command_label(command: str) -> str:
    first, separator, rest = command.partition(" ")
    if "|" not in first:
        return f"/{command}"
    return f"{'|'.join('/' + part for part in first.split('|'))}{separator}{rest}"


def _slash_palette_label(command: str, prefix: str) -> str:
    normalized = prefix.strip().lstrip("/").lower()
    if not normalized:
        return _slash_command_label(command)
    first, separator, rest = command.partition(" ")
    roots = first.split("|")
    matching = [root for root in roots if _fuzzy_match(normalized, root)]
    if not matching:
        return _slash_command_label(command)
    return "|".join(f"/{root}" for root in matching) + separator + rest


def _next_command_hint(command: str) -> str:
    root = command.split()[0].split("|")[0]
    hints = {
        "submit": "/status <id>",
        "dashboard": "/menu",
        "tasks": "/events <id>",
        "session": "/session history",
        "topic": "/sessions",
        "recap": "/session history",
        "branch": "/session new <title>",
        "copy": "/session history",
        "export": "/audit export-siem",
        "rename": "/session rename <title>",
        "save": "/session history",
        "steer": "/prompt",
        "retry": "/status <id>",
        "undo": "/session history",
        "queue": "/tasks",
        "q": "/tasks",
        "add-dir": "/session history",
        "status": "/timeline <id>",
        "approvals": "/approval <id>",
        "approval": "/approve <id>",
        "approve": "/resume <id>",
        "security": "/audit",
        "bug": "/repair readiness",
        "autofix-pr": "/pr_comments",
        "audit": "/evidence <id>",
        "model": "/models auth targets",
        "models": "/models route <id>",
        "setup": "/models auth doctor",
        "setup-bedrock": "/models auth doctor",
        "setup-vertex": "/models auth doctor",
        "gquota": "/models auth google-gemini-oauth",
        "login": "/models auth targets",
        "logout": "/models auth methods",
        "upgrade": "/models auth targets",
        "effort": "/model",
        "cost": "/models usage",
        "insights": "/usage",
        "commands": "/commands all",
        "keybindings": "/terminal-setup",
        "allowed-tools": "/toolsets",
        "bashes": "/bashes start --approved --pty --",
        "processes": "/processes list",
        "tools": "/tools run <name> <json>",
        "skills": "/skills hub <query>",
        "curator": "/curator run --dry-run",
        "plugin": "/plugins",
        "reload": "/plugins",
        "hooks": "/hooks list",
        "memory": "/memory review-queue",
        "mcp": "/mcp list",
        "doctor": "/capabilities",
        "statusbar": "/dashboard",
        "footer": "/statusbar",
        "busy": "/tasks",
        "indicator": "/statusbar",
        "details": "/dashboard",
        "permissions": "/security profile",
        "privacy-settings": "/security profile",
        "whoami": "/permissions",
        "yolo": "/permissions",
        "paste": "/session append <content>",
        "image": "/browser screenshot",
        "agents": "/agents delegate",
        "handoff": "/platforms",
        "remote-control": "/web-setup",
        "web-setup": "/remote-control",
        "capabilities": "/connectors",
        "connectors": "/channels",
        "pr_comments": "/connectors",
        "browser": "/browser status",
        "chrome": "/browser status",
        "boards": "/backends",
        "tui": "/terminal-setup",
        "scroll-speed": "/mouse",
        "terminal-setup": "/vim",
        "mouse": "/terminal-setup",
        "radio": "/voice",
        "stickers": "/help",
        "redraw": "/dashboard",
        "release-notes": "/update",
        "rollback": "/repair readiness",
        "simplify": "/review",
        "ultraplan": "/plan",
        "ultrareview": "/security-review",
        "sethome": "/web-setup",
    }
    return hints.get(root, "/help")


SLASH_SUBCOMMANDS: dict[str, tuple[str, ...]] = {
    "memory": MEMORY_COMMANDS,
    "migrate": MIGRATE_COMMANDS,
    "model": MODEL_COMMANDS,
    "models": MODEL_COMMANDS,
    "repair": REPAIR_COMMANDS,
    "schedule": SCHEDULE_COMMANDS,
    "browser": BROWSER_COMMANDS,
    "mcp": MCP_COMMANDS,
    "hooks": HOOK_COMMANDS,
    "agents": AGENTS_COMMANDS,
    "bashes": PROCESS_COMMANDS,
    "process": PROCESS_COMMANDS,
    "processes": PROCESS_COMMANDS,
    "remote-control": REMOTE_CONTROL_COMMANDS,
    "remote_control": REMOTE_CONTROL_COMMANDS,
    "rc": REMOTE_CONTROL_COMMANDS,
    "session": SESSION_COMMANDS,
    "task": TASK_COMMANDS,
    "tasks": TASKS_COMMANDS,
    "queue": QUEUE_COMMANDS,
    "q": QUEUE_COMMANDS,
    "busy": BUSY_COMMANDS,
    "security": SECURITY_COMMANDS,
    "channel": CHANNEL_COMMANDS,
    "evaluation": EVALUATION_COMMANDS,
    "tools": TOOLS_COMMANDS,
    "backends": BACKEND_COMMANDS,
    "sandbox": BACKEND_COMMANDS,
    "skills": SKILLS_COMMANDS,
    "curator": CURATOR_COMMANDS,
    "plugin": PLUGIN_COMMANDS,
    "plugins": PLUGIN_COMMANDS,
    "menu": _command_group_names(),
}

SLASH_FLAG_HINTS: dict[tuple[str, str], tuple[str, ...]] = {
    ("memory", "health"): ("--limit", "--owner", "--scope"),
    ("memory", "session-commit"): ("--all", "--candidate-id", "--none", "--reviewer"),
    ("memory", "review-queue"): ("--limit", "--owner", "--scope"),
    ("memory", "review-digest"): ("--limit", "--owner", "--scope"),
    ("memory", "recertify"): ("--max-age-days", "--limit", "--dry-run", "--owner", "--scope"),
    ("task", "submit"): ("--path",),
    ("queue", "status"): ("--limit", "--status"),
    ("queue", "show"): ("--limit", "--status"),
    ("queue", "list"): ("--limit", "--status"),
    ("queue", "active"): ("--limit", "--status"),
    ("queue", "pending"): ("--limit", "--status"),
    ("queue", "all"): ("--limit", "--status"),
    ("queue", "session"): ("--limit", "--status"),
    ("q", "status"): ("--limit", "--status"),
    ("q", "show"): ("--limit", "--status"),
    ("q", "list"): ("--limit", "--status"),
    ("q", "active"): ("--limit", "--status"),
    ("q", "pending"): ("--limit", "--status"),
    ("q", "all"): ("--limit", "--status"),
    ("q", "session"): ("--limit", "--status"),
    ("busy", "queue"): ("--limit", "--status"),
    ("session", "new"): ("--model", "--personality"),
    ("schedule", "create"): ("--natural-language", "--channel", "--context-from", "--deliver-to"),
    ("schedule", "script"): ("--channel", "--context-from", "--deliver-to", "--hook-id", "--timeout", "--max-output-bytes"),
    ("schedule", "no-agent"): ("--channel", "--context-from", "--deliver-to", "--hook-id", "--timeout", "--max-output-bytes"),
    ("schedule", "run-due"): ("--limit", "--now"),
    ("hooks", "add"): ("--id", "--enabled", "--approval-required", "--no-approval-required", "--timeout", "--max-output-bytes"),
    ("hooks", "run"): ("--approved", "--context-json"),
    ("agents", "delegate"): ("--approved",),
    ("agents", "model-review"): ("--approved",),
    ("agents", "run"): ("--approved",),
    ("agents", "run-batch"): ("--approved", "--limit", "--card-id"),
    ("bashes", "start"): ("--approved", "--actor", "--label", "--pty", "--rows", "--cols"),
    ("bashes", "logs"): ("--max-bytes",),
    ("bashes", "input"): ("--no-newline",),
    ("bashes", "resize"): ("--rows", "--cols"),
    ("process", "start"): ("--approved", "--actor", "--label", "--pty", "--rows", "--cols"),
    ("process", "logs"): ("--max-bytes",),
    ("process", "input"): ("--no-newline",),
    ("process", "resize"): ("--rows", "--cols"),
    ("processes", "start"): ("--approved", "--actor", "--label", "--pty", "--rows", "--cols"),
    ("processes", "logs"): ("--max-bytes",),
    ("processes", "input"): ("--no-newline",),
    ("processes", "resize"): ("--rows", "--cols"),
    ("mcp", "call"): ("--approved",),
    ("mcp", "register"): ("--discover", "--transport", "--token-secret", "--tool", "--exclude-tool", "--no-resources", "--no-prompts", "--enable", "--no-approval"),
    ("plugins", "fetch-manifest"): ("--catalog-path",),
    ("plugin", "fetch-manifest"): ("--catalog-path",),
    ("plugins", "fetch-bundle"): ("--catalog-path", "--key-name"),
    ("plugin", "fetch-bundle"): ("--catalog-path", "--key-name"),
    ("plugins", "install-bundle"): ("--catalog-path", "--key-name", "--enable"),
    ("plugin", "install-bundle"): ("--catalog-path", "--key-name", "--enable"),
    ("plugins", "install-marketplace"): ("--catalog-path", "--enable"),
    ("plugin", "install-marketplace"): ("--catalog-path", "--enable"),
    ("plugins", "update-marketplace"): ("--catalog-path", "--enable", "--disable", "--force", "--approved"),
    ("plugin", "update-marketplace"): ("--catalog-path", "--enable", "--disable", "--force", "--approved"),
    ("plugins", "prepare-update"): ("--catalog-path", "--force"),
    ("plugin", "prepare-update"): ("--catalog-path", "--force"),
    ("plugins", "apply-prepared-update"): ("--approved", "--enable", "--disable"),
    ("plugin", "apply-prepared-update"): ("--approved", "--enable", "--disable"),
    ("curator", "run"): ("--dry-run",),
    ("remote-control", "pair"): ("--label", "--session-id", "--task-id", "--allowed-actions", "--expires-in-seconds"),
    ("remote-control", "directory"): ("--pairing-id", "--limit"),
    ("remote-control", "revoke"): ("--relay-auth-secret", "--approved"),
    ("remote-control", "relay"): ("--relay-url", "--pairing-id", "--relay-auth-secret", "--approved"),
    ("remote-control", "relay-directory"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit"),
    ("remote-control", "relay-notify"): ("--pairing-id", "--relay-auth-secret", "--approved", "--event", "--task-id"),
    ("remote-control", "push-targets"): ("--target-id",),
    ("remote-control", "push-register"): ("--label", "--provider", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id"),
    ("remote-control", "push-disable"): ("--target-id", "--approved"),
    ("remote-control", "push-rotate"): ("--target-id", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id"),
    ("remote-control", "push"): ("--pairing-id", "--target-id", "--provider", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id", "--event", "--task-id"),
    ("remote-control", "relay-outbox"): ("--status", "--limit"),
    ("remote-control", "relay-retry"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit"),
    ("remote-control", "relay-confirm"): ("--pairing-id", "--outbox-id", "--relay-auth-secret", "--approved"),
    ("remote-control", "relay-pull"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit", "--dry-run"),
    ("remote-control", "relay-action"): ("--pairing-id", "--task-id", "--action", "--relay-auth-secret", "--session-id", "--reason"),
    ("remote_control", "pair"): ("--label", "--session-id", "--task-id", "--allowed-actions", "--expires-in-seconds"),
    ("remote_control", "directory"): ("--pairing-id", "--limit"),
    ("remote_control", "revoke"): ("--relay-auth-secret", "--approved"),
    ("remote_control", "relay"): ("--relay-url", "--pairing-id", "--relay-auth-secret", "--approved"),
    ("remote_control", "relay-directory"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit"),
    ("remote_control", "relay-notify"): ("--pairing-id", "--relay-auth-secret", "--approved", "--event", "--task-id"),
    ("remote_control", "push-targets"): ("--target-id",),
    ("remote_control", "push-register"): ("--label", "--provider", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id"),
    ("remote_control", "push-disable"): ("--target-id", "--approved"),
    ("remote_control", "push-rotate"): ("--target-id", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id"),
    ("remote_control", "push"): ("--pairing-id", "--target-id", "--provider", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id", "--event", "--task-id"),
    ("remote_control", "relay-outbox"): ("--status", "--limit"),
    ("remote_control", "relay-retry"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit"),
    ("remote_control", "relay-confirm"): ("--pairing-id", "--outbox-id", "--relay-auth-secret", "--approved"),
    ("remote_control", "relay-pull"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit", "--dry-run"),
    ("remote_control", "relay-action"): ("--pairing-id", "--task-id", "--action", "--relay-auth-secret", "--session-id", "--reason"),
    ("rc", "pair"): ("--label", "--session-id", "--task-id", "--allowed-actions", "--expires-in-seconds"),
    ("rc", "directory"): ("--pairing-id", "--limit"),
    ("rc", "revoke"): ("--relay-auth-secret", "--approved"),
    ("rc", "relay"): ("--relay-url", "--pairing-id", "--relay-auth-secret", "--approved"),
    ("rc", "relay-directory"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit"),
    ("rc", "relay-notify"): ("--pairing-id", "--relay-auth-secret", "--approved", "--event", "--task-id"),
    ("rc", "push-targets"): ("--target-id",),
    ("rc", "push-register"): ("--label", "--provider", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id"),
    ("rc", "push-disable"): ("--target-id", "--approved"),
    ("rc", "push-rotate"): ("--target-id", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id"),
    ("rc", "push"): ("--pairing-id", "--target-id", "--provider", "--push-auth-secret", "--device-token-secret", "--approved", "--apns-topic", "--fcm-project-id", "--event", "--task-id"),
    ("rc", "relay-outbox"): ("--status", "--limit"),
    ("rc", "relay-retry"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit"),
    ("rc", "relay-confirm"): ("--pairing-id", "--outbox-id", "--relay-auth-secret", "--approved"),
    ("rc", "relay-pull"): ("--pairing-id", "--relay-auth-secret", "--approved", "--limit", "--dry-run"),
    ("rc", "relay-action"): ("--pairing-id", "--task-id", "--action", "--relay-auth-secret", "--session-id", "--reason"),
}

PATH_COMPLETION_FLAGS = {
    "--catalog-path",
    "--config",
    "--path",
    "--patch-file",
    "--synthesis-file",
    "--workspace",
}

PATH_COMPLETION_ROOTS = {
    "add-dir",
    "image",
}


def _complete_slash(text: str, line: str, begidx: int, endidx: int) -> list[str]:
    stripped = line.lstrip()
    if not stripped.startswith("/"):
        return []
    command_line = stripped[1:]
    try:
        parts = shlex.split(command_line[: max(0, endidx - (len(line) - len(stripped)) - 1)])
    except ValueError:
        return []
    trailing_space = command_line.endswith(" ")
    if not parts and not trailing_space:
        return _slash_completion_labels("")
    if len(parts) <= 1 and not trailing_space:
        root_prefix = parts[0] if parts else text.lstrip("/")
        return _slash_completion_labels(root_prefix)
    root = parts[0]
    current = "" if trailing_space else text
    if root in {"model", "models"} and len(parts) >= 2 and parts[1] == "auth":
        return _complete_options(MODEL_AUTH_COMMANDS, current)
    if current.startswith("--") or any(part.startswith("--") for part in parts[1:]):
        subcommand = parts[1] if len(parts) > 1 else ""
        return _complete_options(SLASH_FLAG_HINTS.get((root, subcommand), ()), current)
    subcommands = SLASH_SUBCOMMANDS.get(root, ())
    return _complete_options(subcommands, current)


def _live_completion_context(buffer: str) -> tuple[str, int, int]:
    endidx = len(buffer)
    if not buffer.startswith("/"):
        return buffer, 0, endidx
    if not buffer or buffer[-1].isspace():
        return "", endidx, endidx
    last_break = max(buffer.rfind(" "), buffer.rfind("\t"), buffer.rfind("\n"))
    begidx = last_break + 1 if last_break >= 0 else 1
    return buffer[begidx:endidx], begidx, endidx


def _word_completion_context(buffer: str) -> tuple[str, int, int]:
    endidx = len(buffer)
    if not buffer or buffer[-1].isspace():
        return "", endidx, endidx
    last_break = max(buffer.rfind(" "), buffer.rfind("\t"), buffer.rfind("\n"))
    begidx = last_break + 1 if last_break >= 0 else 0
    return buffer[begidx:endidx], begidx, endidx


def _apply_live_completion(buffer: str, completion: str, begidx: int, endidx: int) -> str:
    if buffer.startswith("/") and completion.startswith("/"):
        return completion
    return f"{buffer[:begidx]}{completion}{buffer[endidx:]}"


def _complete_options(options: tuple[str, ...], text: str) -> list[str]:
    return [option for option in options if option.startswith(text)]


def _complete_context_paths(text: str, line: str, begidx: int, workspace: str | Path) -> list[str]:
    token = text.strip()
    if not token:
        return []
    if token.startswith("@"):
        return _complete_workspace_paths(token, workspace)
    if _expects_path_completion(line, begidx):
        return _complete_workspace_paths(token, workspace, context_marker=False)
    return []


def _expects_path_completion(line: str, begidx: int) -> bool:
    before = line[:begidx]
    try:
        parts = shlex.split(before)
    except ValueError:
        parts = before.split()
    if not parts:
        return False
    if parts[-1] in PATH_COMPLETION_FLAGS:
        return True
    root = parts[0].lstrip("/").replace("_", "-")
    return root in PATH_COMPLETION_ROOTS and len(parts) == 1


def _complete_workspace_paths(text: str, workspace: str | Path, *, context_marker: bool | None = None) -> list[str]:
    raw = text[1:] if text.startswith("@") else text
    marker = "@" if (context_marker if context_marker is not None else text.startswith("@")) else ""
    if raw.startswith(("~", "/")):
        return []
    raw = raw.replace("\\", "/")
    parent_raw, _, fragment = raw.rpartition("/")
    if not raw.endswith("/") and not parent_raw:
        parent_raw = "."
    elif raw.endswith("/"):
        parent_raw = raw.rstrip("/") or "."
        fragment = ""
    root = Path(workspace).expanduser().resolve()
    try:
        parent = (root / parent_raw).resolve()
        parent.relative_to(root)
    except (OSError, ValueError):
        return []
    if not parent.exists() or not parent.is_dir():
        return []
    fragment_lower = fragment.lower()
    rows: list[Path] = []
    try:
        candidates = list(parent.iterdir())
    except OSError:
        return []
    for child in candidates:
        name = child.name
        if name.startswith(".") and not fragment.startswith("."):
            continue
        name_lower = name.lower()
        if fragment_lower and not (name_lower.startswith(fragment_lower) or fragment_lower in name_lower):
            continue
        try:
            child.resolve().relative_to(root)
        except (OSError, ValueError):
            continue
        rows.append(child)
    rows.sort(key=lambda path: (not path.is_dir(), path.name.lower()))
    labels: list[str] = []
    for child in rows[:20]:
        try:
            rel = child.relative_to(root).as_posix()
        except ValueError:
            continue
        suffix = "/" if child.is_dir() else ""
        labels.append(f"{marker}{rel}{suffix}")
    return labels


def _skill_slash_labels(skill_id: str) -> tuple[str, ...]:
    normalized = re.sub(r"[^a-z0-9]+", "-", skill_id.lower()).strip("-")
    labels = [normalized]
    if skill_id and all(part.isalnum() or part in "._-" for part in skill_id):
        labels.append(skill_id)
    seen: list[str] = []
    for label in labels:
        if label and label not in seen:
            seen.append(label)
    return tuple(seen)


def _parse_skill_slash_inputs(schema: dict[str, Any], raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        return {}
    if text.startswith("{"):
        decoded = json.loads(text)
        if not isinstance(decoded, dict):
            raise ValueError("skill slash JSON input must be an object")
        return decoded
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    if not isinstance(properties, dict):
        raise ValueError("skill slash text input requires a JSON object")
    string_properties = [
        str(name)
        for name, spec in properties.items()
        if isinstance(spec, dict) and spec.get("type") in {"string", None}
    ]
    if len(string_properties) == 1:
        return {string_properties[0]: text}
    for preferred in ("input", "query", "prompt", "task", "path"):
        if preferred in string_properties:
            return {preferred: text}
    raise ValueError("skill slash text input is ambiguous; pass a JSON object")


def _complete_subcommand(options: tuple[str, ...], text: str, line: str, begidx: int) -> list[str]:
    try:
        parts = shlex.split(line[:begidx])
    except ValueError:
        return []
    if len(parts) <= 1:
        return _complete_options(options, text)
    return []


def _live_input_block(prompt: str, buffer: str, width: int, *, workspace: str | Path | None = None) -> tuple[str, int]:
    prompt = _strip_readline_markers(prompt)
    context_lines = _live_context_hint_lines(buffer, width, workspace=workspace)
    slash_lines = [] if context_lines else _live_slash_hint_lines(buffer, width)
    suggestion_lines = _live_key_hint_lines(buffer, width) + context_lines + slash_lines
    input_lines = _wrapped_prompt_lines(prompt, buffer, width)
    return "\n".join([*suggestion_lines, *input_lines]), len(suggestion_lines) + len(input_lines)


def _live_key_hint_lines(buffer: str, width: int) -> list[str]:
    if buffer:
        return []
    return [_paint(_shorten_preserve_spaces("keys     Enter send  Ctrl+V newline  Tab complete", width=max(20, width)), "2;36")]


def _live_slash_hint_lines(buffer: str, width: int) -> list[str]:
    if not buffer.startswith("/"):
        return []
    completion_text, begidx, endidx = _live_completion_context(buffer)
    labels = _complete_slash(completion_text, buffer, begidx, endidx)
    if not labels:
        return [_paint("suggest  no slash matches", "2;33")]
    label = _live_completion_hint_label(labels, begidx)
    line = f"{label:<7} " + "  ".join(labels)
    return [_paint(_shorten_preserve_spaces(line, width=max(20, width)), "2;36")]


def _live_context_hint_lines(buffer: str, width: int, *, workspace: str | Path | None = None) -> list[str]:
    if not buffer:
        return []
    if buffer.startswith("/"):
        completion_text, begidx, _endidx = _live_completion_context(buffer)
    else:
        completion_text, begidx, _endidx = _word_completion_context(buffer)
    labels = _complete_context_paths(completion_text, buffer, begidx, workspace or Path.cwd())
    if not labels:
        return []
    label = "context" if completion_text.strip().startswith("@") else "path"
    line = f"{label:<7} " + "  ".join(labels)
    return [_paint(_shorten_preserve_spaces(line, width=max(20, width)), "2;36")]


def _live_completion_hint_label(labels: list[str], begidx: int) -> str:
    if labels and all(label.startswith("--") for label in labels):
        return "flags"
    if labels and all(label.startswith("/") for label in labels) and begidx <= 1:
        return "slash"
    return "subcmd"


def _wrapped_prompt_lines(prompt: str, buffer: str, width: int) -> list[str]:
    width = max(20, width)
    usable_width = max(19, width - 1)
    prompt_len = _visible_length(prompt)
    first_width = max(8, usable_width - prompt_len)
    continuation = " " * min(prompt_len, max(0, usable_width - 8))
    if not buffer:
        return [prompt]
    lines: list[str] = []
    prefix = prompt
    for logical_line in buffer.split("\n"):
        remaining = logical_line
        if not remaining:
            lines.append(prefix)
            prefix = continuation
            continue
        while remaining:
            chunk_width = first_width if prefix == prompt else max(8, usable_width - len(continuation))
            chunk, remaining = remaining[:chunk_width], remaining[chunk_width:]
            lines.append(prefix + chunk)
            prefix = continuation
    return lines


def _inline_completion_line(completions: list[str], *, width: int) -> str:
    return textwrap.shorten("complete " + "  ".join(completions[:12]), width=max(20, width), placeholder=" ...")


def _shorten_preserve_spaces(text: str, *, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 4:
        return text[:width]
    return text[: width - 4].rstrip() + " ..."


def _read_tui_history_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return [line.rstrip("\n") for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return []


def _add_tui_history(line: str) -> bool:
    readline = _readline_module()
    if readline is None:
        return False
    readline.add_history(line)
    return True


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


def _banner(title: str, width: int, subtitle: str | None = None) -> str:
    inner = width - 4
    rule = "+" + "-" * (width - 2) + "+"
    title_line = f"| {_paint(title.ljust(inner), '36;1')} |"
    lines = ["", rule, title_line]
    if subtitle:
        lines.append(f"| {subtitle.ljust(inner)} |")
    lines.append(rule)
    return "\n".join(lines)


def _boxed_lines(title: str, items: list[str], width: int) -> str:
    inner = width - 4
    rule = "+" + "-" * (width - 2) + "+"
    title_line = f"| {_paint(title.ljust(inner), '36;1')} |"
    body = []
    for item in items:
        for line in _wrap_box_line(item, inner):
            body.append(f"| {_pad_visible(line, inner)} |")
    return "\n".join(("", rule, title_line, rule, *body, rule))


def _wrap_box_line(item: str, width: int) -> list[str]:
    if not item:
        return [""]
    if _visible_length(item) <= width:
        return [item]
    plain = ANSI_PATTERN.sub("", _strip_readline_markers(item))
    return textwrap.wrap(plain, width=width, replace_whitespace=False, drop_whitespace=False) or [""]


def _pad_visible(line: str, width: int) -> str:
    return line + " " * max(0, width - _visible_length(line))


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


def _backend_preflight_rows(gap: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for backend in list(gap.get("implemented_backend_adapters", [])) + list(gap.get("available_backend_adapters", [])):
        activation = backend.get("activation", {}) if isinstance(backend, dict) else {}
        blockers = activation.get("blockers", []) if isinstance(activation, dict) else []
        rows.append(
            {
                "backend": str(backend.get("name", "unknown")) if isinstance(backend, dict) else "unknown",
                "preflight": str(activation.get("preflight_status") or activation.get("status") or "unknown") if isinstance(activation, dict) else "unknown",
                "blockers": ", ".join(str(blocker.get("control", "unknown")) for blocker in blockers[:4]) if blockers else "none",
            }
        )
    return rows


def _live_adapter_preflight_rows(gap: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for adapter in list(gap.get("implemented_live_adapters", [])) + list(gap.get("available_live_adapters", [])):
        activation_raw = adapter.get("activation", {}) if isinstance(adapter, dict) else {}
        activation = activation_raw if isinstance(activation_raw, dict) else {}
        blockers = activation.get("blockers", []) if isinstance(activation, dict) else []
        rows.append(
            {
                "adapter": str(adapter.get("name", "unknown")) if isinstance(adapter, dict) else "unknown",
                "kind": str(adapter.get("kind", "unknown")) if isinstance(adapter, dict) else "unknown",
                "preflight": str(activation.get("preflight_status") or activation.get("status") or adapter.get("status") or "unknown")
                if isinstance(adapter, dict)
                else "unknown",
                "blockers": ", ".join(str(blocker.get("control", "unknown")) for blocker in blockers[:4]) if blockers else "none",
            }
        )
    return rows


def _backend_preflight_summary(gap: dict[str, Any]) -> str:
    rows = _backend_preflight_rows(gap)
    return "; ".join(f"{row['backend']}:{row['preflight']}{' blockers ' + row['blockers'] if row['blockers'] != 'none' else ''}" for row in rows[:4]) or "none"


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


def _queue_rows(orchestrator: Any, *, limit: int, session_id: str | None, statuses: set[str]) -> list[dict[str, Any]]:
    rows = orchestrator.store.list_tasks(limit=1000, session_id=session_id)
    active_rows = [row for row in rows if str(row.get("status") or "") in statuses]
    return active_rows[: max(0, limit)]


def _normalize_queue_status(status: str) -> str:
    normalized = status.strip().lower().replace("-", "_")
    if normalized == "waiting":
        return "waiting_approval"
    return normalized


def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _queue_task_row(orchestrator: Any, row: dict[str, Any]) -> dict[str, Any]:
    task_id = str(row.get("id") or "")
    status = str(row.get("status") or "")
    session_label = ""
    if row.get("session_id"):
        try:
            session = orchestrator.status(task_id).get("session")
        except KeyError:
            session = None
        if isinstance(session, dict):
            session_label = f"{_short_id(session.get('id', row.get('session_id', '')))} {session.get('title') or ''}".strip()
        else:
            session_label = _short_id(row.get("session_id", ""))
    checkpoint = _row_checkpoint(row)
    approval_id = checkpoint.get("approval_id")
    next_actions: list[str] = []
    if approval_id and status == "waiting_approval":
        next_actions.extend([f"approval {approval_id}", f"approve {approval_id}", f"resume {task_id}"])
    elif status in {"waiting_approval", "paused"}:
        next_actions.append(f"resume {task_id}")
    if status in set(ACTIVE_WORK_STATUSES_TUI) - {"paused"}:
        next_actions.append(f"pause {task_id}")
    if status in set(ACTIVE_WORK_STATUSES_TUI):
        next_actions.append(f"busy interrupt {task_id}")
    next_actions.extend([f"events {task_id}", f"timeline {task_id}"])
    return {
        "id": task_id,
        "short_id": _short_id(task_id),
        "status": status,
        "risk_level": row.get("risk_level", ""),
        "session_label": session_label,
        "next_actions": "; ".join(next_actions[:5]),
        "updated_at": row.get("updated_at", ""),
    }


def _row_checkpoint(row: dict[str, Any]) -> dict[str, Any]:
    checkpoint = row.get("checkpoint")
    if isinstance(checkpoint, dict):
        return checkpoint
    checkpoint_json = row.get("checkpoint_json")
    if isinstance(checkpoint_json, str) and checkpoint_json:
        try:
            decoded = json.loads(checkpoint_json)
        except json.JSONDecodeError:
            return {}
        return decoded if isinstance(decoded, dict) else {}
    return {}


def _default_busy_task_id(orchestrator: Any, *, session_id: str | None) -> str | None:
    session_rows = _queue_rows(orchestrator, limit=1, session_id=session_id, statuses=set(ACTIVE_WORK_STATUSES_TUI)) if session_id else []
    rows = session_rows or _queue_rows(orchestrator, limit=1, session_id=None, statuses=set(ACTIVE_WORK_STATUSES_TUI))
    if not rows:
        return None
    return str(rows[0].get("id") or "") or None


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
    request_payload = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
    payload["action_hints"] = approval_action_hints(
        payload,
        task_id=task_id,
        session_id=payload.get("session_id"),
        admin_required=bool(request_payload.get("admin_required")) if isinstance(request_payload, dict) else False,
    )
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
    action_hints = payload.get("action_hints", [])
    other_commands = [
        str(hint.get("command"))
        for hint in action_hints
        if isinstance(hint, dict) and hint.get("command") and not str(hint.get("action", "")).startswith("session_")
    ]
    session = payload.get("session")
    if isinstance(session, dict):
        session_label = f"{_short_id(session.get('id', payload.get('session_id', '')))} {session.get('title') or ''}".strip()
    elif payload.get("session_id"):
        session_label = _short_id(payload.get("session_id"))
    session_commands: list[str] = []
    if payload.get("session_id"):
        session_id = str(payload["session_id"])
        session_commands = [f"session open {session_id}", f"session history {session_id}"]
    commands = [*session_commands, *other_commands]
    next_actions = "; ".join(commands[:4]) or f"approval {payload.get('id')}"
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


def _comma_separated(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _optional_int(value: str | None) -> int | None:
    if value is None or not str(value).strip():
        return None
    return int(value)


def _split_json_approval_arg(value: str) -> tuple[str, str | None]:
    marker = " --approval-id "
    if marker not in value:
        return value, None
    json_text, approval_id = value.rsplit(marker, 1)
    return json_text.strip(), approval_id.strip() or None


def _split_approval_arg(value: str) -> tuple[str, str | None]:
    marker = " --approval-id "
    if marker not in value:
        return value, None
    text, approval_id = value.rsplit(marker, 1)
    return text.strip(), approval_id.strip() or None


def _browser_action_approval(
    orchestrator: Any,
    *,
    action: str,
    session_id: str,
    selector: str | None = None,
    fields: dict[str, Any] | None = None,
    url: str | None = None,
    file_path: str | None = None,
    script: str | None = None,
    approval_id: str | None = None,
) -> dict[str, Any]:
    payload = orchestrator.browser.action_approval_payload(action=action, session_id=session_id, selector=selector, fields=fields, url=url, file_path=file_path, script=script)
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


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def _paint(text: str, code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _paint_prompt(text: str, code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\001\033[{code}m\002{text}\001\033[0m\002"


def _strip_readline_markers(text: str) -> str:
    return text.replace("\001", "").replace("\002", "")


def _visible_length(text: str) -> int:
    return len(ANSI_PATTERN.sub("", _strip_readline_markers(text)))
