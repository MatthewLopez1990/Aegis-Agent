"""Dependency-free terminal UI for Aegis Agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import cmd
import json
import os
import shutil
import sys
import textwrap

from aegis.agent.orchestrator import build_orchestrator
from aegis.product.capabilities import build_product_dashboard


class AegisTui(cmd.Cmd):
    """Small but product-facing command deck built on the stdlib cmd loop."""

    def __init__(self, *, data_dir: str | Path, workspace: str | Path) -> None:
        super().__init__()
        self.orchestrator = build_orchestrator(data_dir=data_dir, workspace=workspace)
        self.last_task_id: str | None = None
        self.prompt = _paint("aegis> ", "36;1")
        self.intro = self._render_dashboard()

    def do_dashboard(self, arg: str) -> None:
        """dashboard -- show runtime, security, and capability posture."""
        print(self._render_dashboard())

    def do_submit(self, arg: str) -> None:
        """submit <request> -- submit a governed task."""
        request = arg.strip()
        if not request:
            print("request required")
            return
        result = self.orchestrator.submit_task(request)
        self.last_task_id = result["id"]
        _print_json(_compact_task(result))

    def do_status(self, arg: str) -> None:
        """status [task_id] -- show task status."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        _print_json(self.orchestrator.status(task_id))

    def do_resume(self, arg: str) -> None:
        """resume [task_id] -- resume after approval."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        result = self.orchestrator.resume_task(task_id)
        _print_json(_compact_task(result))

    def do_tasks(self, arg: str) -> None:
        """tasks -- show recent tasks."""
        rows = self.orchestrator.store.list_tasks(limit=12)
        print(
            _table(
                rows,
                (
                    ("status", "status", 18),
                    ("risk", "risk_level", 10),
                    ("request", "user_request", 46),
                    ("updated", "updated_at", 22),
                ),
            )
        )

    def do_approvals(self, arg: str) -> None:
        """approvals -- list pending approvals."""
        rows = self.orchestrator.approvals.list(status="pending")
        if not rows:
            print("no pending approvals")
            return
        print(
            _table(
                rows,
                (
                    ("id", "id", 36),
                    ("risk", "risk_level", 10),
                    ("reason", "reason", 54),
                ),
            )
        )

    def do_approve(self, arg: str) -> None:
        """approve <approval_id> -- approve a pending action."""
        approval_id = arg.strip()
        if not approval_id:
            print("approval id required")
            return
        _print_json(self.orchestrator.approvals.approve(approval_id))

    def do_deny(self, arg: str) -> None:
        """deny <approval_id> -- deny a pending action."""
        approval_id = arg.strip()
        if not approval_id:
            print("approval id required")
            return
        _print_json(self.orchestrator.approvals.deny(approval_id))

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

    def do_models(self, arg: str) -> None:
        """models -- list model providers."""
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
        """tools -- list built-in tools."""
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
        """skills -- list governed skills."""
        rows = []
        for row in self.orchestrator.skills.list():
            manifest = row["manifest"]
            rows.append(
                {
                    "id": row["id"],
                    "enabled": row["enabled"],
                    "risk_level": manifest.get("risk_level", ""),
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
                    ("name", "name", 40),
                ),
            )
        )

    def do_sessions(self, arg: str) -> None:
        """sessions -- list sessions."""
        print(
            _table(
                self.orchestrator.sessions.list_sessions(),
                (
                    ("title", "title", 32),
                    ("channel", "channel", 14),
                    ("status", "status", 12),
                    ("updated", "updated_at", 22),
                ),
            )
        )

    def do_schedules(self, arg: str) -> None:
        """schedules -- list scheduled automations."""
        print(
            _table(
                self.orchestrator.schedules.list_schedules(),
                (
                    ("name", "name", 28),
                    ("cron", "cron", 16),
                    ("status", "status", 26),
                    ("next", "next_run_at", 24),
                ),
            )
        )

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
                    ("description", "description", 54),
                ),
            )
        )

    def do_security(self, arg: str) -> None:
        """security -- show security controls."""
        dashboard = build_product_dashboard(self.orchestrator)
        print(_table(dashboard["security_controls"], (("control", "name", 24), ("state", "state", 16), ("detail", "detail", 74))))

    def do_capabilities(self, arg: str) -> None:
        """capabilities -- show product capability groups."""
        dashboard = build_product_dashboard(self.orchestrator)
        print(_table(dashboard["capability_groups"], (("capability", "name", 30), ("state", "state", 22), ("coverage", "coverage", 42), ("detail", "detail", 64))))

    def do_audit(self, arg: str) -> None:
        """audit -- show audit tail."""
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

    def do_help(self, arg: str) -> None:
        """help -- show command reference."""
        print(_command_reference())

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

    def _render_dashboard(self) -> str:
        dashboard = build_product_dashboard(self.orchestrator)
        runtime = dashboard["runtime"]
        width = min(max(shutil.get_terminal_size((100, 24)).columns, 88), 118)
        lines = [
            _banner("Aegis Agent Command Deck", width),
            _stat_line(
                (
                    ("audit", "ok" if runtime["audit_chain_ok"] else "failed"),
                    ("channels", runtime["channels"]),
                    ("tools", runtime["tools"]),
                    ("approval tools", runtime["approval_gated_tools"]),
                    ("providers", runtime["model_providers"]),
                    ("pending", runtime["pending_approvals"]),
                ),
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
                "Commands",
                [
                    "Type a plain request to submit a task.",
                    "dashboard | tasks | approvals | approve <id> | deny <id> | status [task] | resume [task]",
                    "connectors | channels | models | tools | skills | schedules | boards | backends | security | audit | exit",
                    "Slash aliases work too, for example /tasks or /submit summarize this repo.",
                ],
                width,
            ),
        ]
        return "\n".join(lines)


def run_tui(*, data_dir: str | Path = ".aegis", workspace: str | Path = ".") -> None:
    AegisTui(data_dir=data_dir, workspace=workspace).cmdloop()


def _compact_task(task: dict[str, object]) -> dict[str, object]:
    return {
        "id": task["id"],
        "status": task["status"],
        "risk_level": task["risk_level"],
        "interpretation": task["interpretation"],
        "checkpoint": task["checkpoint"],
        "receipt_result": task["receipt"]["result"] if task.get("receipt") else None,
    }


def _print_json(payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _command_reference() -> str:
    return "\n".join(
        (
            _paint("Aegis TUI Commands", "36;1"),
            "",
            "submit <request>       Submit a governed task",
            "status [task_id]       Show task state and receipt",
            "resume [task_id]       Continue after approval",
            "tasks                  Recent tasks",
            "approvals              Pending approvals",
            "approve <id>           Approve a gated action",
            "deny <id>              Deny a gated action",
            "dashboard              Runtime command deck",
            "security               Security controls",
            "capabilities           Capability groups",
            "connectors             Connector health",
            "channels               Channel adapters",
            "models                 Model providers",
            "tools                  Governed tool catalog",
            "skills                 Governed skills",
            "schedules              Scheduled automations",
            "boards                 Work boards and cards",
            "backends               Execution backends",
            "audit                  Audit tail",
            "exit                   Quit",
            "",
            "Plain text submits a task. Slash aliases such as /tasks also work.",
        )
    )


def _banner(title: str, width: int) -> str:
    inner = width - 4
    rule = "+" + "-" * (width - 2) + "+"
    text = f"| {_paint(title.ljust(inner), '36;1')} |"
    return "\n".join(("", rule, text, rule))


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


def _paint(text: str, code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"
