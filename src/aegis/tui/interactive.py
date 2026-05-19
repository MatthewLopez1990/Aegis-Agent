"""Curses-backed selectable TUI surface for Aegis Agent."""

from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import dataclass
from typing import Any
import io
import os
import sys
import textwrap

from aegis.product.capabilities import build_product_dashboard
from aegis.product.setup import build_setup_readiness


@dataclass(frozen=True)
class InteractiveItem:
    label: str
    detail: str
    command: str = ""
    status: str = ""


@dataclass(frozen=True)
class InteractivePanel:
    panel_id: str
    title: str
    items: tuple[InteractiveItem, ...]


@dataclass(frozen=True)
class PanelBounds:
    panel_id: str
    y: int
    x: int
    h: int
    w: int


def build_interactive_panels(tui: Any) -> tuple[InteractivePanel, ...]:
    """Build the selectable panel model without importing curses."""
    dashboard = build_product_dashboard(tui.orchestrator)
    runtime = dashboard["runtime"]
    readiness = build_setup_readiness(tui.orchestrator, config_path=tui.orchestrator.config.data_dir / "config.toml")
    setup_steps = tuple(step for step in readiness.get("setup_steps", []) if isinstance(step, dict))
    priority_step = _priority_setup_step(setup_steps)
    pending = int(runtime.get("pending_approvals") or 0)
    audit_ok = bool(runtime.get("audit_chain_ok"))
    active_rows = tuple(row for row in dashboard.get("active_work_tasks", []) if isinstance(row, dict))
    active_task = active_rows[0] if active_rows else None

    nav_items = (
        InteractiveItem("Overview", "Open the full posture dashboard.", "dashboard", "active"),
        InteractiveItem("Tasks", "Review recent active-session tasks.", "tasks"),
        InteractiveItem("Approvals", "Review pending approval gates.", "approvals", str(pending)),
        InteractiveItem("Memory", "Open governed memory commands.", "memory health"),
        InteractiveItem("Tools", "List governed tool catalog entries.", "tools list"),
        InteractiveItem("Logs", "Tail audit receipts.", "audit"),
        InteractiveItem("Setup", "Open guided setup mission control.", "setup"),
    )
    command_items = (
        InteractiveItem("/setup next", "Open the first setup step that still needs operator action.", "setup next"),
        InteractiveItem("menu setup", "Open the hidden setup lane.", "menu setup"),
        InteractiveItem("/tasks", "Recent tasks in the current session.", "tasks"),
        InteractiveItem("/approvals", "Pending gates and decision hints.", "approvals"),
        InteractiveItem("/tools", "Tool runtime and governance posture.", "tools list"),
        InteractiveItem("/dashboard", "Full dashboard render.", "dashboard"),
    )
    if active_task:
        active_items = (
            InteractiveItem(
                str(active_task.get("request_summary") or active_task.get("title") or "Active task"),
                "Open task status and command hints.",
                f"status {active_task.get('id')}",
                str(active_task.get("status") or "unknown"),
            ),
            InteractiveItem("Events", "Show grouped run-event progress.", f"events {active_task.get('id')}"),
            InteractiveItem("Timeline", "Show plan, receipts, and audit sequence.", f"timeline {active_task.get('id')}"),
        )
    elif priority_step:
        route = _setup_route(str(priority_step.get("id") or ""))
        active_items = (
            InteractiveItem(
                f"Setup: {priority_step.get('label')}",
                str(priority_step.get("detail") or "Open the guided setup step."),
                f"setup {route}",
                str(priority_step.get("state") or "unknown"),
            ),
            InteractiveItem("/setup next", "Open this first unfinished setup step.", "setup next"),
            InteractiveItem(str(priority_step.get("command") or "setup"), "Suggested first command for this setup lane."),
        )
    else:
        active_items = (
            InteractiveItem("Standing by", "Submit plain text or choose a command to begin governed work."),
            InteractiveItem("/setup verify", "Run the setup verification checklist.", "setup verify"),
        )

    setup_items = []
    for index, step in enumerate(setup_steps, start=1):
        route = _setup_route(str(step.get("id") or ""))
        marker = ">> " if priority_step is step else ""
        setup_items.append(
            InteractiveItem(
                f"{marker}{index}. {step.get('label')}",
                str(step.get("detail") or "Open setup submenu."),
                f"setup {route}",
                str(step.get("state") or "unknown"),
            )
        )
    setup_items.append(InteractiveItem("Verify setup", "Open post-setup verification commands.", "setup verify"))
    setup_items.append(InteractiveItem("Raw packet", "Show machine-readable readiness packet.", "setup json"))

    risk_label = "LOW RISK" if audit_ok and pending == 0 else "REVIEW"
    policy_items = (
        InteractiveItem("Core runtime", "Governed local runtime posture.", "security", risk_label),
        InteractiveItem("Compliance", "Policy and approval posture.", "security", "98%" if audit_ok else "66%"),
        InteractiveItem("Integrity", "Audit chain and receipt integrity.", "audit verify", "97%" if audit_ok else "72%"),
        InteractiveItem("Availability", "Local runtime readiness.", "doctor", "99%"),
    )
    approvals = tuple(row for row in dashboard.get("pending_approvals", []) if isinstance(row, dict))
    approval_items = tuple(
        InteractiveItem(
            str(approval.get("summary") or approval.get("action") or "Approval"),
            "Inspect this approval before deciding.",
            f"approval {approval.get('id')}",
            str(approval.get("risk") or approval.get("risk_level") or "review"),
        )
        for approval in approvals[:6]
    ) or (InteractiveItem("No pending approvals", "A gate will appear here before risky work can continue.", "approvals", "clear"),)
    tool_items = (
        InteractiveItem("Catalog", "Governed tool catalog count.", "tools list", str(runtime.get("tools", 0))),
        InteractiveItem("Approval gates", "Tools that require operator approval.", "toolsets", str(runtime.get("approval_gated_tools", 0))),
        InteractiveItem("Channels", "Channel adapter inventory.", "channels", str(runtime.get("channels", 0))),
        InteractiveItem("Providers", "Model provider routes.", "models list", str(runtime.get("model_providers", 0))),
    )
    memory_items = (
        InteractiveItem("Facts", "Stored governed memories.", "memory search", str(runtime.get("memories", 0))),
        InteractiveItem("Health", "Memory quality and review posture.", "memory health", str(runtime.get("memory_health_score", 0))),
        InteractiveItem("Review", "Open memory review recommendations.", "memory review-queue", str(runtime.get("memory_review_recommendations", 0))),
    )
    return (
        InteractivePanel("nav", "AGENT STATUS", nav_items),
        InteractivePanel("active", "ACTIVE TASK", active_items),
        InteractivePanel("setup", "SETUP TOUR", tuple(setup_items)),
        InteractivePanel("policy", "POLICY POSTURE", policy_items),
        InteractivePanel("approvals", f"APPROVALS ({pending})", approval_items),
        InteractivePanel("tools", "TOOL RUNTIME", tool_items),
        InteractivePanel("memory", "MEMORY", memory_items),
        InteractivePanel("commands", "COMMANDS", command_items),
    )


def run_interactive_tui(tui: Any) -> bool:
    if os.environ.get("AEGIS_TUI_CLASSIC"):
        return False
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    try:
        import curses
    except ImportError:
        return False
    curses.wrapper(lambda stdscr: _CursesAegisDeck(stdscr, tui, curses).run())
    return True


class _CursesAegisDeck:
    def __init__(self, stdscr: Any, tui: Any, curses_module: Any) -> None:
        self.stdscr = stdscr
        self.tui = tui
        self.curses = curses_module
        self.focus_index = 0
        self.selected: dict[str, int] = {}
        self.output_lines: list[str] = ["Select a panel item and press Enter. Press / to run a command."]
        self.message = "Tab/Left/Right focus panels  Up/Down select  Enter open  / command  r refresh  q quit"
        self.bounds: list[PanelBounds] = []

    def run(self) -> None:
        try:
            self.curses.curs_set(0)
        except Exception:
            pass
        self.stdscr.keypad(True)
        self.stdscr.nodelay(False)
        self._init_colors()
        try:
            self.curses.mousemask(self.curses.ALL_MOUSE_EVENTS)
        except Exception:
            pass
        while True:
            panels = list(build_interactive_panels(self.tui))
            focusable = [panel.panel_id for panel in panels if panel.items]
            if self.focus_index >= len(focusable):
                self.focus_index = 0
            self._render(panels, focusable)
            key = self.stdscr.getch()
            if key in (ord("q"), ord("Q"), 27):
                return
            if key in (self.curses.KEY_RIGHT, 9):
                self.focus_index = (self.focus_index + 1) % max(1, len(focusable))
                continue
            if key in (self.curses.KEY_LEFT, getattr(self.curses, "KEY_BTAB", -999999)):
                self.focus_index = (self.focus_index - 1) % max(1, len(focusable))
                continue
            if key == self.curses.KEY_UP:
                self._move_selection(panels, focusable, -1)
                continue
            if key == self.curses.KEY_DOWN:
                self._move_selection(panels, focusable, 1)
                continue
            if key in (10, 13, self.curses.KEY_ENTER):
                self._activate_selected(panels, focusable)
                continue
            if key in (ord("/"), ord(":")):
                command = self._prompt("/")
                if command:
                    self._run_command(command)
                continue
            if key in (ord("r"), ord("R")):
                self.message = "Refreshed runtime posture."
                continue
            if key in (ord("?"),):
                self.output_lines = [
                    "Keyboard",
                    "Tab or Right: next panel",
                    "Left: previous panel",
                    "Up/Down: select within the focused panel",
                    "Enter: open selected command or detail",
                    "/: run any Aegis TUI command",
                    "q or Esc: exit to shell",
                ]
                continue
            if key == self.curses.KEY_MOUSE:
                self._handle_mouse(panels, focusable)

    def _init_colors(self) -> None:
        if not self.curses.has_colors():
            return
        self.curses.start_color()
        self.curses.use_default_colors()
        pairs = (
            (1, self.curses.COLOR_CYAN, -1),
            (2, self.curses.COLOR_MAGENTA, -1),
            (3, self.curses.COLOR_BLACK, self.curses.COLOR_CYAN),
            (4, self.curses.COLOR_WHITE, -1),
            (5, self.curses.COLOR_YELLOW, -1),
            (6, self.curses.COLOR_GREEN, -1),
            (7, self.curses.COLOR_BLACK, self.curses.COLOR_MAGENTA),
        )
        for pair, fg, bg in pairs:
            try:
                self.curses.init_pair(pair, fg, bg)
            except Exception:
                pass

    def _render(self, panels: list[InteractivePanel], focusable: list[str]) -> None:
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        if height < 24 or width < 80:
            self._render_small(panels, focusable, height, width)
            self.stdscr.refresh()
            return
        self._draw_header(width)
        self.bounds = self._layout_bounds(height, width)
        panel_by_id = {panel.panel_id: panel for panel in panels}
        focused_id = focusable[self.focus_index] if focusable else ""
        for bound in self.bounds:
            panel = panel_by_id.get(bound.panel_id)
            if panel is None:
                continue
            self._draw_panel(bound, panel, focused=bound.panel_id == focused_id)
        detail_bound = self._detail_bounds(height, width)
        self._draw_detail(detail_bound, panels, focused_id)
        self._draw_footer(height, width)
        self.stdscr.refresh()

    def _draw_header(self, width: int) -> None:
        session = self.tui.session
        title = " AEGIS-AGENT "
        meta = f"session {_short_id(session.get('id'))} | model {session.get('model') or 'alias/smart'} | /setup next"
        self._add(0, 0, " " * (width - 1), self._pair(7) | self.curses.A_BOLD)
        self._add(0, 2, title, self._pair(7) | self.curses.A_BOLD)
        self._add(0, max(2, width - len(meta) - 2), meta[: max(0, width - 4)], self._pair(7))
        tabs = " [OVERVIEW]  Tasks  Approvals  Memory  Tools  Logs  Setup "
        self._add(1, 1, tabs[: width - 2], self._pair(1) | self.curses.A_BOLD)

    def _layout_bounds(self, height: int, width: int) -> list[PanelBounds]:
        body_y = 3
        body_h = max(8, height - 6)
        if width < 104:
            left_w = 22
            right_w = 27
        else:
            left_w = 26
            right_w = 31
        center_w = max(28, width - left_w - right_w - 4)
        left_x = 0
        center_x = left_w + 1
        right_x = center_x + center_w + 1
        left_nav_h = min(11, body_h // 2)
        left_cmd_h = body_h - left_nav_h
        center_active_h = min(8, max(6, body_h // 3))
        center_setup_h = min(9, max(7, body_h // 3))
        right_policy_h = 5 if body_h < 22 else 6
        right_approval_h = min(6, max(5, body_h // 4))
        right_tools_h = min(6, max(5, body_h // 4))
        right_memory_h = body_h - right_policy_h - right_approval_h - right_tools_h
        return [
            PanelBounds("nav", body_y, left_x, left_nav_h, left_w),
            PanelBounds("commands", body_y + left_nav_h, left_x, left_cmd_h, left_w),
            PanelBounds("active", body_y, center_x, center_active_h, center_w),
            PanelBounds("setup", body_y + center_active_h, center_x, center_setup_h, center_w),
            PanelBounds("policy", body_y, right_x, right_policy_h, right_w),
            PanelBounds("approvals", body_y + right_policy_h, right_x, right_approval_h, right_w),
            PanelBounds("tools", body_y + right_policy_h + right_approval_h, right_x, right_tools_h, right_w),
            PanelBounds("memory", body_y + right_policy_h + right_approval_h + right_tools_h, right_x, max(3, right_memory_h), right_w),
        ]

    def _detail_bounds(self, height: int, width: int) -> PanelBounds:
        body_y = 3
        body_h = max(8, height - 6)
        left_w = 22 if width < 104 else 26
        right_w = 27 if width < 104 else 31
        center_w = max(28, width - left_w - right_w - 4)
        center_x = left_w + 1
        center_active_h = min(8, max(6, body_h // 3))
        center_setup_h = min(9, max(7, body_h // 3))
        detail_y = body_y + center_active_h + center_setup_h
        return PanelBounds("details", detail_y, center_x, max(4, body_y + body_h - detail_y), center_w)

    def _draw_panel(self, bound: PanelBounds, panel: InteractivePanel, *, focused: bool) -> None:
        attr = self._pair(2 if focused else 1) | (self.curses.A_BOLD if focused else 0)
        self._box(bound, panel.title, attr)
        inner_h = max(0, bound.h - 2)
        selected = min(self.selected.get(panel.panel_id, 0), max(0, len(panel.items) - 1))
        self.selected[panel.panel_id] = selected
        start = max(0, selected - inner_h + 1)
        for row, item in enumerate(panel.items[start : start + inner_h]):
            item_index = start + row
            item_attr = self._pair(4)
            prefix = " "
            if focused and item_index == selected:
                item_attr = self._pair(3) | self.curses.A_BOLD
                prefix = ">"
            elif item.status.lower() in {"clear", "ok", "active", "low risk", "ready"}:
                item_attr = self._pair(6)
            elif item.status:
                item_attr = self._pair(5)
            status = f" [{item.status}]" if item.status else ""
            line = f"{prefix} {item.label}{status}"
            self._add(bound.y + 1 + row, bound.x + 1, self._clip(line, bound.w - 2), item_attr)

    def _draw_detail(self, bound: PanelBounds, panels: list[InteractivePanel], focused_id: str) -> None:
        self._box(bound, "DETAILS / OUTPUT", self._pair(1) | self.curses.A_BOLD)
        panel = next((candidate for candidate in panels if candidate.panel_id == focused_id), None)
        selected_item: InteractiveItem | None = None
        if panel and panel.items:
            selected_item = panel.items[min(self.selected.get(panel.panel_id, 0), len(panel.items) - 1)]
        lines: list[str] = []
        if selected_item is not None:
            command = f"command: {selected_item.command}" if selected_item.command else "command: detail only"
            lines.extend([selected_item.label, selected_item.detail, command, ""])
        lines.extend(self.output_lines)
        y = bound.y + 1
        for line in _wrap_lines(lines, bound.w - 2)[: max(0, bound.h - 2)]:
            self._add(y, bound.x + 1, self._clip(line, bound.w - 2), self._pair(4))
            y += 1

    def _render_small(self, panels: list[InteractivePanel], focusable: list[str], height: int, width: int) -> None:
        self._add(0, 0, self._clip("AEGIS-AGENT interactive compact mode", width - 1), self._pair(7) | self.curses.A_BOLD)
        focused_id = focusable[self.focus_index] if focusable else ""
        panel = next((candidate for candidate in panels if candidate.panel_id == focused_id), panels[0])
        self._add(2, 0, self._clip(panel.title, width - 1), self._pair(1) | self.curses.A_BOLD)
        selected = max(0, min(self.selected.get(panel.panel_id, 0), max(0, len(panel.items) - 1)))
        self.selected[panel.panel_id] = selected
        for index, item in enumerate(panel.items[: max(0, height - 8)]):
            attr = self._pair(3) | self.curses.A_BOLD if index == selected else self._pair(4)
            self._add(3 + index, 0, self._clip(f"{'>' if index == selected else ' '} {item.label} {item.status}", width - 1), attr)
        footer = "Tab panel | Enter open | / command | q quit"
        self._add(height - 2, 0, self._clip(footer, width - 1), self._pair(7))

    def _draw_footer(self, height: int, width: int) -> None:
        self._add(height - 2, 0, " " * (width - 1), self._pair(7))
        self._add(height - 2, 1, self._clip(self.message, width - 2), self._pair(7))

    def _move_selection(self, panels: list[InteractivePanel], focusable: list[str], delta: int) -> None:
        if not focusable:
            return
        panel_id = focusable[self.focus_index]
        panel = next((candidate for candidate in panels if candidate.panel_id == panel_id), None)
        if panel is None or not panel.items:
            return
        current = self.selected.get(panel_id, 0)
        self.selected[panel_id] = max(0, min(len(panel.items) - 1, current + delta))

    def _activate_selected(self, panels: list[InteractivePanel], focusable: list[str]) -> None:
        if not focusable:
            return
        panel_id = focusable[self.focus_index]
        panel = next((candidate for candidate in panels if candidate.panel_id == panel_id), None)
        if panel is None or not panel.items:
            return
        item = panel.items[min(self.selected.get(panel_id, 0), len(panel.items) - 1)]
        if item.command:
            self._run_command(item.command)
        else:
            self.output_lines = [item.detail]
            self.message = f"Selected {item.label}"

    def _handle_mouse(self, panels: list[InteractivePanel], focusable: list[str]) -> None:
        try:
            _mouse_id, x, y, _z, _state = self.curses.getmouse()
        except Exception:
            return
        panel_by_id = {panel.panel_id: panel for panel in panels}
        for bound in self.bounds:
            if not (bound.x <= x < bound.x + bound.w and bound.y <= y < bound.y + bound.h):
                continue
            if bound.panel_id in focusable:
                self.focus_index = focusable.index(bound.panel_id)
                row = y - bound.y - 1
                if row >= 0:
                    panel = panel_by_id.get(bound.panel_id)
                    if panel and panel.items:
                        self.selected[bound.panel_id] = max(0, min(len(panel.items) - 1, row))
            return

    def _run_command(self, command: str) -> None:
        normalized = command.strip().lstrip("/")
        if not normalized:
            return
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                self.tui.onecmd(normalized)
        except Exception as exc:  # noqa: BLE001 - interactive shell should stay alive.
            self.output_lines = [f"Command failed: {exc}"]
            self.message = f"Command failed: {normalized}"
            return
        text = output.getvalue().strip()
        self.output_lines = text.splitlines()[:240] if text else [f"Ran: {normalized}"]
        self.message = f"Opened: {normalized}"

    def _prompt(self, prefix: str) -> str:
        height, width = self.stdscr.getmaxyx()
        self._add(height - 1, 0, " " * (width - 1), self._pair(7))
        self._add(height - 1, 0, prefix, self._pair(7) | self.curses.A_BOLD)
        try:
            try:
                self.curses.curs_set(1)
            except Exception:
                pass
            self.curses.echo()
            raw = self.stdscr.getstr(height - 1, len(prefix), max(1, width - len(prefix) - 1))
        finally:
            self.curses.noecho()
            try:
                self.curses.curs_set(0)
            except Exception:
                pass
        return raw.decode("utf-8", errors="replace").strip()

    def _box(self, bound: PanelBounds, title: str, attr: int) -> None:
        if bound.h <= 1 or bound.w <= 1:
            return
        horizontal = "-" * max(0, bound.w - 2)
        self._add(bound.y, bound.x, "+" + horizontal + "+", attr)
        for row in range(1, bound.h - 1):
            self._add(bound.y + row, bound.x, "|", attr)
            self._add(bound.y + row, bound.x + bound.w - 1, "|", attr)
        self._add(bound.y + bound.h - 1, bound.x, "+" + horizontal + "+", attr)
        self._add(bound.y, bound.x + 2, self._clip(f" {title} ", bound.w - 4), attr)

    def _add(self, y: int, x: int, text: str, attr: int = 0) -> None:
        try:
            self.stdscr.addstr(y, x, text, attr)
        except Exception:
            pass

    def _clip(self, text: str, width: int) -> str:
        if width <= 0:
            return ""
        return text[:width].ljust(width)

    def _pair(self, number: int) -> int:
        try:
            return self.curses.color_pair(number)
        except Exception:
            return 0


def _priority_setup_step(steps: tuple[dict[str, Any], ...]) -> dict[str, Any] | None:
    for step in steps:
        if str(step.get("state") or "").lower() not in {"written", "ready", "ok"}:
            return step
    return None


def _setup_route(step_id: str) -> str:
    routes = {
        "initialize": "initialize",
        "model_auth": "model-auth",
        "connectors_channels": "connectors",
        "execution_backends": "backends",
        "remote_control": "remote-control",
        "interfaces": "interfaces",
    }
    return routes.get(step_id, step_id)


def _wrap_lines(lines: list[str], width: int) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        wrapped.extend(textwrap.wrap(line, width=max(10, width), replace_whitespace=False, drop_whitespace=False) or [""])
    return wrapped


def _short_id(value: object) -> str:
    return str(value or "")[:8]
