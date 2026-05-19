"""Curses-backed prompt-first TUI surface for Aegis Agent."""

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
    menu: str = ""


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


def build_interactive_panels(tui: Any, *, active_menu: str | None = None) -> tuple[InteractivePanel, ...]:
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
        InteractiveItem("Overview", "Return to the overview deck and run the full posture dashboard.", "dashboard", "active", "overview"),
        InteractiveItem("Tasks", "Open task actions and recent active-session work.", "", "", "tasks"),
        InteractiveItem("Approvals", "Open approval gates and decision actions.", "", str(pending), "approvals"),
        InteractiveItem("Memory", "Open governed memory actions.", "", "", "memory"),
        InteractiveItem("Tools", "Open governed tool runtime actions.", "", "", "tools"),
        InteractiveItem("Logs", "Open audit and evidence actions.", "", "", "logs"),
        InteractiveItem("Setup", "Open guided setup mission control.", "", "", "setup"),
    )
    command_items = (
        InteractiveItem("/setup next", "Open the first setup step that still needs operator action.", "setup next"),
        InteractiveItem("menu setup", "Open the hidden setup lane.", "menu setup", "", "setup"),
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
    menu_title = "SETUP TOUR"
    menu_items = tuple(setup_items)
    if active_menu and active_menu != "overview":
        menu_title, menu_items = _submenu_panel(
            active_menu,
            active_items=active_items,
            setup_items=tuple(setup_items),
            approval_items=approval_items,
            tool_items=tool_items,
            memory_items=memory_items,
            policy_items=policy_items,
            command_items=command_items,
        )
    return (
        InteractivePanel("nav", "AGENT STATUS", nav_items),
        InteractivePanel("active", "ACTIVE TASK", active_items),
        InteractivePanel("setup", menu_title, menu_items),
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
        self.input_buffer = ""
        self.cursor = 0
        self.history: list[str] = []
        self.history_index: int | None = None
        self.palette_index = 0
        self.should_exit = False
        self._last_palette_top = 0
        self._last_palette_rows = 0
        self.output_lines: list[str] = [
            "Aegis Agent ready.",
            "Type a request and press Enter, or type / to open slash commands.",
            "Hermes-style mode: same sessions, same slash commands, prompt-first surface.",
        ]
        self.message = "Enter send | / commands | Tab complete | Up/Down history or palette | Esc clear/exit"

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
        while not self.should_exit:
            self._render()
            key = self.stdscr.getch()
            if key in (3, 4):
                return
            if key == 27:
                if self.input_buffer:
                    self.input_buffer = ""
                    self.cursor = 0
                    self.palette_index = 0
                    self.message = "Input cleared."
                    continue
                return
            if key in (10, 13, self.curses.KEY_ENTER):
                self._submit_input()
                continue
            if key == self.curses.KEY_LEFT:
                self.cursor = max(0, self.cursor - 1)
                continue
            if key == self.curses.KEY_RIGHT:
                self.cursor = min(len(self.input_buffer), self.cursor + 1)
                continue
            if key in (self.curses.KEY_HOME, 1):
                self.cursor = 0
                continue
            if key in (self.curses.KEY_END, 5):
                self.cursor = len(self.input_buffer)
                continue
            if key in (self.curses.KEY_BACKSPACE, 127, 8):
                if self.cursor > 0:
                    self.input_buffer = self.input_buffer[: self.cursor - 1] + self.input_buffer[self.cursor :]
                    self.cursor -= 1
                    self.palette_index = 0
                continue
            if key == 21:
                self.input_buffer = ""
                self.cursor = 0
                self.palette_index = 0
                continue
            if key in (self.curses.KEY_UP, self.curses.KEY_DOWN):
                self._move_history_or_palette(-1 if key == self.curses.KEY_UP else 1)
                continue
            if key in (9, getattr(self.curses, "KEY_BTAB", -999999)):
                self._complete_palette()
                continue
            if key in (12,):
                self.message = "Redrew screen."
                continue
            if key == self.curses.KEY_MOUSE:
                self._handle_mouse()
                continue
            if 32 <= key <= 126:
                self._insert(chr(key))

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

    def _render(self) -> None:
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        header_lines = self._logo_lines(width)
        header_h = min(len(header_lines) + 1, max(4, min(12, height - 8)))
        for row, line in enumerate(header_lines[: max(1, header_h - 1)]):
            self._add(row, 0, self._clip(line, width - 1), self._pair(1 if row % 2 == 0 else 2) | self.curses.A_BOLD)
        self._draw_status_line(max(1, header_h - 1), width)
        palette = self._palette_candidates()
        palette_h = min(len(palette), max(0, height // 4)) if self.input_buffer.startswith("/") else 0
        prompt_y = max(header_h + 4, height - 3)
        palette_y = max(header_h + 1, prompt_y - palette_h - 1)
        output_bottom = max(header_h + 1, palette_y - 1 if palette_h else prompt_y - 1)
        self._draw_output(header_h, output_bottom, width)
        if palette_h:
            self._draw_palette(palette, palette_y, prompt_y - 1, width)
            self._last_palette_top = palette_y
            self._last_palette_rows = palette_h
        else:
            self._last_palette_top = 0
            self._last_palette_rows = 0
        self._draw_prompt(prompt_y, width)
        self._draw_footer(height, width)
        self.stdscr.refresh()

    def _logo_lines(self, width: int) -> list[str]:
        try:
            from aegis.tui.main import AEGIS_AGENT_WORDMARK, AEGIS_COMPACT_WORDMARK, SHIELD_FRAMES
        except ImportError:
            return ["AEGIS AGENT", "local-first governed runtime", "/ opens slash commands"]
        if width >= 112:
            wordmark = list(AEGIS_AGENT_WORDMARK)
        elif width >= 58:
            wordmark = list(AEGIS_COMPACT_WORDMARK)
        else:
            wordmark = ["AEGIS AGENT", "local-first governed runtime"]
        frame_name, frame_detail, frame_art = SHIELD_FRAMES[0]
        if width < 58:
            return [f"AEGIS SHIELD [{frame_name}]", *wordmark, "type / for commands"]
        return [
            f"AEGIS SHIELD :: local-first governed runtime :: {frame_name} :: {frame_detail}",
            *wordmark,
            *frame_art[:2],
            "COMMAND BUS :: plain request  //  / slash palette  //  Tab complete",
        ]

    def _draw_status_line(self, y: int, width: int) -> None:
        session = self.tui.session
        dashboard = build_product_dashboard(self.tui.orchestrator)
        runtime = dashboard["runtime"]
        status = "ready"
        if int(runtime.get("active_work_count") or 0):
            status = "running"
        elif int(runtime.get("pending_approvals") or 0):
            status = "approval"
        cells = [
            status,
            f"session {_short_id(session.get('id'))}",
            f"model {session.get('model') or 'alias/smart'}",
            f"cwd {self.tui.workspace.name}",
            f"approvals {runtime.get('pending_approvals', 0)}",
        ]
        self._add(y, 0, self._clip(" | ".join(cells), width - 1), self._pair(7) | self.curses.A_BOLD)

    def _draw_output(self, top: int, bottom: int, width: int) -> None:
        if bottom <= top:
            return
        visible_height = max(1, bottom - top)
        wrapped = _wrap_lines(self.output_lines, width - 2)
        visible = wrapped[-visible_height:]
        y = top
        for line in visible:
            self._add(y, 1, self._clip(line, width - 2), self._pair(4))
            y += 1

    def _draw_palette(self, palette: list[tuple[str, str]], top: int, bottom: int, width: int) -> None:
        self._add(top, 0, self._clip(" slash commands ", width - 1), self._pair(2) | self.curses.A_BOLD)
        rows = palette[: max(0, bottom - top)]
        for offset, (command, detail) in enumerate(rows, start=1):
            attr = self._pair(3) | self.curses.A_BOLD if offset - 1 == self.palette_index else self._pair(4)
            line = f"{command:<24} {detail}"
            self._add(top + offset, 1, self._clip(line, width - 2), attr)

    def _draw_footer(self, height: int, width: int) -> None:
        self._add(height - 2, 0, " " * (width - 1), self._pair(7))
        self._add(height - 2, 1, self._clip(self.message, width - 2), self._pair(7))

    def _draw_prompt(self, y: int, width: int) -> None:
        prompt = "aegis> "
        self._add(y, 0, " " * (width - 1), self._pair(1))
        self._add(y, 0, self._clip(prompt + self.input_buffer, width - 1), self._pair(1) | self.curses.A_BOLD)
        cursor_x = min(width - 2, len(prompt) + self.cursor)
        try:
            self.curses.curs_set(1)
            self.stdscr.move(y, cursor_x)
        except Exception:
            pass

    def _insert(self, text: str) -> None:
        self.input_buffer = self.input_buffer[: self.cursor] + text + self.input_buffer[self.cursor :]
        self.cursor += len(text)
        self.palette_index = 0
        self.history_index = None

    def _submit_input(self) -> None:
        command = self.input_buffer.strip()
        if not command:
            self.message = "Type a request or /command."
            return
        if command.startswith("/"):
            palette = self._palette_candidates()
            if palette and (command == "/" or not any(command == candidate for candidate, _detail in palette)):
                command = palette[min(self.palette_index, len(palette) - 1)][0]
        self.history.append(command)
        self.history_index = None
        self.input_buffer = ""
        self.cursor = 0
        self.palette_index = 0
        self._run_command(command)

    def _move_history_or_palette(self, delta: int) -> None:
        palette = self._palette_candidates()
        if self.input_buffer.startswith("/") and palette:
            self.palette_index = max(0, min(len(palette) - 1, self.palette_index + delta))
            self.message = f"Highlighted {palette[self.palette_index][0]}; Tab accepts it."
            return
        if not self.history:
            return
        if self.history_index is None:
            self.history_index = len(self.history) if delta < 0 else len(self.history) - 1
        self.history_index = max(0, min(len(self.history) - 1, self.history_index + delta))
        self.input_buffer = self.history[self.history_index]
        self.cursor = len(self.input_buffer)

    def _complete_palette(self) -> None:
        palette = self._palette_candidates()
        if not palette:
            self.message = "No slash command matches."
            return
        command = palette[min(self.palette_index, len(palette) - 1)][0]
        self.input_buffer = command + (" " if " " not in command else "")
        self.cursor = len(self.input_buffer)
        self.message = f"Completed {command}; add args or press Enter."

    def _palette_candidates(self) -> list[tuple[str, str]]:
        if not self.input_buffer.startswith("/"):
            return []
        return slash_palette_candidates(self.input_buffer)

    def _handle_mouse(self) -> None:
        try:
            _mouse_id, _x, y, _z, _state = self.curses.getmouse()
        except Exception:
            return
        palette = self._palette_candidates()
        if not palette:
            return
        height, _width = self.stdscr.getmaxyx()
        if not height:
            return
        if self._last_palette_top <= y <= self._last_palette_top + self._last_palette_rows:
            index = y - self._last_palette_top - 1
            if index < 0:
                return
            index = max(0, min(len(palette) - 1, index))
            self.palette_index = index
            self._complete_palette()

    def _run_command(self, command: str) -> None:
        normalized = normalize_interactive_command(command)
        if not normalized:
            return
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                should_stop = bool(self.tui.onecmd(normalized))
        except Exception as exc:  # noqa: BLE001 - interactive shell should stay alive.
            self.output_lines = [f"Command failed: {exc}"]
            self.message = f"Command failed: {normalized}"
            return
        text = output.getvalue().strip()
        self.output_lines = [f"$ {normalized}", ""] + (text.splitlines()[:238] if text else ["Command completed."])
        self.message = f"Opened: {normalized}"
        if should_stop:
            self.should_exit = True

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


def _submenu_panel(
    active_menu: str,
    *,
    active_items: tuple[InteractiveItem, ...],
    setup_items: tuple[InteractiveItem, ...],
    approval_items: tuple[InteractiveItem, ...],
    tool_items: tuple[InteractiveItem, ...],
    memory_items: tuple[InteractiveItem, ...],
    policy_items: tuple[InteractiveItem, ...],
    command_items: tuple[InteractiveItem, ...],
) -> tuple[str, tuple[InteractiveItem, ...]]:
    back = InteractiveItem("Back to overview", "Return to the main overview deck.", "", "", "overview")
    menu = active_menu.lower().replace("_", "-")
    if menu == "tasks":
        items = (
            InteractiveItem("Recent tasks", "Show current-session tasks.", "tasks"),
            InteractiveItem("Task queue", "Show active work without raw requests.", "queue"),
            InteractiveItem("Submit task", "Open task submission syntax and command hints.", "submit"),
            *active_items,
        )
        return "TASKS MENU", (back, *items)
    if menu == "approvals":
        items = (
            InteractiveItem("Approval queue", "Show pending approvals and action hints.", "approvals"),
            InteractiveItem("Policy posture", "Open security posture before deciding.", "security"),
            *approval_items,
        )
        return "APPROVALS MENU", (back, *items)
    if menu == "memory":
        items = (
            *memory_items,
            InteractiveItem("Search memory", "Search governed memories.", "memory search"),
            InteractiveItem("Create memory", "Show memory create syntax.", "memory"),
        )
        return "MEMORY MENU", (back, *items)
    if menu == "tools":
        items = (
            *tool_items,
            InteractiveItem("Toolsets", "Show grouped runtime toolsets.", "toolsets"),
            InteractiveItem("Sandbox", "Show sandbox/backend posture.", "sandbox"),
        )
        return "TOOLS MENU", (back, *items)
    if menu == "logs":
        items = (
            InteractiveItem("Audit log", "Show recent audit receipts.", "audit"),
            InteractiveItem("Verify audit", "Verify receipt hash-chain posture.", "audit verify"),
            InteractiveItem("Evidence", "Open evidence for the latest task.", "evidence"),
            InteractiveItem("Timeline", "Open timeline for the latest task.", "timeline"),
            InteractiveItem("Events", "Open events for the latest task.", "events"),
        )
        return "LOGS MENU", (back, *items)
    if menu == "policy":
        return "POLICY MENU", (back, *policy_items)
    if menu == "commands":
        return "COMMAND MENU", (back, *command_items)
    items = (
        InteractiveItem("Guided next step", "Open the first setup step that still needs operator action.", "setup next"),
        InteractiveItem("Setup lane", "Render the hidden setup lane.", "menu setup"),
        *setup_items,
    )
    return "SETUP MENU", (back, *items)


def normalize_interactive_command(command: str) -> str:
    """Normalize command input while preserving slash-command dispatch."""
    stripped = command.strip()
    if stripped.startswith("//"):
        return "/" + stripped.lstrip("/")
    return stripped


def slash_palette_candidates(buffer: str, *, limit: int = 12) -> list[tuple[str, str]]:
    """Return slash-command palette candidates for the live composer."""
    stripped = buffer.lstrip()
    if not stripped.startswith("/"):
        return []
    try:
        from aegis.tui.main import _apply_live_completion, _complete_slash, _live_completion_context, _slash_completion_description
    except ImportError:
        return _fallback_slash_candidates(stripped, limit=limit)
    text, begidx, endidx = _live_completion_context(stripped)
    labels = _complete_slash(text, stripped, begidx, endidx)
    if not labels:
        return _fallback_slash_candidates(stripped, limit=limit)
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label in labels:
        command = _apply_live_completion(stripped, label, begidx, endidx)
        if not command.startswith("/"):
            command = f"/{command}"
        if command in seen:
            continue
        seen.add(command)
        root = command.split(maxsplit=1)[0]
        candidates.append((command, _slash_completion_description(root)))
        if len(candidates) >= limit:
            break
    return candidates


def _fallback_slash_candidates(buffer: str, *, limit: int) -> list[tuple[str, str]]:
    prefix = buffer.strip().lower()
    fallback = (
        ("/help", "full command reference"),
        ("/dashboard", "full posture dashboard"),
        ("/tasks", "recent tasks"),
        ("/approvals", "pending approvals"),
        ("/setup", "guided setup checklist"),
        ("/setup next", "first unfinished setup step"),
        ("/tools", "tool catalog"),
        ("/memory", "governed memory commands"),
        ("/models", "model routes"),
        ("/quit", "exit"),
    )
    return [entry for entry in fallback if entry[0].startswith(prefix)][:limit]


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
