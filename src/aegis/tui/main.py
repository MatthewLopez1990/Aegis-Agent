"""Dependency-free terminal UI for Aegis Agent."""

from __future__ import annotations

from pathlib import Path
import cmd
import json

from aegis.agent.orchestrator import build_orchestrator


class AegisTui(cmd.Cmd):
    intro = "Aegis Agent TUI. Type help or ? for commands."
    prompt = "aegis> "

    def __init__(self, *, data_dir: str | Path, workspace: str | Path) -> None:
        super().__init__()
        self.orchestrator = build_orchestrator(data_dir=data_dir, workspace=workspace)
        self.last_task_id: str | None = None

    def do_submit(self, arg: str) -> None:
        """submit <request> -- submit a task."""
        request = arg.strip()
        if not request:
            print("request required")
            return
        result = self.orchestrator.submit_task(request)
        self.last_task_id = result["id"]
        print(json.dumps(_compact_task(result), indent=2, sort_keys=True))

    def do_status(self, arg: str) -> None:
        """status [task_id] -- show task status."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        print(json.dumps(self.orchestrator.status(task_id), indent=2, sort_keys=True))

    def do_resume(self, arg: str) -> None:
        """resume [task_id] -- resume after approval."""
        task_id = arg.strip() or self.last_task_id
        if not task_id:
            print("no task id")
            return
        result = self.orchestrator.resume_task(task_id)
        print(json.dumps(_compact_task(result), indent=2, sort_keys=True))

    def do_approvals(self, arg: str) -> None:
        """approvals -- list pending approvals."""
        print(json.dumps(self.orchestrator.approvals.list(status="pending"), indent=2, sort_keys=True))

    def do_approve(self, arg: str) -> None:
        """approve <approval_id> -- approve a pending action."""
        approval_id = arg.strip()
        if not approval_id:
            print("approval id required")
            return
        print(json.dumps(self.orchestrator.approvals.approve(approval_id), indent=2, sort_keys=True))

    def do_connectors(self, arg: str) -> None:
        """connectors -- list connector status."""
        print(json.dumps(self.orchestrator.connectors.status(), indent=2, sort_keys=True))

    def do_channels(self, arg: str) -> None:
        """channels -- list channel adapters."""
        print(json.dumps(self.orchestrator.channels.list_channels(), indent=2, sort_keys=True))

    def do_models(self, arg: str) -> None:
        """models -- list supported model routes."""
        print(json.dumps(self.orchestrator.models.list_models(), indent=2, sort_keys=True))

    def do_tools(self, arg: str) -> None:
        """tools -- list built-in tools."""
        print(json.dumps(self.orchestrator.tool_catalog.list(), indent=2, sort_keys=True))

    def do_sessions(self, arg: str) -> None:
        """sessions -- list sessions."""
        print(json.dumps(self.orchestrator.sessions.list_sessions(), indent=2, sort_keys=True))

    def do_audit(self, arg: str) -> None:
        """audit -- show audit tail."""
        print(json.dumps(self.orchestrator.audit_logger.tail(20), indent=2, sort_keys=True))

    def do_exit(self, arg: str) -> bool:
        """exit -- quit."""
        return True

    def do_EOF(self, arg: str) -> bool:  # noqa: N802 - cmd hook name.
        print()
        return True


def run_tui(*, data_dir: str | Path = ".aegis", workspace: str | Path = ".") -> None:
    AegisTui(data_dir=data_dir, workspace=workspace).cmdloop()


def _compact_task(task: dict[str, object]) -> dict[str, object]:
    return {
        "id": task["id"],
        "status": task["status"],
        "interpretation": task["interpretation"],
        "checkpoint": task["checkpoint"],
        "receipt_result": task["receipt"]["result"] if task.get("receipt") else None,
    }
