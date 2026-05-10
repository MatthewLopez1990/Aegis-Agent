"""Execution engine that taints connector output before use."""

from __future__ import annotations

from aegis.agent.planner import PlanStep
from aegis.agent.tool_router import ToolRouter
from aegis.connectors.base import ConnectorResult
from aegis.security.context_firewall import ContextFirewall, FirewallResult
from aegis.security.taint import TrustClass


class ExecutionEngine:
    def __init__(self, router: ToolRouter, firewall: ContextFirewall) -> None:
        self.router = router
        self.firewall = firewall

    def execute(self, step: PlanStep, *, approved: bool = False, task_id: str | None = None) -> tuple[ConnectorResult, FirewallResult]:
        result = self.router.route(step, approved=approved, task_id=task_id)
        item = self.firewall.label_content(
            str(result.data),
            source=f"{result.connector}:{result.operation}",
            trust_class=TrustClass.TOOL_OUTPUT if result.connector != "none" else TrustClass.DEVELOPER_TRUSTED,
            connector_or_tool=result.connector,
        )
        firewall_result = self.firewall.process([item])
        return result, firewall_result
