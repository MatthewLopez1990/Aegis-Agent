"""Agent orchestrator for durable, governed task execution."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from aegis.agent.evidence import EvidenceBundleBuilder
from aegis.agent.execution_engine import ExecutionEngine
from aegis.agent.planner import PlanStep, TaskPlanner
from aegis.agent.policy_gate import PolicyGate
from aegis.agent.state_machine import TaskStateMachine, TaskStatus
from aegis.agent.tool_router import ToolRouter, safe_connector_payload
from aegis.approvals.manager import ApprovalManager
from aegis.approvals.models import ApprovalRequest
from aegis.audit.logger import AuditLogger
from aegis.audit.receipts import ActionReceipt
from aegis.config.loader import AegisConfig, load_config
from aegis.connectors.registry import ConnectorRegistry, build_default_registry
from aegis.channels.registry import ChannelRegistry
from aegis.execution.backends import ExecutionBackendRegistry
from aegis.kanban.manager import KanbanManager
from aegis.learning.loop import LearningLoop
from aegis.memory.manager import MemoryManager
from aegis.memory.store import LocalStore
from aegis.mcp.registry import McpRegistry
from aegis.models.registry import ModelRegistry
from aegis.scheduler.manager import ScheduleManager
from aegis.security.context_firewall import ContextFirewall
from aegis.security.policy_engine import PolicyDecisionType, PolicyEngine, PolicyRequest
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import RiskLevel, Sensitivity, TrustClass
from aegis.sessions.manager import SessionManager
from aegis.skills.manifest import SkillManifest
from aegis.skills.hub import SkillHubCatalog
from aegis.skills.registry import SkillRegistry
from aegis.skills.runtime import builtin_project_summary_manifest, builtin_workflow_candidate_manifest
from aegis.tools.catalog import ToolCatalog
from aegis.tools.executor import BuiltinToolExecutor


class AgentOrchestrator:
    def __init__(
        self,
        *,
        config: AegisConfig,
        store: LocalStore,
        audit_logger: AuditLogger,
        connectors: ConnectorRegistry,
    ) -> None:
        self.config = config
        self.store = store
        self.audit_logger = audit_logger
        self.connectors = connectors
        self.firewall = ContextFirewall()
        self.planner = TaskPlanner()
        self.policy_gate = PolicyGate(PolicyEngine(network_allowlist=config.network_allowlist), audit_logger)
        self.state_machine = TaskStateMachine()
        self.router = ToolRouter(connectors, audit_logger)
        self.execution_engine = ExecutionEngine(self.router, self.firewall)
        self.approvals = ApprovalManager(store, audit_logger)
        self.memory = MemoryManager(store, audit_logger)
        self.skills = SkillRegistry(store, audit_logger)
        self.evidence = EvidenceBundleBuilder(store, audit_logger)
        self.sessions = SessionManager(store, audit_logger)
        self.channels = ChannelRegistry(store, audit_logger)
        self.models = ModelRegistry(store, audit_logger, SecretsBroker(config.secrets_path))
        self.schedules = ScheduleManager(store, audit_logger)
        self.kanban = KanbanManager(store, audit_logger)
        self.mcp = McpRegistry(store, audit_logger)
        self.tool_catalog = ToolCatalog()
        self.tools = BuiltinToolExecutor(connectors, self.memory, audit_logger, PolicyEngine(network_allowlist=config.network_allowlist))
        self.execution_backends = ExecutionBackendRegistry()
        self.skill_hub = SkillHubCatalog()
        self.learning_loop = LearningLoop()
        self._ensure_builtin_skills()

    def submit_task(self, user_request: str, *, path: str | None = None) -> dict[str, Any]:
        task_id = str(uuid4())
        directive = self.firewall.label_content(user_request, source="user", trust_class=TrustClass.USER_DIRECTIVE)
        firewall_result = self.firewall.process([directive])
        plan = self.planner.plan(user_request, path=path)

        self.store.insert_task(
            task_id=task_id,
            user_request=user_request,
            interpretation=plan.interpretation,
            status=TaskStatus.PLANNED.value,
            plan=plan.to_rows(),
            risk_level=plan.risk_level.value,
        )
        self.audit_logger.append(
            "task.created",
            {
                "user_request": user_request,
                "interpretation": plan.interpretation,
                "risk_level": plan.risk_level.value,
                "context": list(firewall_result.model_context),
            },
            task_id=task_id,
        )

        return self._run_plan(task_id, approval_state=None)

    def resume_task(self, task_id: str) -> dict[str, Any]:
        task = self._require_task(task_id)
        checkpoint = json.loads(task["checkpoint_json"])
        approval_id = checkpoint.get("approval_id")
        approval_state = None
        if approval_id:
            approval_state = self.approvals.get(approval_id)["status"]
            if approval_state == "denied":
                self._transition(task_id, task["status"], TaskStatus.BLOCKED, checkpoint={**checkpoint, "blocked_reason": "approval denied"})
                return self.status(task_id)
            if approval_state != "approved":
                return self.status(task_id)
        return self._run_plan(task_id, approval_state=approval_state)

    def status(self, task_id: str) -> dict[str, Any]:
        task = self._require_task(task_id)
        return {
            "id": task["id"],
            "status": task["status"],
            "interpretation": task["interpretation"],
            "risk_level": task["risk_level"],
            "plan": json.loads(task["plan_json"]),
            "checkpoint": json.loads(task["checkpoint_json"]),
            "receipt": json.loads(task["receipt_json"]) if task["receipt_json"] else None,
        }

    def _run_plan(self, task_id: str, *, approval_state: str | None) -> dict[str, Any]:
        task = self._require_task(task_id)
        plan_rows = json.loads(task["plan_json"])
        checkpoint = json.loads(task["checkpoint_json"])
        start_index = int(checkpoint.get("next_step_index", 0))

        for index, row in enumerate(plan_rows[start_index:], start=start_index):
            step = _step_from_row(row)
            policy = self.policy_gate.evaluate(
                PolicyRequest(
                    user_role="local-user",
                    workspace=str(self.config.data_dir),
                    task_type=task["interpretation"],
                    risk_level=step.risk_level,
                    connector=step.connector,
                    operation=_policy_operation(step.operation),
                    requested_scopes=step.scopes,
                    data_sensitivity=Sensitivity.INTERNAL,
                    approval_state=approval_state,
                ),
                task_id=task_id,
            )

            if policy.decision == PolicyDecisionType.DENY:
                receipt = self._receipt(task, step, result="blocked", approval_status="not_applicable", error="; ".join(policy.reasons))
                self._transition(
                    task_id,
                    task["status"],
                    TaskStatus.BLOCKED,
                    checkpoint={"next_step_index": index, "policy": policy.decision.value, "reasons": list(policy.reasons)},
                    receipt=receipt,
                )
                return self.status(task_id)

            if policy.decision == PolicyDecisionType.REQUIRE_APPROVAL and approval_state != "approved":
                approval = self.approvals.request_approval(
                    ApprovalRequest(
                        task_id=task_id,
                        reason="; ".join(policy.reasons),
                        risk_level=policy.risk_level,
                        payload={"step": step.to_dict(), "requirements": list(policy.requirements)},
                    )
                )
                receipt = self._receipt(task, step, result="waiting for approval", approval_status="pending")
                self._transition(
                    task_id,
                    task["status"],
                    TaskStatus.WAITING_APPROVAL,
                    checkpoint={"next_step_index": index, "approval_id": approval.id, "policy": policy.decision.value},
                    receipt=receipt,
                )
                return self.status(task_id)

            self._transition(task_id, task["status"], TaskStatus.RUNNING, checkpoint={"next_step_index": index})
            result, firewall_result = self.execution_engine.execute(step, approved=approval_state == "approved", task_id=task_id)
            receipt = self._receipt(
                task,
                step,
                result="completed" if result.ok else "failed",
                approval_status=approval_state or "not_required",
                sanitized_outputs={"connector": safe_connector_payload(result.data), "context": list(firewall_result.model_context)},
                affected=result.affected,
                error=result.error,
                rollback=result.rollback,
            )
            if not result.ok:
                self._transition(
                    task_id,
                    TaskStatus.RUNNING,
                    TaskStatus.FAILED,
                    checkpoint={"next_step_index": index, "error": result.error},
                    receipt=receipt,
                )
                return self.status(task_id)
            task = self._require_task(task_id)

        self._transition(task_id, TaskStatus.RUNNING, TaskStatus.COMPLETED, checkpoint={"next_step_index": len(plan_rows)}, receipt=receipt)
        self.audit_logger.append("task.completed", {"task_id": task_id}, task_id=task_id)
        return self.status(task_id)

    def _transition(
        self,
        task_id: str,
        current: TaskStatus | str,
        next_status: TaskStatus | str,
        *,
        checkpoint: dict[str, Any] | None = None,
        receipt: dict[str, Any] | None = None,
    ) -> None:
        current_status = TaskStatus(current)
        requested = TaskStatus(next_status)
        if current_status == requested:
            return
        next_value = self.state_machine.transition(current_status, requested).value
        self.store.update_task(task_id, status=next_value, checkpoint=checkpoint, receipt=receipt)
        self.audit_logger.append("task.state_changed", {"from": current_status.value, "to": next_value, "checkpoint": checkpoint or {}}, task_id=task_id)

    def _receipt(
        self,
        task: dict[str, Any],
        step: PlanStep,
        *,
        result: str,
        approval_status: str,
        sanitized_outputs: dict[str, Any] | None = None,
        affected: tuple[str, ...] = (),
        error: str | None = None,
        rollback: str | None = None,
    ) -> dict[str, Any]:
        receipt = ActionReceipt(
            task_id=task["id"],
            user_request=task["user_request"],
            agent_interpretation=task["interpretation"],
            plan_step=step.description,
            tool_or_connector=step.connector or "none",
            permission_scope=step.scopes,
            inputs=step.params,
            sanitized_outputs=sanitized_outputs or {},
            files_or_records_affected=affected,
            risk_classification=step.risk_level.value,
            approval_status=approval_status,
            result=result,
            error_details=error,
            rollback=rollback,
            log_refs=(str(self.config.audit_log_path),),
        ).to_dict()
        self.audit_logger.append("receipt.generated", receipt, task_id=task["id"])
        return receipt

    def _require_task(self, task_id: str) -> dict[str, Any]:
        task = self.store.get_task(task_id)
        if not task:
            raise KeyError(task_id)
        return task

    def _ensure_builtin_skills(self) -> None:
        if not self.store.get_skill("aegis.project_summary"):
            self.skills.register(SkillManifest.from_dict(builtin_project_summary_manifest()), enable=True)
        if not self.store.get_skill("aegis.workflow_candidate"):
            self.skills.register(SkillManifest.from_dict(builtin_workflow_candidate_manifest()), enable=False)


def build_orchestrator(*, data_dir: str | Path | None = None, workspace: str | Path = ".") -> AgentOrchestrator:
    config = load_config(data_dir)
    store = LocalStore(config.database_path)
    audit_logger = AuditLogger(config.audit_log_path)
    connectors = build_default_registry(config, audit_logger, workspace=workspace)
    return AgentOrchestrator(config=config, store=store, audit_logger=audit_logger, connectors=connectors)


def _step_from_row(row: dict[str, Any]) -> PlanStep:
    return PlanStep(
        id=row["id"],
        description=row["description"],
        connector=row.get("connector"),
        operation=row["operation"],
        params=row.get("params", {}),
        scopes=tuple(row.get("scopes", ())),
        risk_level=RiskLevel(row.get("risk_level", RiskLevel.LOW.value)),
    )


def _policy_operation(operation: str) -> str:
    if operation in {"list", "read", "read_ticket", "search_tickets", "read_profile", "read_channel", "draft_message", "draft_email", "record"}:
        return "read"
    if operation.startswith("dry_run"):
        return "write"
    return operation
