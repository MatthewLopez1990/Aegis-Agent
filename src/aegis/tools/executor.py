"""Small governed implementations for safe built-in tools."""

from __future__ import annotations

import ast
import operator
from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.connectors.base import ConnectorRequest
from aegis.connectors.registry import ConnectorRegistry
from aegis.memory.manager import MemoryManager
from aegis.memory.models import MemoryType
from aegis.security.policy_engine import PolicyDecisionType, PolicyEngine, PolicyRequest
from aegis.security.taint import RiskLevel, Sensitivity
from aegis.tools.catalog import ToolCatalog


class ToolExecutionError(RuntimeError):
    pass


class BuiltinToolExecutor:
    def __init__(self, connectors: ConnectorRegistry, memory: MemoryManager, audit_logger: AuditLogger, policy_engine: PolicyEngine | None = None) -> None:
        self.connectors = connectors
        self.memory = memory
        self.audit_logger = audit_logger
        self.policy_engine = policy_engine or PolicyEngine()
        self.catalog = ToolCatalog()

    def execute(self, name: str, params: dict[str, Any], *, approved: bool = False, task_id: str | None = None) -> dict[str, Any]:
        spec = self.catalog.get(name)
        decision = self.policy_engine.evaluate(
            PolicyRequest(
                user_role="local-user",
                workspace="local",
                task_type=f"tool:{name}",
                risk_level=spec.risk_level,
                operation=_operation_for_tool(name),
                requested_scopes=tuple(scope for scope in (spec.permission, "write" if approved else "") if scope and "/" not in scope),
                approval_state="approved" if approved else None,
                data_sensitivity=Sensitivity.INTERNAL,
            )
        )
        if decision.decision == PolicyDecisionType.DENY:
            raise ToolExecutionError("; ".join(decision.reasons))
        if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL and not approved:
            result = {"status": "approval_required", "tool": name, "reasons": list(decision.reasons)}
            self.audit_logger.append("tool.approval_required", result, task_id=task_id)
            return result

        if name == "calculator":
            result = {"result": safe_eval(str(params["expression"]))}
        elif name in {"file_read", "file_write"}:
            connector = self.connectors.get("filesystem")
            if name == "file_read":
                read = connector.read(ConnectorRequest(operation="read", params={"path": params["path"]}, scopes=("read",)))
                result = {"ok": read.ok, "path": read.data.get("path"), "content_length": len(read.data.get("content", "")), "error": read.error}
            else:
                write = connector.dry_run(ConnectorRequest(operation="dry_run_write", params=params, scopes=("write",), approved=approved))
                result = {"ok": write.ok, "dry_run": True, **write.data}
        elif name == "memory_recall":
            result = {"memories": self.memory.retrieve_relevant(str(params["query"]), limit=int(params.get("limit", 5)))}
        elif name == "memory_store":
            record = self.memory.create_memory(
                memory_type=MemoryType.WORKFLOW,
                content=str(params["content"]),
                source="tool:memory_store",
                provenance={"tool": "memory_store"},
                confidence=float(params.get("confidence", 0.8)),
                confirmed=approved,
            )
            result = {"memory_id": record.id}
        elif name == "web_search":
            result = {"results": [{"title": "Mock search result", "url": "https://example.com", "snippet": str(params["query"])}], "mode": "mock"}
        elif name == "browser":
            result = {"status": "stubbed_pending_browser_backend", "action": params.get("action"), "safe_mode": True}
        else:
            result = {"status": "stubbed", "tool": name, "safe_mode": True, "params": sorted(params)}
        self.audit_logger.append("tool.executed", {"tool": name, "result": result}, task_id=task_id)
        return result


ALLOWED_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
}
ALLOWED_UNARY = {ast.USub: operator.neg, ast.UAdd: operator.pos}


def safe_eval(expression: str) -> float:
    def visit(node: ast.AST) -> float:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.BinOp) and type(node.op) in ALLOWED_BINOPS:
            return ALLOWED_BINOPS[type(node.op)](visit(node.left), visit(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in ALLOWED_UNARY:
            return ALLOWED_UNARY[type(node.op)](visit(node.operand))
        raise ToolExecutionError("unsupported calculator expression")

    return visit(ast.parse(expression, mode="eval"))


def _operation_for_tool(name: str) -> str:
    if name in {"file_write", "memory_store", "image_generate", "tts", "subagent_delegate", "mcp_call"}:
        return "write"
    if name == "shell":
        return "execute"
    return "read"
