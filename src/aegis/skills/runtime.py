"""Sandboxed skill runtime for built-in governed skills."""

from __future__ import annotations

from typing import Any

from aegis.audit.logger import AuditLogger
from aegis.connectors.base import ConnectorRequest
from aegis.connectors.registry import ConnectorRegistry
from aegis.security.context_firewall import ContextFirewall
from aegis.security.taint import TrustClass
from aegis.skills.registry import SkillRegistry


class SkillPermissionError(PermissionError):
    pass


class SkillRuntime:
    def __init__(self, registry: SkillRegistry, connectors: ConnectorRegistry, audit_logger: AuditLogger) -> None:
        self.registry = registry
        self.connectors = connectors
        self.audit_logger = audit_logger
        self.firewall = ContextFirewall()

    def invoke(self, skill_id: str, inputs: dict[str, Any], *, requested_permissions: dict[str, Any] | None = None) -> dict[str, Any]:
        manifest, enabled = self.registry.get(skill_id)
        if not enabled:
            raise SkillPermissionError("skill is disabled or awaiting approval")
        self._enforce_permissions(manifest.permissions, requested_permissions or {})
        if skill_id == "aegis.project_summary":
            result = self._project_summary(inputs)
        elif skill_id == "aegis.workflow_candidate":
            result = self._workflow_candidate(inputs)
        else:
            raise KeyError(f"no runtime implementation for skill {skill_id!r}")
        self.audit_logger.append("skill.invoked", {"skill_id": skill_id, "inputs": inputs, "result_keys": sorted(result)})
        return result

    def _project_summary(self, inputs: dict[str, Any]) -> dict[str, Any]:
        path = str(inputs.get("path", "."))
        connector = self.connectors.get("filesystem")
        listing = connector.read(ConnectorRequest(operation="list", params={"path": path}, scopes=("read",)))
        if not listing.ok:
            raise RuntimeError(listing.error)
        item = self.firewall.label_content(
            "\n".join(listing.data.get("entries", [])),
            source=f"filesystem:{path}",
            trust_class=TrustClass.CONNECTOR_DATA,
            connector_or_tool="filesystem",
        )
        processed = self.firewall.process([item])
        return {
            "path": path,
            "entries": listing.data.get("entries", []),
            "summary": processed.model_context[0],
        }

    def _workflow_candidate(self, inputs: dict[str, Any]) -> dict[str, Any]:
        task = str(inputs.get("task", "")).strip()
        return {
            "name": "User-approved workflow candidate",
            "steps": [step.strip() for step in task.split(".") if step.strip()] or [task],
            "approval_required": True,
            "status": "candidate_disabled_until_review",
        }

    def _enforce_permissions(self, manifest_permissions: dict[str, Any], requested: dict[str, Any]) -> None:
        for domain, requested_value in requested.items():
            if domain not in manifest_permissions:
                raise SkillPermissionError(f"skill requested undeclared permission domain {domain!r}")
            declared_value = manifest_permissions[domain]
            if isinstance(requested_value, list):
                declared_set = set(declared_value or [])
                missing = set(requested_value) - declared_set
                if missing:
                    raise SkillPermissionError(f"skill requested undeclared permissions: {sorted(missing)}")
            elif isinstance(requested_value, dict):
                for key, value in requested_value.items():
                    if declared_value.get(key) != value and value:
                        raise SkillPermissionError(f"skill requested undeclared permission {domain}.{key}")


def builtin_project_summary_manifest() -> dict[str, Any]:
    return {
        "id": "aegis.project_summary",
        "name": "Safe Project Summary",
        "description": "Summarizes project file names using the read-only filesystem connector and context firewall.",
        "version": "0.1.0",
        "author": "Aegis Agent",
        "source": "built-in",
        "permissions": {"connectors": ["filesystem"], "filesystem": {"read": True}},
        "connectors": ["filesystem"],
        "secrets": [],
        "network": {},
        "filesystem": {"read": True, "write": False},
        "commands": [],
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "output_schema": {"type": "object", "properties": {"summary": {"type": "string"}}},
        "risk_level": "low",
        "approval_required": False,
        "sandbox_profile": "read_only_no_network",
        "tests": [{"name": "lists project files"}],
        "evals": [{"name": "does not execute file content"}],
        "rollback": "Disable the skill.",
        "changelog": ["Initial built-in skill."],
    }


def builtin_workflow_candidate_manifest() -> dict[str, Any]:
    return {
        "id": "aegis.workflow_candidate",
        "name": "Workflow Candidate Builder",
        "description": "Creates a disabled workflow candidate from a user-approved task description.",
        "version": "0.1.0",
        "author": "Aegis Agent",
        "source": "built-in",
        "permissions": {},
        "connectors": [],
        "secrets": [],
        "network": {},
        "filesystem": {},
        "commands": [],
        "input_schema": {"type": "object", "properties": {"task": {"type": "string"}}},
        "output_schema": {"type": "object", "properties": {"steps": {"type": "array"}}},
        "risk_level": "medium",
        "approval_required": True,
        "sandbox_profile": "no_tools",
        "tests": [{"name": "creates disabled candidate"}],
        "evals": [{"name": "requires approval before enablement"}],
        "rollback": "Delete the generated candidate.",
        "changelog": ["Initial built-in skill."],
    }
