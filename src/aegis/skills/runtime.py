"""Sandboxed skill runtime for built-in governed skills."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from typing import Any
try:
    import resource
except ImportError:  # pragma: no cover - resource is Unix-specific.
    resource = None  # type: ignore[assignment]

from aegis.audit.logger import AuditLogger, redact
from aegis.connectors.base import ConnectorRequest
from aegis.connectors.registry import ConnectorRegistry
from aegis.security.context_firewall import ContextFirewall
from aegis.security.taint import TrustClass
from aegis.skills.manifest import SkillManifest
from aegis.skills.registry import SkillRegistry
from aegis.skills.sandbox import get_sandbox_profile


class SkillPermissionError(PermissionError):
    pass


class SkillSchemaError(ValueError):
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
        _validate_schema(manifest.input_schema, inputs, label=f"{skill_id} input")
        self._enforce_sandbox_profile(manifest)
        self._enforce_permissions(manifest, requested_permissions or {})
        sandbox = _SkillConnectorSandbox(skill_id=skill_id, manifest=manifest, connectors=self.connectors, audit_logger=self.audit_logger)
        if skill_id == "aegis.project_summary":
            result = self._project_summary(inputs, sandbox=sandbox)
        elif skill_id == "aegis.workflow_candidate":
            result = self._workflow_candidate(inputs)
        elif manifest.commands:
            result = self._invoke_process_skill(manifest, inputs)
        else:
            raise KeyError(f"no runtime implementation for skill {skill_id!r}")
        _validate_schema(manifest.output_schema, result, label=f"{skill_id} output")
        self.audit_logger.append("skill.invoked", {"skill_id": skill_id, "inputs": inputs, "result_keys": sorted(result)})
        return result

    def _project_summary(self, inputs: dict[str, Any], *, sandbox: "_SkillConnectorSandbox") -> dict[str, Any]:
        path = str(inputs.get("path", "."))
        connector = sandbox.get("filesystem")
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

    def _invoke_process_skill(self, manifest: SkillManifest, inputs: dict[str, Any]) -> dict[str, Any]:
        profile = get_sandbox_profile(manifest.sandbox_profile)
        if profile.get("process") != "python_json":
            self._deny_profile(manifest, "isolated process execution is not allowed by sandbox profile")
        argv, source_root = _isolated_python_command(manifest)
        timeout_seconds = min(_manifest_timeout_seconds(manifest), 15.0)
        output_limit_bytes = _manifest_output_limit_bytes(manifest)
        resource_limits = _manifest_resource_limits(manifest, timeout_seconds=timeout_seconds)
        env = _minimal_process_env()
        payload = json.dumps(inputs, sort_keys=True)
        cwd_mode = str(profile.get("cwd", "source"))
        try:
            if cwd_mode == "ephemeral":
                with tempfile.TemporaryDirectory(prefix="aegis-skill-") as run_dir:
                    completed = _run_isolated_python_process(
                        argv,
                        cwd=Path(run_dir),
                        env=env,
                        payload=payload,
                        timeout_seconds=timeout_seconds,
                        resource_limits=resource_limits,
                    )
            elif cwd_mode == "source":
                completed = _run_isolated_python_process(
                    argv,
                    cwd=source_root,
                    env=env,
                    payload=payload,
                    timeout_seconds=timeout_seconds,
                    resource_limits=resource_limits,
                )
            else:
                self._deny_profile(manifest, f"unsupported isolated process cwd mode {cwd_mode!r}")
        except subprocess.TimeoutExpired as exc:
            self.audit_logger.append(
                "skill.process_timeout",
                {
                    "skill_id": manifest.id,
                    "command": _command_fingerprint(manifest.commands[0]),
                    "timeout_seconds": timeout_seconds,
                    "cwd_mode": cwd_mode,
                    "resource_limits": resource_limits,
                },
            )
            raise TimeoutError(f"skill process timed out after {timeout_seconds:g}s") from exc
        stdout_bytes = len(completed.stdout.encode("utf-8", errors="replace"))
        stderr_bytes = len(completed.stderr.encode("utf-8", errors="replace"))
        if stdout_bytes > output_limit_bytes or stderr_bytes > output_limit_bytes:
            self.audit_logger.append(
                "skill.process_output_limit",
                {
                    "skill_id": manifest.id,
                    "command": _command_fingerprint(manifest.commands[0]),
                    "stdout_bytes": stdout_bytes,
                    "stderr_bytes": stderr_bytes,
                    "limit_bytes": output_limit_bytes,
                    "sandbox_profile": manifest.sandbox_profile,
                    "cwd_mode": cwd_mode,
                    "resource_limits": resource_limits,
                },
            )
            raise RuntimeError(f"skill process output exceeded {output_limit_bytes} bytes")
        stdout = completed.stdout[:output_limit_bytes]
        stderr = completed.stderr[:output_limit_bytes]
        event_payload = {
            "skill_id": manifest.id,
            "command": _command_fingerprint(manifest.commands[0]),
            "returncode": completed.returncode,
            "stdout": redact(stdout),
            "stderr": redact(stderr),
            "sandbox_profile": manifest.sandbox_profile,
            "cwd_mode": cwd_mode,
            "resource_limits": resource_limits,
        }
        self.audit_logger.append("skill.process_completed", event_payload)
        if completed.returncode != 0:
            raise RuntimeError(f"skill process failed with exit code {completed.returncode}")
        try:
            result = json.loads(stdout or "{}")
        except json.JSONDecodeError as exc:
            raise SkillSchemaError("skill process stdout must be a JSON object") from exc
        if not isinstance(result, dict):
            raise SkillSchemaError("skill process stdout must be a JSON object")
        return result

    def _enforce_permissions(self, manifest: SkillManifest, requested: dict[str, Any]) -> None:
        manifest_permissions = manifest.permissions
        for domain, requested_value in requested.items():
            if domain not in manifest_permissions:
                self._deny_permission(manifest, domain=domain, permission=None, reason=f"skill requested undeclared permission domain {domain!r}")
            declared_value = manifest_permissions[domain]
            if isinstance(requested_value, list):
                declared_set = set(declared_value or [])
                missing = set(requested_value) - declared_set
                if missing:
                    self._deny_permission(
                        manifest,
                        domain=domain,
                        permission=",".join(sorted(str(item) for item in missing)),
                        reason=f"skill requested undeclared permissions: {sorted(missing)}",
                    )
            elif isinstance(requested_value, dict):
                for key, value in requested_value.items():
                    if declared_value.get(key) != value and value:
                        self._deny_permission(
                            manifest,
                            domain=domain,
                            permission=str(key),
                            reason=f"skill requested undeclared permission {domain}.{key}",
                        )

    def _deny_permission(self, manifest: SkillManifest, *, domain: str, permission: str | None, reason: str) -> None:
        self.audit_logger.append(
            "skill.sandbox_denied",
            {
                "skill_id": manifest.id,
                "connector": domain,
                "operation": "request_permission",
                "permission": f"{domain}.{permission}" if permission else domain,
                "outcome": "permission_denied",
                "reason": reason,
            },
        )
        raise SkillPermissionError(reason)

    def _enforce_sandbox_profile(self, manifest: SkillManifest) -> None:
        profile = get_sandbox_profile(manifest.sandbox_profile)
        permissions = manifest.permissions or {}
        declared_connectors = _declared_skill_connectors(manifest)
        if profile.get("secrets") is False and manifest.secrets:
            self._deny_profile(manifest, "secrets are not allowed by sandbox profile")
        if manifest.commands and profile.get("process") != "python_json":
            self._deny_profile(manifest, "isolated process execution is not allowed by sandbox profile")
        if profile.get("shell") is False and manifest.commands:
            self._deny_profile(manifest, "shell commands are not allowed by sandbox profile")
        if profile.get("network") is False and manifest.network:
            self._deny_profile(manifest, "network access is not allowed by sandbox profile")
        filesystem_mode = profile.get("filesystem")
        if filesystem_mode == "none":
            if manifest.filesystem or permissions.get("filesystem") or "filesystem" in declared_connectors:
                self._deny_profile(manifest, "filesystem access is not allowed by sandbox profile")
        elif filesystem_mode == "read":
            if manifest.filesystem.get("write") or _connector_permission_requests_write(permissions.get("filesystem")):
                self._deny_profile(manifest, "filesystem write is not allowed by sandbox profile")
        if profile.get("connectors") == "mock":
            for connector_name in declared_connectors:
                try:
                    connector = self.connectors.get(connector_name)
                except KeyError:
                    self._deny_profile(manifest, f"unknown connector {connector_name!r}")
                if connector.spec.default_mode != "mock":
                    self._deny_profile(manifest, f"connector {connector_name!r} is not mock-mode")
        if profile.get("connectors") is None and filesystem_mode == "none" and declared_connectors:
            self._deny_profile(manifest, "connectors are not allowed by sandbox profile")
        for connector_name in declared_connectors:
            if _connector_permission_requests_write(permissions.get(connector_name)):
                self._deny_profile(manifest, f"connector {connector_name!r} write is not allowed by sandbox profile")

    def _deny_profile(self, manifest: SkillManifest, reason: str) -> None:
        self.audit_logger.append(
            "skill.sandbox_profile_denied",
            {"skill_id": manifest.id, "sandbox_profile": manifest.sandbox_profile, "reason": reason},
        )
        raise SkillPermissionError(reason)


class _SkillConnectorSandbox:
    def __init__(self, *, skill_id: str, manifest: SkillManifest, connectors: ConnectorRegistry, audit_logger: AuditLogger) -> None:
        self.skill_id = skill_id
        self.manifest = manifest
        self.connectors = connectors
        self.audit_logger = audit_logger

    def get(self, connector_name: str) -> "_SkillConnectorProxy":
        declared_connectors = set(self.manifest.permissions.get("connectors", []))
        if connector_name not in declared_connectors:
            self._deny(connector_name, "connect", f"connector {connector_name!r} is not declared")
        return _SkillConnectorProxy(
            skill_id=self.skill_id,
            manifest=self.manifest,
            connector=self.connectors.get(connector_name),
            audit_logger=self.audit_logger,
            deny=self._deny,
        )

    def _deny(self, connector_name: str, operation: str, reason: str) -> None:
        self.audit_logger.append(
            "skill.sandbox_denied",
            {"skill_id": self.skill_id, "connector": connector_name, "operation": operation, "reason": reason},
        )
        raise SkillPermissionError(reason)


def _declared_skill_connectors(manifest: SkillManifest) -> set[str]:
    non_connector_domains = {"process", "network", "secrets", "filesystem", "identity", "email"}
    declared = set(str(item) for item in manifest.connectors)
    permission_connectors = manifest.permissions.get("connectors", [])
    if isinstance(permission_connectors, list):
        declared.update(str(item) for item in permission_connectors)
    for key, value in manifest.permissions.items():
        if key not in non_connector_domains and isinstance(value, dict):
            declared.add(str(key))
    return {item for item in declared if item}


def _connector_permission_requests_write(value: Any) -> bool:
    return isinstance(value, dict) and any(bool(value.get(key)) for key in ("write", "delete", "execute", "admin"))


def _isolated_python_command(manifest: SkillManifest) -> tuple[tuple[str, ...], Path]:
    if len(manifest.commands) != 1:
        raise SkillPermissionError("isolated process skills must declare exactly one command")
    argv = shlex.split(str(manifest.commands[0]))
    if len(argv) != 2:
        raise SkillPermissionError("isolated process command must be 'python3 <script.py>'")
    executable = Path(argv[0]).name
    if executable not in {"python", "python3", Path(sys.executable).name}:
        raise SkillPermissionError(f"isolated process executable {argv[0]!r} is not allowlisted")
    if argv[1].startswith("-"):
        raise SkillPermissionError("isolated process command must name a script file")
    source = Path(manifest.source).expanduser().resolve()
    if not source.exists():
        raise SkillPermissionError("isolated process skill source path does not exist")
    source_root = source.parent if source.is_file() else source
    script = (source_root / argv[1]).resolve()
    try:
        script.relative_to(source_root)
    except ValueError as exc:
        raise SkillPermissionError("isolated process script must stay under the skill source path") from exc
    if script.suffix != ".py" or not script.is_file():
        raise SkillPermissionError("isolated process script must be a Python file")
    return (sys.executable, "-I", str(script)), source_root


def _manifest_timeout_seconds(manifest: SkillManifest) -> float:
    raw = manifest.permissions.get("process", {})
    if isinstance(raw, dict):
        try:
            return max(0.1, float(raw.get("timeout_seconds", 5)))
        except (TypeError, ValueError):
            return 5.0
    return 5.0


def _manifest_output_limit_bytes(manifest: SkillManifest) -> int:
    raw = manifest.permissions.get("process", {})
    if isinstance(raw, dict):
        try:
            return max(256, min(int(raw.get("max_output_bytes", 5000)), 50000))
        except (TypeError, ValueError):
            return 5000
    return 5000


def _manifest_resource_limits(manifest: SkillManifest, *, timeout_seconds: float) -> dict[str, int | bool]:
    raw = manifest.permissions.get("process", {})
    process = raw if isinstance(raw, dict) else {}
    try:
        cpu_seconds = int(process.get("max_cpu_seconds", max(1, int(timeout_seconds) + 1)))
    except (TypeError, ValueError):
        cpu_seconds = max(1, int(timeout_seconds) + 1)
    try:
        memory_mb = int(process.get("max_memory_mb", 128))
    except (TypeError, ValueError):
        memory_mb = 128
    return {
        "cpu_seconds": max(1, min(cpu_seconds, 30)),
        "memory_mb": max(32, min(memory_mb, 512)),
        "os_enforced": resource is not None,
    }


def _run_isolated_python_process(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    payload: str,
    timeout_seconds: float,
    resource_limits: dict[str, int | bool],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv is restricted to an isolated Python script path.
        argv,
        cwd=cwd,
        env=env,
        input=payload,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
        preexec_fn=_resource_limiter(resource_limits) if resource is not None else None,
    )


def _resource_limiter(limits: dict[str, int | bool]) -> Any:
    def apply_limits() -> None:
        if resource is None:
            return
        cpu_seconds = int(limits.get("cpu_seconds") or 1)
        memory_bytes = int(limits.get("memory_mb") or 128) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    return apply_limits


def _minimal_process_env() -> dict[str, str]:
    env = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1",
    }
    if os.environ.get("PATH"):
        env["PATH"] = os.environ["PATH"]
    return env


def _command_fingerprint(command: str) -> dict[str, str]:
    return {"sha256": hashlib.sha256(command.encode("utf-8")).hexdigest()}


class _SkillConnectorProxy:
    def __init__(self, *, skill_id: str, manifest: SkillManifest, connector: Any, audit_logger: AuditLogger, deny: Any) -> None:
        self.skill_id = skill_id
        self.manifest = manifest
        self.connector = connector
        self.audit_logger = audit_logger
        self._deny = deny

    def read(self, request: ConnectorRequest) -> Any:
        self._enforce("read", request)
        return self.connector.read(request)

    def write(self, request: ConnectorRequest) -> Any:
        self._enforce("write", request)
        return self.connector.write(request)

    def dry_run(self, request: ConnectorRequest) -> Any:
        self._enforce("write", request)
        return self.connector.dry_run(request)

    def rollback(self, request: ConnectorRequest) -> Any:
        self._enforce("write", request)
        return self.connector.rollback(request)

    def _enforce(self, capability: str, request: ConnectorRequest) -> None:
        connector_name = self.connector.spec.name
        declared = self.manifest.permissions.get(connector_name, {})
        if not isinstance(declared, dict):
            self._deny(connector_name, request.operation, f"connector {connector_name!r} has no scoped permission map")
        if not declared.get(capability):
            self._deny(connector_name, request.operation, f"skill lacks {connector_name}.{capability} permission")
        for scope in request.scopes:
            if scope in {"read", "write"} and not declared.get(scope):
                self._deny(connector_name, request.operation, f"skill lacks {connector_name}.{scope} scope")
        if capability == "write" and request.operation in self.connector.spec.approval_required and not request.approved:
            self._deny(connector_name, request.operation, f"{connector_name}.{request.operation} requires approval")
        self.audit_logger.append(
            "skill.connector_allowed",
            {"skill_id": self.skill_id, "connector": connector_name, "operation": request.operation, "capability": capability},
        )


def _validate_schema(schema: dict[str, Any], value: Any, *, label: str, path: str = "$") -> None:
    expected_type = schema.get("type")
    if expected_type:
        _validate_type(expected_type, value, label=label, path=path)
    if expected_type == "object" or "properties" in schema:
        if not isinstance(value, dict):
            raise SkillSchemaError(f"{label} {path} must be an object")
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        missing = required - value.keys()
        if missing:
            raise SkillSchemaError(f"{label} {path} missing required fields: {sorted(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise SkillSchemaError(f"{label} {path} has undeclared fields: {sorted(extra)}")
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, dict):
                _validate_schema(child_schema, value[key], label=label, path=f"{path}.{key}")
    if expected_type == "array" or "items" in schema:
        if not isinstance(value, list):
            raise SkillSchemaError(f"{label} {path} must be an array")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_schema(item_schema, item, label=label, path=f"{path}[{index}]")


def _validate_type(expected_type: str | list[str], value: Any, *, label: str, path: str) -> None:
    expected = [expected_type] if isinstance(expected_type, str) else list(expected_type)
    if any(_matches_type(item, value) for item in expected):
        return
    raise SkillSchemaError(f"{label} {path} must be {', '.join(expected)}")


def _matches_type(expected_type: str, value: Any) -> bool:
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return (isinstance(value, int | float) and not isinstance(value, bool))
    if expected_type == "null":
        return value is None
    return True


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
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "additionalProperties": False,
        },
        "output_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "entries": {"type": "array", "items": {"type": "string"}},
                "summary": {"type": "string"},
            },
            "required": ["path", "entries", "summary"],
            "additionalProperties": False,
        },
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
        "input_schema": {
            "type": "object",
            "properties": {"task": {"type": "string"}},
            "additionalProperties": False,
        },
        "output_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "steps": {"type": "array", "items": {"type": "string"}},
                "approval_required": {"type": "boolean"},
                "status": {"type": "string"},
            },
            "required": ["name", "steps", "approval_required", "status"],
            "additionalProperties": False,
        },
        "risk_level": "medium",
        "approval_required": True,
        "sandbox_profile": "no_tools",
        "tests": [{"name": "creates disabled candidate"}],
        "evals": [{"name": "requires approval before enablement"}],
        "rollback": "Delete the generated candidate.",
        "changelog": ["Initial built-in skill."],
    }
