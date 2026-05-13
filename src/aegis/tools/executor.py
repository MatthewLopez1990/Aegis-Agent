"""Small governed implementations for safe built-in tools."""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import io
import json
import re
import operator
import os
from pathlib import Path
import shutil
import shlex
import struct
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request
import wave
import zlib
from xml.etree import ElementTree
from uuid import uuid4
import zipfile

from aegis.audit.logger import AuditLogger, redact
from aegis.browser.controller import BrowserController
from aegis.connectors.base import ConnectorRequest, ConnectorResult
from aegis.connectors.http import _open_without_redirects, _private_network_error, _validate_url
from aegis.connectors.registry import ConnectorRegistry
from aegis.execution.backends import ExecutionBackendRegistry
from aegis.kanban.manager import KanbanManager
from aegis.memory.manager import MemoryManager
from aegis.memory.models import MemoryType
from aegis.mcp.registry import McpRegistry
from aegis.research.harness import ResearchHarness
from aegis.scheduler.manager import ScheduleManager
from aegis.security.policy_engine import PolicyDecisionType, PolicyEngine, PolicyRequest
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import RiskLevel, Sensitivity, now_utc
from aegis.tools.catalog import ToolCatalog


class ToolExecutionError(RuntimeError):
    pass


class BuiltinToolExecutor:
    def __init__(
        self,
        connectors: ConnectorRegistry,
        memory: MemoryManager,
        audit_logger: AuditLogger,
        policy_engine: PolicyEngine | None = None,
        *,
        mcp_registry: McpRegistry | None = None,
        allowed_executables: tuple[str, ...] = (),
        network_allowlist: tuple[str, ...] = (),
        browser_controller: BrowserController | None = None,
        kanban_manager: KanbanManager | None = None,
        execution_backends: ExecutionBackendRegistry | None = None,
        schedule_manager: ScheduleManager | None = None,
        data_dir: str | Path | None = None,
        secrets_broker: SecretsBroker | None = None,
    ) -> None:
        self.connectors = connectors
        self.memory = memory
        self.audit_logger = audit_logger
        self.policy_engine = policy_engine or PolicyEngine()
        self.catalog = ToolCatalog()
        self.mcp_registry = mcp_registry
        self.allowed_executables = allowed_executables
        self.network_allowlist = network_allowlist
        self.browser = browser_controller
        self.kanban = kanban_manager
        self.execution_backends = execution_backends
        self.schedules = schedule_manager
        self.research = ResearchHarness(data_dir=data_dir)
        self.secrets_broker = secrets_broker or SecretsBroker()

    def execute(self, name: str, params: dict[str, Any], *, approved: bool = False, admin_approved: bool = False, task_id: str | None = None) -> dict[str, Any]:
        virtual_mcp_tool = self.mcp_registry.resolve_virtual_tool(name) if self.mcp_registry is not None else None
        if virtual_mcp_tool is not None:
            return self._execute_virtual_mcp_tool(name, virtual_mcp_tool, params, approved=approved, task_id=task_id)
        spec = self.catalog.get(name)
        operation = _operation_for_tool(name, spec.permission)
        if spec.approval_required and not approved:
            result = {"status": "approval_required", "tool": name, "reasons": ["tool catalog requires approval before execution"]}
            self.audit_logger.append("tool.approval_required", result, task_id=task_id)
            return result
        approval_state = "admin_approved" if admin_approved else "approved" if approved else None
        decision = self.policy_engine.evaluate(
            PolicyRequest(
                user_role="local-user",
                workspace="local",
                task_type=f"tool:{name}",
                risk_level=spec.risk_level,
                operation=operation,
                requested_scopes=_scopes_for_tool(spec.permission, operation),
                approval_state=approval_state,
                data_sensitivity=Sensitivity.INTERNAL,
            )
        )
        if decision.decision == PolicyDecisionType.DENY:
            raise ToolExecutionError("; ".join(decision.reasons))
        if decision.decision in {PolicyDecisionType.REQUIRE_APPROVAL, PolicyDecisionType.REQUIRE_ADMIN_APPROVAL}:
            result = {
                "status": "approval_required",
                "tool": name,
                "reasons": list(decision.reasons),
                "admin_required": decision.decision == PolicyDecisionType.REQUIRE_ADMIN_APPROVAL,
            }
            self.audit_logger.append("tool.approval_required", result, task_id=task_id)
            return result
        if decision.decision != PolicyDecisionType.ALLOW:
            raise ToolExecutionError("; ".join((*decision.reasons, *decision.requirements)))

        if name == "calculator":
            result = {"result": safe_eval(str(params["expression"]))}
        elif name in {"file_read", "file_write"}:
            connector = self.connectors.get("filesystem")
            if name == "file_read":
                read = connector.read(ConnectorRequest(operation="read", params={"path": params["path"]}, scopes=("read",)))
                result = {"ok": read.ok, "path": read.data.get("path"), "content_length": len(read.data.get("content", "")), "error": read.error}
            else:
                if approved:
                    write = connector.write(ConnectorRequest(operation="write", params=params, scopes=("write",), approved=True))
                    result = {"ok": write.ok, "dry_run": False, **write.data, "error": write.error}
                else:
                    write = connector.dry_run(ConnectorRequest(operation="dry_run_write", params=params, scopes=("write",)))
                    result = {"ok": write.ok, "dry_run": True, **write.data, "error": write.error}
        elif name == "shell":
            connector = self.connectors.get("shell")
            shell = connector.write(ConnectorRequest(operation="execute", params={"command": params["command"]}, scopes=("execute",), approved=approved))
            result = {"ok": shell.ok, **shell.data, "error": shell.error}
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
            result = self._execute_web_search(params=params)
        elif name in {"vision_analyze", "voice_transcribe", "video_analyze"}:
            result = self._execute_media_read(name=name, params=params, approved=approved)
        elif name in {"image_generate", "image_edit", "tts", "voice_record"}:
            result = self._execute_media_artifact(name=name, params=params)
        elif name == "http_request":
            result = self._execute_http_request(params=params, approved=approved)
        elif name == "webhook_call":
            result = self._execute_webhook_call(params=params, approved=approved)
        elif name == "rest_call":
            result = self._execute_rest_call(params=params, approved=approved)
        elif name == "web_extract":
            result = self._execute_web_extract(params=params)
        elif name == "rss_read":
            result = self._execute_rss_read(params=params)
        elif name == "price_monitor":
            result = self._execute_price_monitor(params=params)
        elif name == "weather":
            result = self._execute_weather(params=params)
        elif name == "maps_geocode":
            result = self._execute_maps_geocode(params=params)
        elif name in {"translation", "summarizer", "meeting_summary"}:
            result = self._execute_language_utility(name=name, params=params)
        elif name == "git_status":
            result = self._execute_git_status(params=params)
        elif name == "git_diff":
            result = self._execute_git_diff(params=params)
        elif name in {"code_execute", "python_repl"}:
            result = self._execute_code(name=name, params=params)
        elif name == "diff_apply":
            result = self._execute_diff_apply(params=params)
        elif name == "document_parse":
            result = self._execute_document_parse(params=params)
        elif name == "spreadsheet_read":
            result = self._execute_spreadsheet_read(params=params)
        elif name == "spreadsheet_write":
            result = self._execute_spreadsheet_write(params=params, approved=approved)
        elif name == "pdf_extract":
            result = self._execute_pdf_extract(params=params)
        elif name == "archive_extract":
            result = self._execute_archive_extract(params=params)
        elif name == "database_query":
            result = self._execute_database_query(params=params)
        elif name == "embeddings_search":
            result = self._execute_embeddings_search(params=params)
        elif name == "vector_upsert":
            result = self._execute_vector_upsert(params=params, approved=approved)
        elif name in {"email_draft", "email_send"}:
            result = self._execute_email(name=name, params=params, approved=approved)
        elif name == "calendar_read":
            result = self._execute_graph_read(operation="read_calendar", output_key="events", params=params)
        elif name == "calendar_write":
            result = self._execute_calendar_write(params=params, approved=approved)
        elif name == "contacts_search":
            result = self._execute_graph_read(operation="search_contacts", output_key="contacts", params=params)
        elif name == "contacts_write":
            result = self._execute_contacts_write(params=params, approved=approved)
        elif name in {"github_pr", "github_issue"}:
            result = self._execute_github(name=name, params=params, approved=approved)
        elif name in {"gitlab_merge_request", "gitlab_issue"}:
            result = self._execute_gitlab(name=name, params=params, approved=approved)
        elif name == "service_ticket_read":
            result = self._execute_service_ticket_read(params=params)
        elif name == "service_ticket_write":
            result = self._execute_service_ticket_write(params=params, approved=approved)
        elif name in {"browser", "browser_click", "browser_fill", "browser_submit", "browser_screenshot", "browser_render_screenshot", "browser_extract_table", "browser_dom_snapshot", "browser_close"}:
            if self.browser is None:
                raise ToolExecutionError("browser controller is not configured")
            result = self._execute_browser(name, params, approved=approved)
        elif name == "mcp_call":
            if self.mcp_registry is None:
                raise ToolExecutionError("MCP registry is not configured")
            call = self.mcp_registry.call_tool(
                server=str(params["server"]),
                tool=str(params["tool"]),
                arguments=dict(params.get("arguments", {})),
                approved=approved,
                task_id=task_id,
                policy_engine=self.policy_engine,
                allowed_executables=self.allowed_executables,
                network_allowlist=self.network_allowlist,
            )
            result = call.to_dict()
        elif name == "subagent_delegate":
            if self.kanban is None:
                raise ToolExecutionError("kanban manager is not configured")
            result = self._delegate_subagent(params=params, task_id=task_id)
        elif name == "kanban_create":
            if self.kanban is None:
                raise ToolExecutionError("kanban manager is not configured")
            result = self._execute_kanban_create(params=params, task_id=task_id)
        elif name == "cron_schedule":
            if self.schedules is None:
                raise ToolExecutionError("schedule manager is not configured")
            result = self._execute_cron_schedule(params=params)
        elif name == "terminal_backend":
            if self.execution_backends is None:
                raise ToolExecutionError("execution backend registry is not configured")
            result = self.execution_backends.select(str(params["backend"]))
        elif name in {"package_install", "container_run", "docker_run", "ssh_exec", "hosted_sandbox_exec"}:
            result = self._execute_backend_gate(name=name, params=params)
        elif name in {"trajectory_generate", "trajectory_compress"}:
            result = self._execute_research_tool(name=name, params=params)
        else:
            result = {"status": "stubbed", "tool": name, "safe_mode": True, "params": sorted(params)}
        self.audit_logger.append("tool.executed", {"tool": name, "result": result}, task_id=task_id)
        return result

    def _execute_virtual_mcp_tool(
        self,
        name: str,
        virtual_tool: dict[str, Any],
        params: dict[str, Any],
        *,
        approved: bool,
        task_id: str | None,
    ) -> dict[str, Any]:
        if self.mcp_registry is None:
            raise ToolExecutionError("MCP registry is not configured")
        if bool(virtual_tool.get("approval_required", True)) and not approved:
            result = {
                "status": "approval_required",
                "tool": name,
                "server_name": virtual_tool.get("server_name"),
                "mcp_tool": virtual_tool.get("tool"),
                "reasons": ["MCP virtual tools require approval before execution"],
            }
            self.audit_logger.append("tool.approval_required", result, task_id=task_id)
            return result
        call = self.mcp_registry.call_tool(
            server=str(virtual_tool["server_id"]),
            tool=str(virtual_tool["tool"]),
            arguments=params,
            approved=approved,
            task_id=task_id,
            policy_engine=self.policy_engine,
            allowed_executables=self.allowed_executables,
            network_allowlist=self.network_allowlist,
        )
        result = {
            "status": "completed",
            "virtual_tool": name,
            **call.to_dict(),
        }
        self.audit_logger.append("tool.executed", {"tool": name, "result": result}, task_id=task_id)
        return result

    def _execute_research_tool(self, *, name: str, params: dict[str, Any]) -> dict[str, Any]:
        if name == "trajectory_generate":
            steps = tuple(str(step) for step in params.get("steps", ()))
            if not steps:
                steps = ("capture scenario", "run governed checks", "record human-reviewed result")
            trajectory = self.research.generate_trajectory(str(params["scenario"]), steps)
            result = {
                "ok": True,
                "trajectory_id": trajectory.id,
                "scenario": trajectory.scenario,
                "steps": list(trajectory.steps),
                "compressed_summary": trajectory.compressed_summary,
                "manifest": self.research.evaluation_manifest(),
            }
            if params.get("persist_report"):
                result["evaluation_report"] = self.research.record_evaluation_run(
                    trajectory=trajectory,
                    status=str(params.get("status", "recorded")),
                    reviewer=str(params.get("reviewer", "local")),
                    notes=str(params.get("notes", "")),
                )
                result["evaluation_trends"] = self.research.evaluation_trends()
            return result
        if name == "trajectory_compress" and params.get("include_trends"):
            source_steps = tuple(str(step) for step in params.get("steps", ()))
            if not source_steps:
                source_steps = (str(params.get("trajectory_id", "")) or str(params.get("text", "")) or "empty trajectory",)
            return {
                "ok": True,
                "trajectory_id": str(params.get("trajectory_id", "ad-hoc")),
                "summary": " | ".join(source_steps)[:500],
                "training_use": "human_review_required",
                "evaluation_trends": self.research.evaluation_trends(limit=int(params.get("trend_limit", 20))),
            }
        source_steps = tuple(str(step) for step in params.get("steps", ()))
        if not source_steps:
            source_steps = (str(params.get("trajectory_id", "")) or str(params.get("text", "")) or "empty trajectory",)
        return {
            "ok": True,
            "trajectory_id": str(params.get("trajectory_id", "ad-hoc")),
            "summary": " | ".join(source_steps)[:500],
            "training_use": "human_review_required",
        }

    def _execute_media_read(self, *, name: str, params: dict[str, Any], approved: bool = False) -> dict[str, Any]:
        path_key = {"vision_analyze": "image_path", "voice_transcribe": "audio_path", "video_analyze": "video_path"}[name]
        root = _workspace_root(self.connectors)
        if name == "voice_transcribe" and params.get("provider_url"):
            if not approved:
                return {
                    "status": "approval_required",
                    "tool": name,
                    "mode": "live_media_provider",
                    "reasons": ["provider-backed audio transcription sends workspace audio to an external allowlisted provider"],
                    "required_controls": _live_media_required_controls(),
                }
            return self._execute_live_transcription_provider(params=params, root=root)
        path = _resolve_under_root(root, params[path_key])
        size = path.stat().st_size if path.exists() else 0
        if name == "voice_transcribe":
            text = path.read_text(encoding="utf-8", errors="replace")[:4000] if path.is_file() else ""
            return {"ok": path.is_file(), "text": text, "path": str(path), "bytes": size, "taint": "FILE_CONTENT", "mode": "local_text_fallback"}
        if name == "video_analyze":
            metadata = _local_video_metadata(path)
            details = [str(metadata.get("format", "unknown"))]
            if metadata.get("duration_seconds") is not None:
                details.append(f"{metadata['duration_seconds']}s")
            summary = f"Local video metadata: {path.name}, {size} bytes, {', '.join(details)}."
            return {"ok": path.is_file(), "summary": summary, "path": str(path), "bytes": size, "metadata": metadata, "taint": "FILE_CONTENT", "mode": "local_metadata"}
        metadata = _local_image_metadata(path)
        description = f"Local image metadata: {path.name}, {size} bytes."
        if metadata.get("width") and metadata.get("height"):
            description = f"{description} {metadata['format']} {metadata['width']}x{metadata['height']}."
        return {
            "ok": path.is_file(),
            "description": description,
            "path": str(path),
            "bytes": size,
            "metadata": metadata,
            "taint": "FILE_CONTENT",
            "mode": "local_metadata",
        }

    def _execute_media_artifact(self, *, name: str, params: dict[str, Any]) -> dict[str, Any]:
        root = _workspace_root(self.connectors)
        artifact_dir = root / ".aegis" / "tool-artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_dir.chmod(0o700)
        if params.get("provider_url"):
            return self._execute_live_media_provider(name=name, params=params, artifact_dir=artifact_dir)
        if name == "tts":
            text = str(params.get("text", ""))
            path = artifact_dir / f"{name}-{uuid4()}.wav"
            worker_result = _run_media_artifact_worker(artifact_dir=artifact_dir, artifact_name=path.name, tool=name, payload={"text": text})
            duration_seconds = float(worker_result["duration_seconds"])
            artifact_receipt = _artifact_receipt(path)
            sandbox_receipt = _media_sandbox_receipt(tool=name, mode="local_wav_tone", worker_result=worker_result)
            metadata_path = _write_tool_artifact_metadata(
                artifact_dir=artifact_dir,
                tool=name,
                artifact_path=path,
                mode="local_wav_tone",
                artifact_receipt=artifact_receipt,
                sandbox_receipt=sandbox_receipt,
                details={"duration_seconds": duration_seconds, "sample_rate": 8000, "text_length": len(text)},
            )
            return {
                "ok": True,
                "asset_path": str(path),
                "artifact_path": str(path),
                "metadata_path": str(metadata_path),
                **artifact_receipt,
                "sandbox_receipt": sandbox_receipt,
                "mode": "local_wav_tone",
                "duration_seconds": duration_seconds,
                "sample_rate": 8000,
                "text_length": len(text),
            }
        if name == "voice_record":
            duration_seconds = _bounded_float(params.get("duration", 1), minimum=0.1, maximum=60.0, label="duration")
            path = artifact_dir / f"{name}-{uuid4()}.wav"
            worker_result = _run_media_artifact_worker(artifact_dir=artifact_dir, artifact_name=path.name, tool=name, payload={"duration": duration_seconds})
            artifact_receipt = _artifact_receipt(path)
            sandbox_receipt = _media_sandbox_receipt(tool=name, mode="local_wav_silence", worker_result=worker_result)
            metadata_path = _write_tool_artifact_metadata(
                artifact_dir=artifact_dir,
                tool=name,
                artifact_path=path,
                mode="local_wav_silence",
                artifact_receipt=artifact_receipt,
                sandbox_receipt=sandbox_receipt,
                details={"duration_seconds": round(duration_seconds, 3), "sample_rate": 8000},
            )
            return {
                "ok": True,
                "asset_path": str(path),
                "artifact_path": str(path),
                "metadata_path": str(metadata_path),
                **artifact_receipt,
                "sandbox_receipt": sandbox_receipt,
                "mode": "local_wav_silence",
                "duration_seconds": round(duration_seconds, 3),
                "sample_rate": 8000,
            }
        if name in {"image_generate", "image_edit"}:
            prompt = str(params.get("prompt", ""))
            source_path = str(params.get("source_path") or params.get("image_path") or "")
            path = artifact_dir / f"{name}-{uuid4()}.png"
            worker_result = _run_media_artifact_worker(
                artifact_dir=artifact_dir,
                artifact_name=path.name,
                tool=name,
                payload={"prompt": prompt, "source": source_path},
            )
            width = int(worker_result["width"])
            height = int(worker_result["height"])
            artifact_receipt = _artifact_receipt(path)
            sandbox_receipt = _media_sandbox_receipt(tool=name, mode="local_png_preview", worker_result=worker_result)
            metadata_path = _write_tool_artifact_metadata(
                artifact_dir=artifact_dir,
                tool=name,
                artifact_path=path,
                mode="local_png_preview",
                artifact_receipt=artifact_receipt,
                sandbox_receipt=sandbox_receipt,
                details={"width": width, "height": height, "prompt_length": len(prompt), "source_present": bool(source_path)},
            )
            return {
                "ok": True,
                "asset_path": str(path),
                "artifact_path": str(path),
                "metadata_path": str(metadata_path),
                **artifact_receipt,
                "sandbox_receipt": sandbox_receipt,
                "mode": "local_png_preview",
                "width": width,
                "height": height,
                "prompt_length": len(prompt),
                "source_path": source_path or None,
            }
        extension = {"image_generate": "txt", "image_edit": "txt", "tts": "txt", "voice_record": "txt"}[name]
        path = artifact_dir / f"{name}-{uuid4()}.{extension}"
        content = {
            "tool": name,
            "prompt": params.get("prompt"),
            "text": params.get("text"),
            "duration": params.get("duration"),
            "source": params.get("source_path") or params.get("image_path"),
            "mode": "local_placeholder_artifact",
        }
        path.write_text("\n".join(f"{key}: {value}" for key, value in content.items() if value is not None), encoding="utf-8")
        path.chmod(0o600)
        key = "asset_path"
        if name == "tts":
            key = "asset_path"
        if name == "voice_record":
            key = "asset_path"
        artifact_receipt = _artifact_receipt(path)
        sandbox_receipt = _media_sandbox_receipt(tool=name, mode="local_placeholder_artifact")
        metadata_path = _write_tool_artifact_metadata(
            artifact_dir=artifact_dir,
            tool=name,
            artifact_path=path,
            mode="local_placeholder_artifact",
            artifact_receipt=artifact_receipt,
            sandbox_receipt=sandbox_receipt,
            details={"text_artifact": True},
        )
        return {"ok": True, key: str(path), "artifact_path": str(path), "metadata_path": str(metadata_path), **artifact_receipt, "sandbox_receipt": sandbox_receipt, "mode": "local_placeholder_artifact"}

    def _execute_live_media_provider(self, *, name: str, params: dict[str, Any], artifact_dir: Path) -> dict[str, Any]:
        if name not in {"image_generate", "image_edit", "tts"}:
            return {
                "ok": False,
                "tool": name,
                "mode": "live_media_provider",
                "status": "unsupported_provider_tool",
                "reason": f"{name} does not support provider-backed media execution",
                "required_controls": _live_media_required_controls(),
            }
        rest = self.connectors.get("generic_rest")
        if not bool(getattr(rest, "live_writes", False)):
            return {
                "ok": False,
                "tool": name,
                "mode": "live_media_provider",
                "status": "not_configured",
                "reason": "live_rest_writes must be enabled before provider-backed media execution",
                "required_controls": _live_media_required_controls(),
            }
        provider_url = str(params["provider_url"])
        parsed = urlparse(provider_url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed) or (None if parsed.scheme == "https" else "media provider execution requires https")
        if validation_error:
            return {"ok": False, "tool": name, "mode": "live_media_provider", "status": "scope_rejected", "reason": validation_error, "required_controls": _live_media_required_controls()}
        http = self.connectors.get("http")
        allowlist = tuple(str(item) for item in getattr(http, "allowlist", ()))
        if not _host_allowed(domain, allowlist):
            return {"ok": False, "tool": name, "mode": "live_media_provider", "status": "scope_rejected", "reason": f"media provider host {domain!r} is not allowlisted", "required_controls": _live_media_required_controls()}
        private_error = _private_network_error(domain)
        if private_error:
            return {"ok": False, "tool": name, "mode": "live_media_provider", "status": "scope_rejected", "reason": private_error, "required_controls": _live_media_required_controls()}
        prompt = str(params.get("prompt", ""))
        text = str(params.get("text", ""))
        source_path = str(params.get("source_path") or params.get("image_path") or "")
        provider_adapter = _live_media_provider_adapter(name=name, params=params)
        if provider_adapter["error"]:
            return {
                "ok": False,
                "tool": name,
                "mode": "live_media_provider",
                "status": "unsupported_provider_adapter",
                "reason": provider_adapter["error"],
                "required_controls": _live_media_required_controls(),
            }
        adapter_name = str(provider_adapter["name"] or "generic")
        source_file: dict[str, Any] | None = None
        mask_file: dict[str, Any] | None = None
        if adapter_name == "openai_image_edit":
            try:
                root = _workspace_root(self.connectors)
                source_file = _live_media_source_file(root=root, source_path=source_path, field="image")
                mask_path = str(params.get("mask_path") or params.get("mask") or "").strip()
                if mask_path:
                    mask_file = _live_media_source_file(root=root, source_path=mask_path, field="mask")
            except ToolExecutionError as exc:
                return {
                    "ok": False,
                    "tool": name,
                    "mode": "live_media_provider",
                    "status": "invalid_source",
                    "reason": str(redact(str(exc))),
                    "required_controls": _live_media_required_controls(),
                }
        token_secret = str(params.get("token_secret") or "AEGIS_MEDIA_PROVIDER_TOKEN")
        handle = self.secrets_broker.request_handle(name=token_secret, requester="media_provider", reason=f"{name} provider-backed artifact", scopes=("media:execute",))
        if not handle.present:
            return {"ok": False, "tool": name, "mode": "live_media_provider", "status": "not_configured", "reason": f"secret {token_secret!r} is not configured", "required_controls": _live_media_required_controls()}
        token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="media_provider")
        request_payload = _live_media_request_payload(name=name, prompt=prompt, text=text, source_path=source_path, params=params, provider_adapter=adapter_name, source_file=source_file, mask_file=mask_file)
        live_result = _send_live_media_provider_request(url=provider_url, token=token, tool=name, payload=request_payload, provider_adapter=adapter_name, source_file=source_file, mask_file=mask_file)
        if not live_result["ok"]:
            return {
                "ok": False,
                "tool": name,
                "mode": "live_media_provider",
                "status": "failed",
                "domain": domain,
                "http_status": live_result["http_status"],
                "error": live_result.get("error"),
                "provider_adapter": adapter_name,
                "provider_receipt": _live_media_provider_receipt(domain=domain, http_status=live_result["http_status"], request_payload=request_payload, handle_present=handle.present, provider_adapter=adapter_name),
            }
        media_bytes = live_result["content"]
        extension, mime_type = _live_media_extension_and_mime(name=name, declared_mime=str(live_result.get("mime_type", "")), content=media_bytes)
        path = artifact_dir / f"{name}-{uuid4()}.{extension}"
        path.write_bytes(media_bytes)
        path.chmod(0o600)
        artifact_receipt = _artifact_receipt(path)
        sandbox_receipt = _media_sandbox_receipt(tool=name, mode=f"live_provider_{extension}", worker_result={"provider_domain": domain, "provider_adapter": adapter_name})
        provider_receipt = _live_media_provider_receipt(domain=domain, http_status=live_result["http_status"], request_payload=request_payload, handle_present=handle.present, provider_adapter=adapter_name)
        details = {
            "mime_type": mime_type,
            "prompt_length": len(prompt),
            "text_length": len(text),
            "source_present": bool(source_path),
            "provider_adapter": adapter_name,
            "provider_receipt": provider_receipt,
        }
        if name in {"image_generate", "image_edit"}:
            metadata = _local_image_metadata(path)
            details.update({"width": metadata.get("width"), "height": metadata.get("height")})
        if name == "tts" and live_result.get("duration_seconds") is not None:
            details["duration_seconds"] = live_result["duration_seconds"]
        metadata_path = _write_tool_artifact_metadata(
            artifact_dir=artifact_dir,
            tool=name,
            artifact_path=path,
            mode=f"live_provider_{extension}",
            artifact_receipt=artifact_receipt,
            sandbox_receipt=sandbox_receipt,
            details=details,
        )
        result = {
            "ok": True,
            "asset_path": str(path),
            "artifact_path": str(path),
            "metadata_path": str(metadata_path),
            **artifact_receipt,
            "sandbox_receipt": sandbox_receipt,
            "provider_receipt": provider_receipt,
            "provider_adapter": adapter_name,
            "mode": f"live_provider_{extension}",
            "mime_type": mime_type,
            "domain": domain,
        }
        if name in {"image_generate", "image_edit"}:
            result.update({"width": details.get("width"), "height": details.get("height")})
        if name == "tts" and live_result.get("duration_seconds") is not None:
            result["duration_seconds"] = live_result["duration_seconds"]
        return result

    def _execute_live_transcription_provider(self, *, params: dict[str, Any], root: Path) -> dict[str, Any]:
        rest = self.connectors.get("generic_rest")
        if not bool(getattr(rest, "live_writes", False)):
            return {
                "ok": False,
                "tool": "voice_transcribe",
                "mode": "live_media_provider",
                "status": "not_configured",
                "reason": "live_rest_writes must be enabled before provider-backed audio transcription",
                "required_controls": _live_media_required_controls(),
            }
        provider_url = str(params["provider_url"])
        parsed = urlparse(provider_url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed) or (None if parsed.scheme == "https" else "media provider transcription requires https")
        if validation_error:
            return {"ok": False, "tool": "voice_transcribe", "mode": "live_media_provider", "status": "scope_rejected", "reason": validation_error, "required_controls": _live_media_required_controls()}
        http = self.connectors.get("http")
        allowlist = tuple(str(item) for item in getattr(http, "allowlist", ()))
        if not _host_allowed(domain, allowlist):
            return {"ok": False, "tool": "voice_transcribe", "mode": "live_media_provider", "status": "scope_rejected", "reason": f"media provider host {domain!r} is not allowlisted", "required_controls": _live_media_required_controls()}
        private_error = _private_network_error(domain)
        if private_error:
            return {"ok": False, "tool": "voice_transcribe", "mode": "live_media_provider", "status": "scope_rejected", "reason": private_error, "required_controls": _live_media_required_controls()}
        provider_adapter = _live_media_provider_adapter(name="voice_transcribe", params=params)
        if provider_adapter["error"]:
            return {
                "ok": False,
                "tool": "voice_transcribe",
                "mode": "live_media_provider",
                "status": "unsupported_provider_adapter",
                "reason": provider_adapter["error"],
                "required_controls": _live_media_required_controls(),
            }
        adapter_name = str(provider_adapter["name"] or "generic")
        if adapter_name != "openai_transcription":
            return {
                "ok": False,
                "tool": "voice_transcribe",
                "mode": "live_media_provider",
                "status": "unsupported_provider_adapter",
                "reason": f"{adapter_name} provider adapter does not support provider-backed transcription",
                "required_controls": _live_media_required_controls(),
            }
        try:
            audio_file = _live_media_audio_file(root=root, audio_path=str(params.get("audio_path") or params.get("path") or ""))
        except ToolExecutionError as exc:
            return {
                "ok": False,
                "tool": "voice_transcribe",
                "mode": "live_media_provider",
                "status": "invalid_source",
                "reason": str(redact(str(exc))),
                "required_controls": _live_media_required_controls(),
            }
        token_secret = str(params.get("token_secret") or "AEGIS_MEDIA_PROVIDER_TOKEN")
        handle = self.secrets_broker.request_handle(name=token_secret, requester="media_provider", reason="voice_transcribe provider-backed transcription", scopes=("media:execute",))
        if not handle.present:
            return {"ok": False, "tool": "voice_transcribe", "mode": "live_media_provider", "status": "not_configured", "reason": f"secret {token_secret!r} is not configured", "required_controls": _live_media_required_controls()}
        token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="media_provider")
        request_payload = _live_media_request_payload(
            name="voice_transcribe",
            prompt=str(params.get("prompt", "")),
            text="",
            source_path=str(params.get("audio_path") or ""),
            params=params,
            provider_adapter=adapter_name,
        )
        live_result = _send_live_transcription_provider_request(url=provider_url, token=token, payload=request_payload, provider_adapter=adapter_name, audio_file=audio_file)
        provider_receipt = _live_media_provider_receipt(domain=domain, http_status=live_result["http_status"], request_payload=request_payload, handle_present=handle.present, provider_adapter=adapter_name)
        if not live_result["ok"]:
            return {
                "ok": False,
                "tool": "voice_transcribe",
                "mode": "live_media_provider",
                "status": "failed",
                "domain": domain,
                "http_status": live_result["http_status"],
                "error": live_result.get("error"),
                "provider_adapter": adapter_name,
                "provider_receipt": provider_receipt,
            }
        audio_receipt = {
            "source_audio_sha256": audio_file["sha256"],
            "source_audio_bytes": audio_file["bytes"],
            "source_audio_mime_type": audio_file["mime_type"],
            "source_audio_path_included": False,
            "raw_audio_included": False,
        }
        return {
            "ok": True,
            "tool": "voice_transcribe",
            "text": str(live_result["text"])[:4000],
            "path": str(audio_file["path"]),
            "bytes": audio_file["bytes"],
            "taint": "WEB_CONTENT",
            "mode": "live_provider_transcription",
            "domain": domain,
            "http_status": live_result["http_status"],
            "provider_adapter": adapter_name,
            "provider_receipt": provider_receipt,
            "audio_receipt": audio_receipt,
            "raw_audio_included": False,
            "raw_response_body_included": False,
        }

    def _delegate_subagent(self, *, params: dict[str, Any], task_id: str | None) -> dict[str, Any]:
        assert self.kanban is not None
        role = str(params["role"]).strip()
        task = str(params["task"]).strip()
        if not role or not task:
            raise ToolExecutionError("subagent delegation requires non-empty role and task")
        try:
            card = self.kanban.add_subagent_delegation(role=role, task=task, task_id=task_id)
        except ValueError as exc:
            raise ToolExecutionError(str(exc)) from exc
        return {
            "ok": True,
            "board_id": card["board_id"],
            "card_id": card["id"],
            "lane": card["lane"],
            "owner": role,
            "execution_mode": "durable_card_queue",
            "instructions_tainted": True,
            "raw_instruction_forwarded_to_model": False,
        }

    def _execute_kanban_create(self, *, params: dict[str, Any], task_id: str | None) -> dict[str, Any]:
        assert self.kanban is not None
        title = str(params["title"]).strip()
        if not title:
            raise ToolExecutionError("kanban_create requires a non-empty title")
        board_id = str(params.get("board_id", "")).strip()
        if board_id:
            board = next((row for row in self.kanban.list_boards() if row["id"] == board_id), None)
            if board is None:
                raise ToolExecutionError(f"kanban board {board_id!r} was not found")
        else:
            board = self.kanban.create_board(str(params.get("board", "Aegis Work")), metadata={"purpose": "tool_created"})
        card = self.kanban.add_card(
            board["id"],
            title=title,
            description=str(params.get("description", "")),
            lane=str(params.get("lane", "backlog")),
            owner=str(params["owner"]) if params.get("owner") else None,
            risk_level=RiskLevel.MEDIUM,
            task_id=task_id,
            metadata={"source_tool": "kanban_create"},
        )
        return {"ok": True, "board_id": board["id"], "card_id": card["id"], "lane": card["lane"], "title": card["title"]}

    def _execute_cron_schedule(self, *, params: dict[str, Any]) -> dict[str, Any]:
        assert self.schedules is not None
        schedule = self.schedules.create_schedule(
            name=str(params.get("name", "Tool-created schedule")),
            natural_language=str(params.get("natural_language", params["task"])),
            cron=str(params["cron"]),
            task_request=str(params["task"]),
            channel=str(params.get("channel", "tool")),
            metadata={"source_tool": "cron_schedule"},
        )
        return {"ok": True, "schedule_id": schedule["id"], "status": schedule["status"], "next_run_at": schedule["next_run_at"]}

    def _execute_http_request(self, *, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        method = str(params.get("method", "GET")).upper()
        url = str(params["url"])
        connector = self.connectors.get("http")
        if method in {"GET", "HEAD"}:
            read = connector.read(ConnectorRequest(operation="read", params={"url": url}, scopes=("read",), approved=approved))
            content = read.data.get("content", "")
            return {
                "ok": read.ok,
                "method": method,
                "url": read.data.get("url", url),
                "domain": read.data.get("domain"),
                "content_length": len(content),
                "content_preview": str(content)[:500],
                "taint": "WEB_CONTENT",
                "error": read.error,
            }
        write = connector.write(ConnectorRequest(operation=method.lower(), params=params, scopes=("write",), approved=approved))
        return {"ok": write.ok, "method": method, "url": url, **write.data, "error": write.error}

    def _execute_web_search(self, *, params: dict[str, Any]) -> dict[str, Any]:
        query = str(params["query"])
        limit = int(params.get("num_results", params.get("limit", 5)))
        if params.get("provider_url"):
            read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": str(params["provider_url"])}, scopes=("read",)))
            if not read.ok:
                return {"ok": False, "query": query, "results": [], "mode": "allowlisted_live_read", "error": read.error}
            try:
                decoded = json.loads(str(read.data.get("content", "")))
            except json.JSONDecodeError:
                return {"ok": False, "query": query, "results": [], "mode": "allowlisted_live_read", "error": "search provider response must be JSON"}
            return {
                "ok": True,
                "query": query,
                "url": read.data.get("url", params["provider_url"]),
                "results": _extract_search_results(decoded, limit=limit),
                "mode": "allowlisted_live_read",
                "taint": "WEB_CONTENT",
            }
        return {
            "ok": True,
            "query": query,
            "results": _local_workspace_search(_workspace_root(self.connectors), query=query, limit=limit),
            "mode": "local_workspace_search",
            "local_fallback": True,
            "requires_live_connector": True,
        }

    def _execute_rest_call(self, *, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        connector_name = str(params.get("connector", "generic_rest"))
        connector = self.connectors.get(connector_name)
        method = str(params.get("method", "GET")).upper()
        url = str(params["url"])
        if method in {"GET", "HEAD"}:
            read = connector.read(ConnectorRequest(operation="read", params={"url": url}, scopes=("read",), approved=approved))
            return {"ok": read.ok, "connector": connector_name, "method": method, "url": read.data.get("url", url), "taint": "WEB_CONTENT", "data": _jsonish(read.data), "error": read.error}
        write = connector.write(ConnectorRequest(operation=method.lower(), params=params, scopes=("write",), approved=approved))
        return {"ok": write.ok, "connector": connector_name, "method": method, "url": url, "data": _jsonish(write.data), "error": write.error}

    def _execute_webhook_call(self, *, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        result = self.connectors.get("generic_rest").write(
            ConnectorRequest(
                operation="webhook_call",
                params={"url": str(params["url"]), "payload": dict(params.get("payload", {}))},
                scopes=("write",),
                approved=approved,
            )
        )
        return {"ok": result.ok, "url": result.data.get("url", params["url"]), "status": result.data.get("status"), "mode": result.data.get("mode"), "accepted": result.data.get("accepted", {}), **_connector_activation_fields(result), "rollback": result.rollback, "error": result.error}

    def _execute_web_extract(self, *, params: dict[str, Any]) -> dict[str, Any]:
        read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": str(params["url"])}, scopes=("read",)))
        content = str(read.data.get("content", ""))
        text = _extract_text(content)
        return {"ok": read.ok, "url": read.data.get("url", params["url"]), "text": text[:4000], "content_length": len(content), "taint": "WEB_CONTENT", "error": read.error}

    def _execute_rss_read(self, *, params: dict[str, Any]) -> dict[str, Any]:
        read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": str(params["url"])}, scopes=("read",)))
        content = str(read.data.get("content", ""))
        return {"ok": read.ok, "url": read.data.get("url", params["url"]), "items": _parse_rss_items(content, limit=int(params.get("limit", 10))), "taint": "WEB_CONTENT", "error": read.error}

    def _execute_price_monitor(self, *, params: dict[str, Any]) -> dict[str, Any]:
        read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": str(params["url"])}, scopes=("read",)))
        content = str(read.data.get("content", ""))
        match = re.search(r"[$€£]\s?\d+(?:[.,]\d{2})?", content)
        return {"ok": read.ok, "url": read.data.get("url", params["url"]), "price": match.group(0) if match else "", "mode": "allowlisted_extract", "taint": "WEB_CONTENT", "error": read.error}

    def _execute_weather(self, *, params: dict[str, Any]) -> dict[str, Any]:
        location = str(params["location"])
        if "latitude" not in params or "longitude" not in params:
            return {"ok": True, "location": location, "forecast": {"source": "mock_local", "summary": "Weather provider not configured", "requires_live_connector": True}}
        latitude = _bounded_float(params["latitude"], minimum=-90.0, maximum=90.0, label="latitude")
        longitude = _bounded_float(params["longitude"], minimum=-180.0, maximum=180.0, label="longitude")
        connector = self.connectors.get("http")
        points_url = f"https://api.weather.gov/points/{latitude:.4f},{longitude:.4f}"
        points = connector.read(ConnectorRequest(operation="read", params={"url": points_url}, scopes=("read",)))
        if not points.ok:
            return {"ok": False, "location": location, "forecast": {"source": "nws", "mode": "allowlisted_live_read"}, "error": points.error}
        try:
            points_data = _json_object(str(points.data.get("content", "")))
        except ValueError as exc:
            return {"ok": False, "location": location, "forecast": {"source": "nws", "mode": "allowlisted_live_read"}, "error": str(exc)}
        forecast_url = str(points_data.get("properties", {}).get("forecast", ""))
        if not forecast_url:
            return {"ok": False, "location": location, "forecast": {"source": "nws", "mode": "allowlisted_live_read"}, "error": "weather provider did not return a forecast URL"}
        forecast = connector.read(ConnectorRequest(operation="read", params={"url": forecast_url}, scopes=("read",)))
        if not forecast.ok:
            return {"ok": False, "location": location, "forecast": {"source": "nws", "mode": "allowlisted_live_read"}, "error": forecast.error}
        try:
            forecast_data = _json_object(str(forecast.data.get("content", "")))
        except ValueError as exc:
            return {"ok": False, "location": location, "forecast": {"source": "nws", "mode": "allowlisted_live_read"}, "error": str(exc)}
        periods = forecast_data.get("properties", {}).get("periods", [])
        if not isinstance(periods, list):
            periods = []
        parsed_periods = [_weather_period(period) for period in periods[: int(params.get("limit", 5))] if isinstance(period, dict)]
        return {
            "ok": True,
            "location": location,
            "coordinates": {"latitude": latitude, "longitude": longitude},
            "forecast": {
                "source": "nws",
                "mode": "allowlisted_live_read",
                "url": forecast.data.get("url", forecast_url),
                "periods": parsed_periods,
            },
            "taint": "WEB_CONTENT",
        }

    def _execute_maps_geocode(self, *, params: dict[str, Any]) -> dict[str, Any]:
        address = str(params["address"])
        if params.get("provider_url"):
            read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": str(params["provider_url"])}, scopes=("read",)))
            if not read.ok:
                return {"ok": False, "address": address, "coordinates": {"source": "live_geocode", "mode": "allowlisted_live_read"}, "error": read.error}
            try:
                decoded = json.loads(str(read.data.get("content", "")))
            except json.JSONDecodeError as exc:
                return {"ok": False, "address": address, "coordinates": {"source": "live_geocode", "mode": "allowlisted_live_read"}, "error": "geocode provider response must be JSON"}
            coordinates = _extract_geocode_coordinates(decoded)
            if coordinates is None:
                return {"ok": False, "address": address, "coordinates": {"source": "live_geocode", "mode": "allowlisted_live_read"}, "error": "geocode provider response did not include coordinates"}
            return {
                "ok": True,
                "address": address,
                "coordinates": {
                    "lat": coordinates[0],
                    "lng": coordinates[1],
                    "source": "live_geocode",
                    "mode": "allowlisted_live_read",
                    "url": read.data.get("url", params["provider_url"]),
                },
                "taint": "WEB_CONTENT",
            }
        seed = sum(ord(char) for char in address)
        return {"ok": True, "address": address, "coordinates": {"lat": round((seed % 18000) / 100 - 90, 6), "lng": round((seed % 36000) / 100 - 180, 6), "source": "mock_local"}}

    def _execute_language_utility(self, *, name: str, params: dict[str, Any]) -> dict[str, Any]:
        source = str(params.get("text") or params.get("transcript") or "")
        if name == "translation":
            return _local_translate(source, target=str(params["target"]))
        summary = _summarize_text(source)
        key = "summary"
        return {"ok": True, key: summary, "source_length": len(source), "mode": "local_extractive"}

    def _execute_git_status(self, *, params: dict[str, Any]) -> dict[str, Any]:
        root = _workspace_root(self.connectors)
        target = _resolve_under_root(root, params.get("path", "."))
        completed = _run_git(root, "status", "--short", "--branch", "--", str(target.relative_to(root)))
        return {"ok": completed.returncode == 0, "path": str(target), "status": completed.stdout[:5000], "stderr": completed.stderr[:1000], "returncode": completed.returncode}

    def _execute_git_diff(self, *, params: dict[str, Any]) -> dict[str, Any]:
        root = _workspace_root(self.connectors)
        target = _resolve_under_root(root, params.get("path", "."))
        completed = _run_git(root, "diff", "--", str(target.relative_to(root)))
        return {"ok": completed.returncode == 0, "path": str(target), "diff": completed.stdout[:10000], "stderr": completed.stderr[:1000], "returncode": completed.returncode, "taint": "REPO_CONTENT"}

    def _execute_code(self, *, name: str, params: dict[str, Any]) -> dict[str, Any]:
        language = str(params.get("language", "python")).lower()
        if name == "python_repl":
            language = "python"
        if language not in {"python", "python3", "py"}:
            return {"ok": False, "status": "unsupported_language", "language": language, "supported": ["python"], "mode": "local_sandbox"}
        root = _workspace_root(self.connectors)
        run_dir = root / ".aegis" / "tool-artifacts" / "code-runs" / str(uuid4())
        run_dir.mkdir(parents=True, exist_ok=True)
        script = run_dir / "snippet.py"
        script.write_text(str(params["code"]), encoding="utf-8")
        completed = subprocess.run(
            (sys.executable, "-I", str(script)),
            cwd=run_dir,
            text=True,
            capture_output=True,
            timeout=float(params.get("timeout", 5)),
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "status": "completed" if completed.returncode == 0 else "failed",
            "language": "python",
            "stdout": completed.stdout[:5000],
            "stderr": completed.stderr[:5000],
            "returncode": completed.returncode,
            "artifact_dir": str(run_dir),
            "mode": "local_isolated_python",
            "taint": "CODE_OUTPUT",
        }

    def _execute_diff_apply(self, *, params: dict[str, Any]) -> dict[str, Any]:
        patch = str(params["patch"])
        changed_files = _changed_files_from_patch(patch)
        root = _workspace_root(self.connectors)
        check = subprocess.run(("git", "-C", str(root), "apply", "--check", "-"), input=patch, text=True, capture_output=True, timeout=10, check=False)
        if check.returncode != 0:
            return {"ok": False, "status": "check_failed", "changed_files": changed_files, "stderr": check.stderr[:2000], "returncode": check.returncode}
        applied = subprocess.run(("git", "-C", str(root), "apply", "-"), input=patch, text=True, capture_output=True, timeout=10, check=False)
        return {
            "ok": applied.returncode == 0,
            "status": "applied" if applied.returncode == 0 else "failed",
            "changed_files": changed_files,
            "stdout": applied.stdout[:1000],
            "stderr": applied.stderr[:2000],
            "returncode": applied.returncode,
            "rollback": "review git diff and revert affected files if needed",
        }

    def _execute_backend_gate(self, *, name: str, params: dict[str, Any]) -> dict[str, Any]:
        backend_name = {"container_run": "docker", "docker_run": "docker", "ssh_exec": "ssh", "hosted_sandbox_exec": str(params.get("backend", ""))}.get(name, "local")
        if name == "hosted_sandbox_exec" and backend_name not in {"modal", "daytona", "vercel_sandbox"}:
            return {"ok": False, "status": "scope_rejected", "tool": name, "backend": backend_name or "unknown", "reason": "hosted sandbox backend must be one of: modal, daytona, vercel_sandbox", "verification_gates": ["scope_escape_rejection"]}
        backend = self.execution_backends.get(backend_name) if self.execution_backends is not None else None
        activation = _backend_activation_requirements(name=name, backend=backend_name, backend_record=backend)
        if backend is not None and not backend["enabled"]:
            return {
                "ok": False,
                "status": "disabled",
                "tool": name,
                "backend": backend_name,
                "reason": "backend adapter is not enabled",
                **activation,
            }
        if backend_name == "docker" and backend is not None:
            return self._execute_docker_backend(name=name, params=params, backend=backend)
        if backend_name == "ssh" and backend is not None:
            return self._execute_ssh_backend(name=name, params=params, backend=backend)
        if backend_name in {"modal", "daytona", "vercel_sandbox"} and backend is not None:
            return self._execute_hosted_sandbox_backend(name=name, params=params, backend=backend)
        return {
            "ok": False,
            "status": "not_configured",
            "tool": name,
            "backend": backend_name,
            "params": sorted(params),
            "reason": "live execution adapter requires explicit sandbox/provider configuration",
            **activation,
        }

    def _execute_hosted_sandbox_backend(self, *, name: str, params: dict[str, Any], backend: dict[str, Any]) -> dict[str, Any]:
        config = dict(backend.get("adapter_config", {}))
        backend_name = str(backend.get("name", params.get("backend", "")))
        activation = _backend_activation_requirements(name=name, backend=backend_name, backend_record=backend)
        action = _hosted_sandbox_action(params)
        if action is None:
            return {"ok": False, "status": "scope_rejected", "tool": name, "backend": backend_name, "reason": "hosted sandbox action must be one of: submit, status, logs, cancel, artifact, rollback", "verification_gates": ["scope_escape_rejection"]}
        url = str(params.get("provider_url") or params.get("api_url") or config.get("api_url") or "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed) or (None if parsed.scheme == "https" else "hosted sandbox execution requires https")
        if validation_error:
            return {"ok": False, "status": "not_configured", "tool": name, "backend": backend_name, "reason": validation_error, **activation}
        allowed_hosts = tuple(str(item) for item in config.get("allowed_hosts", ()))
        if not _host_allowed(domain, allowed_hosts):
            return {"ok": False, "status": "scope_rejected", "tool": name, "backend": backend_name, "reason": f"hosted sandbox API host {domain!r} is not allowlisted", "verification_gates": ["scope_escape_rejection"]}
        private_error = _private_network_error(domain)
        if private_error:
            return {"ok": False, "status": "scope_rejected", "tool": name, "backend": backend_name, "reason": private_error, "verification_gates": ["scope_escape_rejection"]}
        command_args: list[str] = []
        if action == "submit":
            try:
                command_args = _safe_remote_command_args(str(params.get("command", "")))
            except ToolExecutionError as exc:
                return {"ok": False, "status": "scope_rejected", "tool": name, "backend": backend_name, "reason": str(exc), "verification_gates": ["scope_escape_rejection"]}
        token_secret = str(params.get("token_secret") or config.get("token_secret") or "AEGIS_HOSTED_SANDBOX_TOKEN")
        handle = self.secrets_broker.request_handle(name=token_secret, requester="hosted_sandbox_backend", reason=f"{backend_name} sandbox execution", scopes=(f"{backend_name}:execute",))
        if not handle.present:
            return {"ok": False, "status": "not_configured", "tool": name, "backend": backend_name, "reason": f"secret {token_secret!r} is not configured", **activation}
        token = self.secrets_broker.resolve_for_authorized_tool(handle, requester="hosted_sandbox_backend")
        timeout = int(config.get("timeout_seconds", 60))
        if action != "submit":
            job_id = str(params.get("job_id") or params.get("id") or "").strip()
            if not _safe_hosted_sandbox_job_id(job_id):
                return {"ok": False, "status": "scope_rejected", "tool": name, "backend": backend_name, "reason": "hosted sandbox lifecycle actions require a simple job_id", "verification_gates": ["scope_escape_rejection"]}
            live_result = _send_hosted_sandbox_lifecycle_request(url=url, token=token, backend=backend_name, action=action, job_id=job_id, timeout=timeout)
            lifecycle_receipt = _hosted_sandbox_lifecycle_receipt(
                backend=backend_name,
                action=action,
                domain=domain,
                job_id=job_id,
                http_status=live_result["http_status"],
                handle_present=handle.present,
                response_summary=live_result.get("response_summary", {}),
            )
            result: dict[str, Any] = {
                "ok": bool(live_result["ok"]),
                "status": "lifecycle_completed" if live_result["ok"] else "failed",
                "tool": name,
                "backend": backend_name,
                "domain": domain,
                "http_status": live_result["http_status"],
                "job_id": job_id,
                "lifecycle_action": action,
                "lifecycle_receipt": lifecycle_receipt,
                "provider_status": live_result.get("provider_status"),
                "taint": "TOOL_OUTPUT",
                "error": live_result.get("error"),
            }
            if action == "logs":
                result["log_tail"] = live_result.get("log_tail", [])
                result["log_line_count"] = live_result.get("log_line_count", 0)
            if action == "cancel":
                result["cleanup_receipt"] = {"status": "cancel_requested" if live_result["ok"] else "cancel_failed", "raw_response_body_included": False}
            if action == "rollback":
                result["rollback_receipt"] = {"status": "rollback_requested" if live_result["ok"] else "rollback_failed", "raw_response_body_included": False, "raw_secret_values_included": False}
            if action == "artifact":
                content = live_result.get("artifact_content")
                if not isinstance(content, bytes) or not content:
                    result.update({"ok": False, "status": "failed", "error": live_result.get("error") or "hosted sandbox artifact response did not include downloadable content"})
                    return result
                artifact_dir = _workspace_root(self.connectors) / ".aegis" / "backend-artifacts"
                artifact_dir.mkdir(parents=True, exist_ok=True)
                artifact_dir.chmod(0o700)
                extension = _hosted_sandbox_artifact_extension(str(live_result.get("artifact_name") or ""), str(live_result.get("artifact_mime") or ""))
                artifact_path = artifact_dir / f"{backend_name}-{uuid4()}.{extension}"
                artifact_path.write_bytes(content)
                artifact_path.chmod(0o600)
                result.update({"artifact_path": str(artifact_path), "artifact_receipt": _artifact_receipt(artifact_path), "mime_type": live_result.get("artifact_mime") or "application/octet-stream"})
            return result
        command_hash = hashlib.sha256("\0".join([backend_name, *command_args]).encode("utf-8")).hexdigest()
        started = now_utc()
        live_result = _send_hosted_sandbox_request(url=url, token=token, backend=backend_name, command_args=command_args, command_hash=command_hash, timeout=timeout)
        return {
            "ok": live_result["ok"],
            "status": "submitted" if live_result["ok"] else "failed",
            "tool": name,
            "backend": backend_name,
            "domain": domain,
            "http_status": live_result["http_status"],
            "job_id": live_result.get("job_id"),
            "activation_receipt": {
                "status": "approved_activation",
                "backend": backend_name,
                "required_controls": ["human_approval", "brokered_backend_auth", "scope_limits", "rollback_receipts"],
                "allowed_host": domain,
                "secret_handle_present": handle.present,
                "raw_secret_values_included": False,
                "started_at": started,
            },
            "execution_receipt": {
                "command_sha256": command_hash,
                "argv_count": len(command_args),
                "timeout_seconds": timeout,
                "raw_command_logged": False,
                "raw_response_body_included": False,
            },
            "cleanup_receipt": {
                "status": "generic_lifecycle_available",
                "supported_actions": ["status", "logs", "cancel", "artifact", "rollback"],
                "rollback": "run hosted_sandbox_exec with action=cancel or action=rollback and the provider job_id",
            },
            "error": live_result.get("error"),
        }

    def _execute_ssh_backend(self, *, name: str, params: dict[str, Any], backend: dict[str, Any]) -> dict[str, Any]:
        config = dict(backend.get("adapter_config", {}))
        executable = _resolve_executable(str(config.get("executable", "ssh")))
        activation = _backend_activation_requirements(name=name, backend="ssh", backend_record=backend)
        if executable is None:
            return {"ok": False, "status": "not_configured", "tool": name, "backend": "ssh", "reason": "ssh executable is not available", **activation}
        host = str(params.get("host", "")).strip()
        user = str(params.get("user", config.get("user", ""))).strip()
        allowed_hosts = tuple(str(item) for item in config.get("allowed_hosts", ()))
        if not _host_allowed(host, allowed_hosts):
            return {"ok": False, "status": "scope_rejected", "tool": name, "backend": "ssh", "reason": f"ssh host {host!r} is not allowlisted", "verification_gates": ["scope_escape_rejection"]}
        try:
            remote_args = _safe_remote_command_args(str(params.get("command", "")))
        except ToolExecutionError as exc:
            return {"ok": False, "status": "scope_rejected", "tool": name, "backend": "ssh", "reason": str(exc), "verification_gates": ["scope_escape_rejection"]}
        key_secret = str(params.get("key_secret") or config.get("key_secret") or "AEGIS_SSH_PRIVATE_KEY")
        handle = self.secrets_broker.request_handle(name=key_secret, requester="ssh_backend", reason="SSH backend execution", scopes=("ssh:execute",))
        if not handle.present:
            return {"ok": False, "status": "not_configured", "tool": name, "backend": "ssh", "reason": f"secret {key_secret!r} is not configured", **activation}
        private_key = self.secrets_broker.resolve_for_authorized_tool(handle, requester="ssh_backend")
        timeout = int(config.get("timeout_seconds", 30))
        target = f"{user}@{host}" if user else host
        started = now_utc()
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="aegis-ssh-key-", delete=False) as key_file:
            key_file.write(private_key)
            key_file.write("\n")
            key_path = Path(key_file.name)
        try:
            os.chmod(key_path, 0o600)
            args = [
                "-i",
                str(key_path),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"ConnectTimeout={min(timeout, 30)}",
                target,
                "--",
                *remote_args,
            ]
            command_hash = hashlib.sha256("\0".join([target, *remote_args]).encode("utf-8")).hexdigest()
            completed = subprocess.run((executable, *args), cwd=_workspace_root(self.connectors), text=True, capture_output=True, timeout=timeout, check=False)
        finally:
            key_path.unlink(missing_ok=True)
        return {
            "ok": completed.returncode == 0,
            "status": "completed" if completed.returncode == 0 else "failed",
            "tool": name,
            "backend": "ssh",
            "host": host,
            "stdout": completed.stdout[:4000],
            "stderr": completed.stderr[:4000],
            "returncode": completed.returncode,
            "activation_receipt": {
                "status": "approved_activation",
                "backend": "ssh",
                "required_controls": ["human_approval", "brokered_backend_auth", "scope_limits", "rollback_receipts"],
                "allowed_host": host,
                "secret_handle_present": handle.present,
                "raw_secret_values_included": False,
                "started_at": started,
            },
            "execution_receipt": {
                "command_sha256": command_hash,
                "argv_count": len(remote_args),
                "timeout_seconds": timeout,
                "raw_command_logged": False,
            },
            "cleanup_receipt": {
                "status": "completed",
                "temporary_key_removed": True,
                "rollback": "remote command rollback is operator/provider specific",
            },
        }

    def _execute_docker_backend(self, *, name: str, params: dict[str, Any], backend: dict[str, Any]) -> dict[str, Any]:
        config = dict(backend.get("adapter_config", {}))
        executable = _resolve_executable(str(config.get("executable", "docker")))
        activation = _backend_activation_requirements(name=name, backend="docker", backend_record=backend)
        if executable is None:
            return {
                "ok": False,
                "status": "not_configured",
                "tool": name,
                "backend": "docker",
                "reason": "docker executable is not available",
                **activation,
            }

        try:
            args = _docker_args_for_tool(name=name, params=params, config=config)
        except ToolExecutionError as exc:
            return {
                "ok": False,
                "status": "scope_rejected",
                "tool": name,
                "backend": "docker",
                "reason": str(exc),
                "verification_gates": ["scope_escape_rejection"],
            }

        timeout = int(config.get("timeout_seconds", 30))
        started = now_utc()
        command_hash = hashlib.sha256("\0".join(args).encode("utf-8")).hexdigest()
        completed = subprocess.run((executable, *args), cwd=_workspace_root(self.connectors), text=True, capture_output=True, timeout=timeout, check=False)
        cleanup_receipt = {
            "status": "not_required" if name == "docker_run" and args[:1] != ["run"] else "requested",
            "auto_remove": "--rm" in args,
            "workspace_mounts_allowed": False,
        }
        return {
            "ok": completed.returncode == 0,
            "status": "completed" if completed.returncode == 0 else "failed",
            "tool": name,
            "backend": "docker",
            "stdout": completed.stdout[:4000],
            "stderr": completed.stderr[:4000],
            "returncode": completed.returncode,
            "activation_receipt": {
                "status": "approved_activation",
                "backend": "docker",
                "required_controls": ["human_approval", "scope_limits", "resource_limits", "rollback_receipts"],
                "limits": _docker_limit_receipt(config),
                "started_at": started,
            },
            "execution_receipt": {
                "command_sha256": command_hash,
                "argv_count": len(args) + 1,
                "timeout_seconds": timeout,
                "raw_command_logged": False,
            },
            "cleanup_receipt": cleanup_receipt,
        }

    def _execute_document_parse(self, *, params: dict[str, Any]) -> dict[str, Any]:
        read = self.connectors.get("filesystem").read(ConnectorRequest(operation="read", params={"path": params["path"], "limit": int(params.get("limit", 20000))}, scopes=("read",)))
        content = str(read.data.get("content", ""))
        return {"ok": read.ok, "path": read.data.get("path"), "text": content[:10000], "content_length": len(content), "taint": "FILE_CONTENT", "error": read.error}

    def _execute_spreadsheet_read(self, *, params: dict[str, Any]) -> dict[str, Any]:
        path = params.get("path") or params.get("range")
        if not path:
            raise ToolExecutionError("spreadsheet_read requires path or range")
        read = self.connectors.get("filesystem").read(ConnectorRequest(operation="read", params={"path": path, "limit": int(params.get("limit", 20000))}, scopes=("read",)))
        content = str(read.data.get("content", ""))
        rows = list(csv.reader(io.StringIO(content)))[: int(params.get("rows", 100))]
        return {"ok": read.ok, "path": read.data.get("path"), "values": rows, "rows": len(rows), "taint": "FILE_CONTENT", "error": read.error}

    def _execute_spreadsheet_write(self, *, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        output = io.StringIO()
        writer = csv.writer(output)
        for row in params.get("values", ()):
            writer.writerow(list(row))
        write = self.connectors.get("filesystem").write(
            ConnectorRequest(
                operation="write",
                params={"path": params["range"], "content": output.getvalue(), "overwrite": bool(params.get("overwrite", False))},
                scopes=("write",),
                approved=approved,
            )
        )
        return {"ok": write.ok, "path": write.data.get("path"), "updated": len(tuple(params.get("values", ()))), "error": write.error}

    def _execute_pdf_extract(self, *, params: dict[str, Any]) -> dict[str, Any]:
        root = _workspace_root(self.connectors)
        path = _resolve_under_root(root, params["path"])
        raw = path.read_bytes()[: int(params.get("limit", 20000))]
        text = re.sub(r"\s+", " ", raw.decode("utf-8", errors="ignore")).strip()
        return {"ok": path.is_file(), "path": str(path), "text": text[:10000], "content_length": len(raw), "taint": "FILE_CONTENT", "mode": "text_fallback"}

    def _execute_archive_extract(self, *, params: dict[str, Any]) -> dict[str, Any]:
        root = _workspace_root(self.connectors)
        path = _resolve_under_root(root, params["path"])
        limit = int(params.get("limit", 200))
        extract = bool(params.get("extract", False))
        destination = _resolve_under_root(root, params.get("destination") or f"{path.stem}-extracted")
        requested_members = {str(member) for member in params.get("members", ())}
        max_files = int(params.get("max_files", limit))
        max_bytes = int(params.get("max_bytes", 10 * 1024 * 1024))
        files: list[dict[str, Any]] = []
        extracted_files: list[str] = []
        total_bytes = 0
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                files = [{"name": info.filename, "size": info.file_size, "directory": info.is_dir()} for info in members[:limit]]
                if extract:
                    for info in members:
                        if requested_members and info.filename not in requested_members:
                            continue
                        if len(extracted_files) >= max_files:
                            raise ToolExecutionError("archive extraction exceeded max_files")
                        target = _safe_archive_member_path(destination, info.filename)
                        if info.is_dir():
                            target.mkdir(parents=True, exist_ok=True)
                            continue
                        total_bytes += int(info.file_size)
                        if total_bytes > max_bytes:
                            raise ToolExecutionError("archive extraction exceeded max_bytes")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with archive.open(info) as source, target.open("wb") as output:
                            output.write(source.read())
                        extracted_files.append(str(target.relative_to(root)))
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as archive:
                members = archive.getmembers()
                files = [{"name": item.name, "size": item.size, "directory": item.isdir()} for item in members[:limit]]
                if extract:
                    for item in members:
                        if requested_members and item.name not in requested_members:
                            continue
                        if item.issym() or item.islnk() or item.isdev():
                            raise ToolExecutionError(f"archive member {item.name!r} is not safe to extract")
                        if len(extracted_files) >= max_files:
                            raise ToolExecutionError("archive extraction exceeded max_files")
                        target = _safe_archive_member_path(destination, item.name)
                        if item.isdir():
                            target.mkdir(parents=True, exist_ok=True)
                            continue
                        if not item.isfile():
                            continue
                        total_bytes += int(item.size)
                        if total_bytes > max_bytes:
                            raise ToolExecutionError("archive extraction exceeded max_bytes")
                        source = archive.extractfile(item)
                        if source is None:
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with source, target.open("wb") as output:
                            output.write(source.read())
                        extracted_files.append(str(target.relative_to(root)))
        else:
            return {"ok": False, "path": str(path), "files": [], "error": "unsupported archive format"}
        return {
            "ok": True,
            "path": str(path),
            "files": files,
            "extracted": extract,
            "destination": str(destination) if extract else None,
            "extracted_files": extracted_files,
            "extracted_count": len(extracted_files),
            "extracted_bytes": total_bytes,
            "taint": "FILE_CONTENT",
        }

    def _execute_database_query(self, *, params: dict[str, Any]) -> dict[str, Any]:
        query = str(params["query"]).strip()
        if not _is_read_only_sql(query):
            raise ToolExecutionError("database_query only allows read-only SELECT, WITH, PRAGMA, or EXPLAIN statements")
        root = _workspace_root(self.connectors)
        path = _resolve_under_root(root, params["path"])
        uri = f"file:{path}?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            db.row_factory = sqlite3.Row
            rows = [dict(row) for row in db.execute(query).fetchmany(int(params.get("limit", 100)))]
        return {"ok": True, "path": str(path), "rows": rows, "row_count": len(rows), "taint": "DATABASE_CONTENT"}

    def _execute_embeddings_search(self, *, params: dict[str, Any]) -> dict[str, Any]:
        query = str(params["query"])
        matches = self.memory.retrieve_relevant(
            query,
            limit=int(params.get("limit", 10)),
            owner=str(params.get("owner", "local-user")),
            scope=str(params.get("scope", "workspace")) if params.get("scope", "workspace") is not None else None,
        )
        return {"ok": True, "query": query, "matches": matches, "mode": "governed_memory_search"}

    def _execute_vector_upsert(self, *, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        record = dict(params.get("record", {}))
        content = str(record.get("content") or params.get("content") or "")
        if not content.strip():
            raise ToolExecutionError("vector_upsert requires record.content or content")
        memory = self.memory.create_memory(
            memory_type=MemoryType.WORKFLOW,
            content=content,
            source="tool:vector_upsert",
            provenance={"tool": "vector_upsert", "record": {key: value for key, value in record.items() if key != "content"}},
            confidence=float(record.get("confidence", params.get("confidence", 0.8))),
            owner=str(record.get("owner", params.get("owner", "local-user"))),
            scope=str(record.get("scope", params.get("scope", "workspace"))),
            tags=tuple(str(item) for item in record.get("tags", params.get("tags", ("vector",)))),
            confirmed=approved,
        )
        return {"ok": True, "id": memory.id, "memory_id": memory.id, "mode": "governed_memory_vector_facade"}

    def _execute_email(self, *, name: str, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        operation = "draft_email" if name == "email_draft" else "send_email"
        request_params = {key: value for key, value in params.items() if key != "operation"}
        request_params["message"] = dict(params.get("message", {}))
        result = self.connectors.get("mock_graph").write(
            ConnectorRequest(operation=operation, params=request_params, scopes=("write",), approved=approved)
        )
        key = "draft_id" if name == "email_draft" else "message_id"
        return {
            "ok": result.ok,
            "status": "drafted" if name == "email_draft" and result.ok else "sent" if result.ok else "failed",
            key: f"mock-{operation}",
            "connector": result.connector,
            "mode": result.data.get("mode", "mock"),
            "accepted": result.data.get("accepted", {}),
            **_connector_activation_fields(result),
            "rollback": result.rollback,
            "error": result.error,
        }

    def _execute_graph_read(self, *, operation: str, output_key: str, params: dict[str, Any]) -> dict[str, Any]:
        if params.get("provider_url") or params.get("api_url"):
            return self._execute_productivity_live_read(operation=operation, output_key=output_key, params=params)
        result = self.connectors.get("mock_graph").read(ConnectorRequest(operation=operation, params=params, scopes=("read",)))
        data = result.data.get("data", {}) if isinstance(result.data.get("data"), dict) else {}
        return {"ok": result.ok, output_key: data.get(output_key, []), "connector": result.connector, "mode": "mock", "taint": "CONNECTOR_CONTENT", "error": result.error}

    def _execute_productivity_live_read(self, *, operation: str, output_key: str, params: dict[str, Any]) -> dict[str, Any]:
        url = str(params.get("provider_url") or params["api_url"])
        read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": url}, scopes=("read",)))
        if not read.ok:
            return {"ok": False, output_key: [], "connector": "http", "mode": "allowlisted_live_read", "error": read.error}
        try:
            decoded = json.loads(str(read.data.get("content", "")))
        except json.JSONDecodeError:
            return {"ok": False, output_key: [], "connector": "http", "mode": "allowlisted_live_read", "error": "productivity provider response must be JSON"}
        records = _extract_productivity_records(decoded, output_key=output_key)
        normalizer = _normalize_calendar_event if output_key == "events" else _normalize_contact_record
        return {
            "ok": True,
            output_key: [normalizer(record) for record in records],
            "connector": "http",
            "operation": operation,
            "mode": "allowlisted_live_read",
            "url": read.data.get("url", url),
            "taint": "WEB_CONTENT",
            "error": None,
        }

    def _execute_calendar_write(self, *, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        request_params = {key: value for key, value in params.items() if key != "operation"}
        request_params["event"] = dict(params.get("event", {}))
        result = self.connectors.get("mock_graph").write(
            ConnectorRequest(operation="create_event", params=request_params, scopes=("write",), approved=approved)
        )
        return {
            "ok": result.ok,
            "status": "created" if result.ok else "failed",
            "event_id": "mock-create_event",
            "connector": result.connector,
            "mode": result.data.get("mode", "mock"),
            "accepted": result.data.get("accepted", {}),
            **_connector_activation_fields(result),
            "rollback": result.rollback,
            "error": result.error,
        }

    def _execute_contacts_write(self, *, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        requested = str(params.get("operation", "create")).lower()
        operation = "update_contact" if requested in {"update", "update_contact"} else "create_contact"
        contact = dict(params.get("contact", {}))
        for key, value in params.items():
            if key not in {"operation", "contact"} and key not in contact:
                contact[key] = value
        request_params = {key: value for key, value in params.items() if key != "operation"}
        request_params["contact"] = contact
        result = self.connectors.get("mock_graph").write(
            ConnectorRequest(operation=operation, params=request_params, scopes=("write",), approved=approved)
        )
        return {
            "ok": result.ok,
            "operation": operation,
            "status": "accepted" if result.ok else "failed",
            "contact_id": str(contact.get("id") or contact.get("contact_id") or contact.get("email") or f"mock-{operation}"),
            "connector": result.connector,
            "mode": result.data.get("mode", "mock"),
            "accepted": result.data.get("accepted", {}),
            **_connector_activation_fields(result),
            "rollback": result.rollback,
            "error": result.error,
        }

    def _execute_github(self, *, name: str, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        requested = str(params.get("operation", "read")).lower()
        connector = self.connectors.get("github")
        if name == "github_pr":
            if requested in {"rollback_comment", "rollback_pull_request_comment", "delete_comment"}:
                result = connector.rollback(ConnectorRequest(operation="rollback_pull_request_comment", params=params, scopes=("write",), approved=approved))
                return {
                    "ok": result.ok,
                    "operation": "rollback_pull_request_comment",
                    "connector": result.connector,
                    "mode": result.data.get("mode"),
                    "rate_limit": result.data.get("rate_limit"),
                    "rollback_receipt": result.data.get("rollback_receipt"),
                    **_connector_activation_fields(result),
                    "rollback": result.rollback,
                    "error": result.error,
                }
            if requested in {"autofix_apply", "autofix_patch", "apply_autofix", "apply_patch", "local_patch"}:
                return self._execute_github_pr_autofix_patch(params=params)
            if requested in {"autofix_response", "autofix_comment", "autofix_report", "post_autofix", "provider_autofix"}:
                write_params = {key: value for key, value in params.items() if key != "operation"}
                write_params["body"] = _github_pr_autofix_response_body(params)
                result = connector.write(ConnectorRequest(operation="comment_on_pull_request", params=write_params, scopes=("write",), approved=approved))
                mode = result.data.get("mode", "mock" if result.data.get("mock") else None)
                return {
                    "ok": result.ok,
                    "operation": "pr_autofix_provider_response",
                    "connector": result.connector,
                    "mode": mode,
                    "status": "autofix_response_recorded" if result.ok else "autofix_response_blocked",
                    "auto_apply": False,
                    "provider_writes_performed": bool(result.ok and mode == "live_write"),
                    "mock_write_recorded": bool(result.ok and result.data.get("mock")),
                    "raw_secret_values_included": False,
                    "accepted": result.data.get("accepted", {}),
                    **_connector_activation_fields(result),
                    "rollback": result.rollback,
                    "error": result.error,
                }
            if requested in {"autofix", "autofix_plan", "review_autofix", "fix_plan"}:
                if params.get("provider_url") or params.get("api_url"):
                    comments = self._execute_github_live_read(
                        kind="pull_request_comments",
                        operation="read_pull_request_comments",
                        params=params,
                    )
                else:
                    result = connector.read(ConnectorRequest(operation="read_pull_request_comments", params=params, scopes=("read",)))
                    comments = {
                        "ok": result.ok,
                        "operation": "read_pull_request_comments",
                        "connector": result.connector,
                        "data": result.data.get("data", {}),
                        "taint": "CONNECTOR_CONTENT",
                        "error": result.error,
                    }
                return _github_pr_autofix_plan(comments)
            if requested in {"comments", "review_comments", "pull_request_comments", "read_comments"}:
                if params.get("provider_url") or params.get("api_url"):
                    return self._execute_github_live_read(
                        kind="pull_request_comments",
                        operation="read_pull_request_comments",
                        params=params,
                    )
                result = connector.read(ConnectorRequest(operation="read_pull_request_comments", params=params, scopes=("read",)))
                return {
                    "ok": result.ok,
                    "operation": "read_pull_request_comments",
                    "connector": result.connector,
                    "data": result.data.get("data", {}),
                    "taint": "CONNECTOR_CONTENT",
                    "error": result.error,
                }
            if requested in {"comment", "comment_on_pull_request", "write"}:
                result = connector.write(ConnectorRequest(operation="comment_on_pull_request", params=params, scopes=("write",), approved=approved))
                return {"ok": result.ok, "operation": "comment_on_pull_request", "connector": result.connector, "accepted": result.data.get("accepted", {}), **_connector_activation_fields(result), "rollback": result.rollback, "error": result.error}
            if params.get("provider_url") or params.get("api_url"):
                return self._execute_github_live_read(kind="pull_request", operation="read_pull_request", params=params)
            result = connector.read(ConnectorRequest(operation="read_pull_request", params=params, scopes=("read",)))
            return {"ok": result.ok, "operation": "read_pull_request", "connector": result.connector, "data": result.data.get("data", {}), "taint": "CONNECTOR_CONTENT", "error": result.error}
        if requested in {"create", "create_issue", "write"}:
            result = connector.write(ConnectorRequest(operation="create_issue", params=params, scopes=("write",), approved=approved))
            return {"ok": result.ok, "operation": "create_issue", "connector": result.connector, "accepted": result.data.get("accepted", {}), **_connector_activation_fields(result), "rollback": result.rollback, "error": result.error}
        if requested in {"rollback", "rollback_issue", "close_issue"}:
            result = connector.rollback(ConnectorRequest(operation="rollback_issue", params=params, scopes=("write",), approved=approved))
            return {
                "ok": result.ok,
                "operation": "rollback_issue",
                "connector": result.connector,
                "mode": result.data.get("mode"),
                "rate_limit": result.data.get("rate_limit"),
                "rollback_receipt": result.data.get("rollback_receipt"),
                **_connector_activation_fields(result),
                "rollback": result.rollback,
                "error": result.error,
            }
        if params.get("provider_url") or params.get("api_url"):
            return self._execute_github_live_read(kind="issue", operation="read_issue", params=params)
        result = connector.read(ConnectorRequest(operation="read_issue", params=params, scopes=("read",)))
        return {"ok": result.ok, "operation": "read_issue", "connector": result.connector, "data": result.data.get("data", {}), "taint": "CONNECTOR_CONTENT", "error": result.error}

    def _execute_github_pr_autofix_patch(self, *, params: dict[str, Any]) -> dict[str, Any]:
        patch = str(params.get("patch") or params.get("unified_diff") or "")
        if not patch.strip():
            raise ToolExecutionError("github_pr autofix patch requires patch or unified_diff")
        action_items = _github_pr_action_items(params)
        if not action_items:
            raise ToolExecutionError("github_pr autofix patch requires autofix_plan.action_items or action_items")
        changed_files = _changed_files_from_patch(patch)
        referenced_files = _github_pr_referenced_files(action_items)
        linked_comment_ids = [
            item.get("comment_id")
            for item in action_items
            if isinstance(item, dict) and item.get("comment_id") is not None
        ]
        apply_result = self._execute_diff_apply(params={"patch": patch})
        applied = bool(apply_result.get("ok"))
        return {
            "ok": applied,
            "operation": "pr_autofix_local_patch_application",
            "connector": "github",
            "status": "autofix_patch_applied" if applied else "autofix_patch_check_failed",
            "mode": "approved_review_comment_patch_application",
            "changed_files": changed_files,
            "referenced_files": sorted(referenced_files),
            "unreferenced_changed_files": sorted(path for path in changed_files if path not in referenced_files),
            "linked_comment_ids": linked_comment_ids[:50],
            "comment_linked_action_count": len(action_items),
            "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest(),
            "auto_generated_patch": False,
            "approval_required_before_application": True,
            "provider_writes_performed": False,
            "raw_secret_values_included": False,
            "post_apply_required_controls": [
                "workspace_diff_review",
                "targeted_tests_before_commit",
                "approval_before_provider_response",
            ],
            "apply_result": apply_result,
        }

    def _execute_github_live_read(self, *, kind: str, operation: str, params: dict[str, Any]) -> dict[str, Any]:
        url = str(params.get("provider_url") or params["api_url"])
        read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": url}, scopes=("read",)))
        if not read.ok:
            return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "data": {}, "error": read.error}
        try:
            decoded = json.loads(str(read.data.get("content", "")))
        except json.JSONDecodeError:
            return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "data": {}, "error": "GitHub provider response must be JSON"}
        if kind == "pull_request_comments":
            if not isinstance(decoded, list):
                return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "data": {}, "error": "GitHub PR comments response must be a JSON array"}
            data = {
                "kind": kind,
                "count": len(decoded),
                "comments": [
                    _normalize_github_pr_comment(item)
                    for item in decoded[:100]
                    if isinstance(item, dict)
                ],
            }
            return {
                "ok": True,
                "operation": operation,
                "connector": "http",
                "mode": "allowlisted_live_read",
                "url": read.data.get("url", url),
                "data": data,
                "taint": "WEB_CONTENT",
                "error": None,
            }
        if not isinstance(decoded, dict):
            return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "data": {}, "error": "GitHub provider response must be a JSON object"}
        return {
            "ok": True,
            "operation": operation,
            "connector": "http",
            "mode": "allowlisted_live_read",
            "url": read.data.get("url", url),
            "data": _normalize_github_record(decoded, kind=kind),
            "taint": "WEB_CONTENT",
            "error": None,
        }

    def _execute_gitlab(self, *, name: str, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        requested = str(params.get("operation", "read")).lower()
        connector = self.connectors.get("gitlab")
        if name == "gitlab_merge_request":
            if requested in {"rollback_note", "rollback_merge_request_note", "delete_note"}:
                result = connector.rollback(ConnectorRequest(operation="rollback_merge_request_note", params=params, scopes=("write",), approved=approved))
                return {
                    "ok": result.ok,
                    "operation": "rollback_merge_request_note",
                    "connector": result.connector,
                    "mode": result.data.get("mode"),
                    "rate_limit": result.data.get("rate_limit"),
                    "rollback_receipt": result.data.get("rollback_receipt"),
                    **_connector_activation_fields(result),
                    "rollback": result.rollback,
                    "error": result.error,
                }
            if requested in {"comment", "note", "comment_on_merge_request", "write"}:
                result = connector.write(ConnectorRequest(operation="comment_on_merge_request", params=params, scopes=("write",), approved=approved))
                return {"ok": result.ok, "operation": "comment_on_merge_request", "connector": result.connector, "accepted": result.data.get("accepted", {}), **_connector_activation_fields(result), "rollback": result.rollback, "error": result.error}
            if params.get("provider_url") or params.get("api_url"):
                return self._execute_gitlab_live_read(kind="merge_request", operation="read_merge_request", params=params)
            result = connector.read(ConnectorRequest(operation="read_merge_request", params=params, scopes=("read",)))
            return {"ok": result.ok, "operation": "read_merge_request", "connector": result.connector, "data": result.data.get("data", {}), "taint": "CONNECTOR_CONTENT", "error": result.error}
        if requested in {"create", "create_issue", "write"}:
            result = connector.write(ConnectorRequest(operation="create_issue", params=params, scopes=("write",), approved=approved))
            return {"ok": result.ok, "operation": "create_issue", "connector": result.connector, "accepted": result.data.get("accepted", {}), **_connector_activation_fields(result), "rollback": result.rollback, "error": result.error}
        if requested in {"rollback", "rollback_issue", "close_issue"}:
            result = connector.rollback(ConnectorRequest(operation="rollback_issue", params=params, scopes=("write",), approved=approved))
            return {
                "ok": result.ok,
                "operation": "rollback_issue",
                "connector": result.connector,
                "mode": result.data.get("mode"),
                "rate_limit": result.data.get("rate_limit"),
                "rollback_receipt": result.data.get("rollback_receipt"),
                **_connector_activation_fields(result),
                "rollback": result.rollback,
                "error": result.error,
            }
        if params.get("provider_url") or params.get("api_url"):
            return self._execute_gitlab_live_read(kind="issue", operation="read_issue", params=params)
        result = connector.read(ConnectorRequest(operation="read_issue", params=params, scopes=("read",)))
        return {"ok": result.ok, "operation": "read_issue", "connector": result.connector, "data": result.data.get("data", {}), "taint": "CONNECTOR_CONTENT", "error": result.error}

    def _execute_gitlab_live_read(self, *, kind: str, operation: str, params: dict[str, Any]) -> dict[str, Any]:
        url = str(params.get("provider_url") or params["api_url"])
        read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": url}, scopes=("read",)))
        if not read.ok:
            return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "data": {}, "error": read.error}
        try:
            decoded = json.loads(str(read.data.get("content", "")))
        except json.JSONDecodeError:
            return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "data": {}, "error": "GitLab provider response must be JSON"}
        if not isinstance(decoded, dict):
            return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "data": {}, "error": "GitLab provider response must be a JSON object"}
        return {
            "ok": True,
            "operation": operation,
            "connector": "http",
            "mode": "allowlisted_live_read",
            "url": read.data.get("url", url),
            "data": _normalize_gitlab_record(decoded, kind=kind),
            "taint": "WEB_CONTENT",
            "error": None,
        }

    def _execute_service_ticket_read(self, *, params: dict[str, Any]) -> dict[str, Any]:
        requested = str(params.get("operation", "search")).lower()
        operation = "read_ticket" if requested in {"read", "get", "read_ticket"} else "search_tickets"
        if params.get("provider_url") or params.get("api_url"):
            url = str(params.get("provider_url") or params["api_url"])
            read = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": url}, scopes=("read",)))
            if not read.ok:
                return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "tickets": [], "error": read.error}
            try:
                decoded = json.loads(str(read.data.get("content", "")))
            except json.JSONDecodeError:
                return {"ok": False, "operation": operation, "connector": "http", "mode": "allowlisted_live_read", "tickets": [], "error": "service-desk provider response must be JSON"}
            return {
                "ok": True,
                "operation": operation,
                "connector": "http",
                "mode": "allowlisted_live_read",
                "url": read.data.get("url", url),
                "tickets": [_normalize_service_ticket(ticket) for ticket in _extract_service_tickets(decoded)],
                "taint": "WEB_CONTENT",
                "error": None,
            }
        result = self.connectors.get("mock_servicenow").read(ConnectorRequest(operation=operation, params=params, scopes=("read",)))
        data = result.data.get("data", {}) if isinstance(result.data.get("data"), dict) else {}
        return {"ok": result.ok, "operation": operation, "connector": result.connector, "mode": "mock", "tickets": data.get("tickets", []), "taint": "CONNECTOR_CONTENT", "error": result.error}

    def _execute_service_ticket_write(self, *, params: dict[str, Any], approved: bool) -> dict[str, Any]:
        requested = str(params.get("operation", "create")).lower()
        if requested in {"update", "update_ticket"}:
            operation = "update_ticket"
        elif requested in {"close", "close_ticket", "resolve"}:
            operation = "close_ticket"
        elif requested in {"rollback", "rollback_close", "rollback_close_ticket", "reopen"}:
            operation = "rollback_close_ticket"
        else:
            operation = "create_ticket"
        payload = dict(params.get("ticket", {}))
        for key, value in params.items():
            if key not in {"operation", "ticket"} and key not in payload:
                payload[key] = value
        request_params = {key: value for key, value in params.items() if key != "operation"}
        request_params["ticket"] = payload
        connector = self.connectors.get("mock_servicenow")
        request = ConnectorRequest(operation=operation, params=request_params, scopes=("write",), approved=approved)
        result = connector.rollback(request) if operation == "rollback_close_ticket" else connector.write(request)
        return {
            "ok": result.ok,
            "operation": operation,
            "connector": result.connector,
            "status": "accepted" if result.ok else "failed",
            "ticket_id": str(payload.get("id") or payload.get("number") or f"mock-{operation}"),
            "mode": result.data.get("mode", "mock"),
            "accepted": result.data.get("accepted", {}),
            "rate_limit": result.data.get("rate_limit"),
            "rollback_receipt": result.data.get("rollback_receipt"),
            **_connector_activation_fields(result),
            "rollback": result.rollback,
            "error": result.error,
        }

    def _execute_browser(self, name: str, params: dict[str, Any], *, approved: bool) -> dict[str, Any]:
        default_action = {
            "browser": "navigate",
            "browser_click": "click",
            "browser_fill": "fill",
            "browser_submit": "submit",
            "browser_screenshot": "screenshot",
            "browser_render_screenshot": "render_screenshot",
            "browser_extract_table": "extract_table",
            "browser_dom_snapshot": "dom_snapshot",
            "browser_close": "close",
        }[name]
        action = str(params.get("action", default_action))
        session_id = str(params["session_id"]) if params.get("session_id") else None
        live_actions = {"live_navigate", "live_click", "live_fill", "live_submit", "live_screenshot", "live_render_screenshot", "live_evaluate"}
        if action in live_actions or bool(params.get("live")):
            selector = str(params["selector"]) if params.get("selector") else None
            return self.browser.deny_live_automation(action=action, session_id=session_id, selector=selector)
        if action == "session":
            return self.browser.create_session(label=str(params.get("label", "Browser session")))
        if action == "navigate":
            return self.browser.navigate(session_id=session_id, url=str(params["url"]))
        if action == "extract":
            if session_id is None:
                raise ToolExecutionError("browser extract requires session_id")
            return self.browser.extract_text(session_id=session_id)
        if action == "screenshot":
            if session_id is None:
                raise ToolExecutionError("browser screenshot requires session_id")
            return self.browser.screenshot(session_id=session_id)
        if action == "render_screenshot":
            if session_id is None:
                raise ToolExecutionError("browser render screenshot requires session_id")
            return self.browser.render_screenshot(session_id=session_id)
        if action == "extract_table":
            if session_id is None:
                raise ToolExecutionError("browser table extraction requires session_id")
            return self.browser.extract_table(session_id=session_id, selector=str(params["selector"]) if params.get("selector") else None)
        if action == "dom_snapshot":
            if session_id is None:
                raise ToolExecutionError("browser DOM snapshot requires session_id")
            return self.browser.dom_snapshot(session_id=session_id, selector=str(params["selector"]) if params.get("selector") else None)
        if action == "inspect":
            if session_id is None:
                raise ToolExecutionError("browser inspect requires session_id")
            return self.browser.inspect(session_id=session_id)
        if action == "click":
            if session_id is None:
                raise ToolExecutionError("browser click requires session_id")
            return self.browser.click(session_id=session_id, selector=str(params["selector"]), approved=approved)
        if action == "fill":
            if session_id is None:
                raise ToolExecutionError("browser fill requires session_id")
            return self.browser.fill(session_id=session_id, fields=dict(params.get("fields", {})), approved=approved)
        if action == "submit":
            if session_id is None:
                raise ToolExecutionError("browser submit requires session_id")
            return self.browser.submit(session_id=session_id, selector=str(params["selector"]) if params.get("selector") else None, approved=approved)
        if action == "close":
            if session_id is None:
                raise ToolExecutionError("browser close requires session_id")
            return self.browser.close_session(session_id=session_id)
        raise ToolExecutionError(f"unsupported browser action: {action}")


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


def _jsonish(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if key != "content"}


def _connector_activation_fields(result: ConnectorResult) -> dict[str, Any]:
    activation = result.data.get("activation")
    if not isinstance(activation, dict):
        return {}
    return {"activation": activation, "preflight_status": activation.get("preflight_status", "unknown")}


def _json_object(content: str) -> dict[str, Any]:
    try:
        decoded = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("weather provider response must be a JSON object") from exc
    if not isinstance(decoded, dict):
        raise ValueError("weather provider response must be a JSON object")
    return decoded


def _bounded_float(value: Any, *, minimum: float, maximum: float, label: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ToolExecutionError(f"{label} must be numeric") from exc
    if parsed < minimum or parsed > maximum:
        raise ToolExecutionError(f"{label} must be between {minimum:g} and {maximum:g}")
    return parsed


def _weather_period(period: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(period.get("name", "")),
        "start_time": str(period.get("startTime", "")),
        "end_time": str(period.get("endTime", "")),
        "temperature": period.get("temperature"),
        "temperature_unit": str(period.get("temperatureUnit", "")),
        "wind_speed": str(period.get("windSpeed", "")),
        "short_forecast": str(period.get("shortForecast", "")),
        "detailed_forecast": str(period.get("detailedForecast", ""))[:500],
    }


def _extract_geocode_coordinates(decoded: Any) -> tuple[float, float] | None:
    candidate: Any = decoded
    if isinstance(decoded, list):
        candidate = decoded[0] if decoded else None
    if not isinstance(candidate, dict):
        return None
    lat_value = candidate.get("lat", candidate.get("latitude"))
    lng_value = candidate.get("lon", candidate.get("lng", candidate.get("longitude")))
    if lat_value is None or lng_value is None:
        point = candidate.get("point")
        if isinstance(point, dict):
            lat_value = point.get("lat", point.get("latitude"))
            lng_value = point.get("lon", point.get("lng", point.get("longitude")))
    if lat_value is None or lng_value is None:
        return None
    try:
        latitude = _bounded_float(lat_value, minimum=-90.0, maximum=90.0, label="latitude")
        longitude = _bounded_float(lng_value, minimum=-180.0, maximum=180.0, label="longitude")
    except ToolExecutionError:
        return None
    return latitude, longitude


def _local_image_metadata(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"format": "missing"}
    header = path.read_bytes()[:4096]
    if header.startswith(b"\x89PNG\r\n\x1a\n") and len(header) >= 24:
        return {
            "format": "png",
            "width": int.from_bytes(header[16:20], "big"),
            "height": int.from_bytes(header[20:24], "big"),
        }
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        if len(header) >= 10:
            return {
                "format": "gif",
                "width": int.from_bytes(header[6:8], "little"),
                "height": int.from_bytes(header[8:10], "little"),
            }
        return {"format": "gif"}
    if header.startswith(b"\xff\xd8"):
        dimensions = _jpeg_dimensions(header)
        metadata: dict[str, Any] = {"format": "jpeg"}
        if dimensions is not None:
            metadata.update({"width": dimensions[0], "height": dimensions[1]})
        return metadata
    return {"format": "unknown"}


def _local_video_metadata(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"format": "missing"}
    header = path.read_bytes()[:1024 * 1024]
    if len(header) >= 12 and header[4:8] == b"ftyp":
        metadata = {"format": "mp4", "brand": header[8:12].decode("ascii", errors="replace").strip()}
        duration = _mp4_duration_seconds(header)
        if duration is not None:
            metadata["duration_seconds"] = duration
        return metadata
    if header.startswith(b"\x1a\x45\xdf\xa3"):
        return {"format": "matroska_or_webm"}
    if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"AVI ":
        return {"format": "avi"}
    if header.startswith(b"OggS"):
        return {"format": "ogg"}
    if header.startswith(b"FLV"):
        return {"format": "flv"}
    if header.startswith(b"\x00\x00\x01\xba") or header.startswith(b"\x00\x00\x01\xb3"):
        return {"format": "mpeg"}
    return {"format": "unknown"}


def _mp4_duration_seconds(data: bytes) -> float | None:
    mvhd = _find_mp4_box(data, b"mvhd")
    if mvhd is None or len(mvhd) < 20:
        return None
    version = mvhd[0]
    try:
        if version == 1 and len(mvhd) >= 32:
            timescale = int.from_bytes(mvhd[20:24], "big")
            duration = int.from_bytes(mvhd[24:32], "big")
        else:
            timescale = int.from_bytes(mvhd[12:16], "big")
            duration = int.from_bytes(mvhd[16:20], "big")
    except ValueError:
        return None
    if timescale <= 0:
        return None
    return round(duration / timescale, 3)


def _find_mp4_box(data: bytes, target: bytes, *, depth: int = 0) -> bytes | None:
    if depth > 6:
        return None
    index = 0
    while index + 8 <= len(data):
        size = int.from_bytes(data[index : index + 4], "big")
        box_type = data[index + 4 : index + 8]
        header_size = 8
        if size == 1:
            if index + 16 > len(data):
                return None
            size = int.from_bytes(data[index + 8 : index + 16], "big")
            header_size = 16
        elif size == 0:
            size = len(data) - index
        if size < header_size or index + size > len(data):
            return None
        payload = data[index + header_size : index + size]
        if box_type == target:
            return payload
        if box_type in {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts"}:
            nested = _find_mp4_box(payload, target, depth=depth + 1)
            if nested is not None:
                return nested
        index += size
    return None


def _jpeg_dimensions(data: bytes) -> tuple[int, int] | None:
    index = 2
    while index + 9 <= len(data):
        if data[index] != 0xFF:
            index += 1
            continue
        marker = data[index + 1]
        index += 2
        while marker == 0xFF and index < len(data):
            marker = data[index]
            index += 1
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if index + 2 > len(data):
            return None
        segment_length = int.from_bytes(data[index : index + 2], "big")
        if segment_length < 2 or index + segment_length > len(data):
            return None
        if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF} and segment_length >= 7:
            height = int.from_bytes(data[index + 3 : index + 5], "big")
            width = int.from_bytes(data[index + 5 : index + 7], "big")
            return width, height
        index += segment_length
    return None


def _write_tts_tone(path: Path, *, text: str) -> float:
    sample_rate = 8000
    duration_seconds = min(3.0, max(0.35, 0.08 * max(len(text.split()), 1)))
    frame_count = int(sample_rate * duration_seconds)
    amplitude = 9000
    frequency = 440
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(sample_rate)
        frames = bytearray()
        for index in range(frame_count):
            phase = (index * frequency) % sample_rate
            value = amplitude if phase < sample_rate // 2 else -amplitude
            frames.extend(struct.pack("<h", value))
        handle.writeframes(bytes(frames))
    path.chmod(0o600)
    return round(duration_seconds, 3)


def _write_silence_wav(path: Path, *, duration_seconds: float) -> None:
    sample_rate = 8000
    frame_count = int(sample_rate * duration_seconds)
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(sample_rate)
        handle.writeframes(b"\x00\x00" * frame_count)
    path.chmod(0o600)


def _write_prompt_png(path: Path, *, prompt: str, source: str = "") -> tuple[int, int]:
    width = 128
    height = 80
    seed = hashlib.sha256(f"{prompt}\0{source}".encode("utf-8", errors="replace")).digest()
    base_r, base_g, base_b = seed[0], seed[1], seed[2]
    accent_r, accent_g, accent_b = seed[3], seed[4], seed[5]
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            band = (x // 16 + y // 10) % 2
            blend = (x * 3 + y * 5 + seed[(x + y) % len(seed)]) % 64
            if band:
                rows.extend(((accent_r + blend) % 256, (accent_g + blend // 2) % 256, (accent_b + blend * 2) % 256))
            else:
                rows.extend(((base_r + blend * 2) % 256, (base_g + blend) % 256, (base_b + blend // 2) % 256))
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(bytes(rows), level=9))
        + _png_chunk(b"IEND", b"")
    )
    path.chmod(0o600)
    return width, height


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


_TARGET_LANGUAGE_ALIASES = {
    "es": "es",
    "spa": "es",
    "spanish": "es",
    "fr": "fr",
    "fre": "fr",
    "fra": "fr",
    "french": "fr",
    "de": "de",
    "ger": "de",
    "deu": "de",
    "german": "de",
}

_LOCAL_TRANSLATION_GLOSSARY = {
    "es": {
        "aegis": "Aegis",
        "agent": "agente",
        "approval": "aprobacion",
        "approvals": "aprobaciones",
        "audit": "auditoria",
        "browser": "navegador",
        "cancel": "cancelar",
        "close": "cerrar",
        "closed": "cerrado",
        "hello": "hola",
        "memory": "memoria",
        "policy": "politica",
        "repair": "reparacion",
        "resume": "reanudar",
        "safe": "seguro",
        "secure": "seguro",
        "session": "sesion",
        "sessions": "sesiones",
        "task": "tarea",
        "tasks": "tareas",
        "tool": "herramienta",
        "tools": "herramientas",
        "web": "web",
    },
    "fr": {
        "aegis": "Aegis",
        "agent": "agent",
        "approval": "approbation",
        "approvals": "approbations",
        "audit": "audit",
        "browser": "navigateur",
        "cancel": "annuler",
        "close": "fermer",
        "closed": "ferme",
        "hello": "bonjour",
        "memory": "memoire",
        "policy": "politique",
        "repair": "reparation",
        "resume": "reprendre",
        "safe": "sur",
        "secure": "securise",
        "session": "session",
        "sessions": "sessions",
        "task": "tache",
        "tasks": "taches",
        "tool": "outil",
        "tools": "outils",
        "web": "web",
    },
    "de": {
        "aegis": "Aegis",
        "agent": "Agent",
        "approval": "Freigabe",
        "approvals": "Freigaben",
        "audit": "Audit",
        "browser": "Browser",
        "cancel": "abbrechen",
        "close": "schliessen",
        "closed": "geschlossen",
        "hello": "hallo",
        "memory": "Gedachtnis",
        "policy": "Richtlinie",
        "repair": "Reparatur",
        "resume": "fortsetzen",
        "safe": "sicher",
        "secure": "sicher",
        "session": "Sitzung",
        "sessions": "Sitzungen",
        "task": "Aufgabe",
        "tasks": "Aufgaben",
        "tool": "Werkzeug",
        "tools": "Werkzeuge",
        "web": "Web",
    },
}


def _local_translate(source: str, *, target: str) -> dict[str, Any]:
    normalized_target = _TARGET_LANGUAGE_ALIASES.get(target.strip().lower(), target.strip().lower())
    glossary = _LOCAL_TRANSLATION_GLOSSARY.get(normalized_target)
    if glossary is None:
        return {
            "ok": False,
            "target": target,
            "translation": source[:1000],
            "mode": "local_glossary",
            "coverage": 0.0,
            "error": "unsupported local translation target",
            "supported_targets": sorted(_LOCAL_TRANSLATION_GLOSSARY),
        }
    translated_tokens: list[str] = []
    matched = 0
    words = 0
    for token in re.findall(r"\w+|[^\w]+", source[:1000], flags=re.UNICODE):
        if re.fullmatch(r"\w+", token, flags=re.UNICODE):
            words += 1
            replacement = glossary.get(token.lower())
            if replacement is not None:
                matched += 1
                translated_tokens.append(_match_case(token, replacement))
            else:
                translated_tokens.append(token)
        else:
            translated_tokens.append(token)
    coverage = round(matched / words, 3) if words else 1.0
    return {
        "ok": True,
        "target": normalized_target,
        "translation": "".join(translated_tokens),
        "mode": "local_glossary",
        "coverage": coverage,
        "quality": "glossary" if coverage == 1.0 else "partial_glossary",
        "untranslated_terms": max(words - matched, 0),
    }


def _match_case(source: str, translated: str) -> str:
    if source.isupper():
        return translated.upper()
    if source[:1].isupper():
        return translated[:1].upper() + translated[1:]
    return translated


def _extract_search_results(decoded: Any, *, limit: int) -> list[dict[str, str]]:
    candidates: Any = decoded
    if isinstance(decoded, dict):
        for key_path in (
            ("results",),
            ("items",),
            ("organic_results",),
            ("webPages", "value"),
        ):
            candidates = decoded
            for key in key_path:
                candidates = candidates.get(key) if isinstance(candidates, dict) else None
            if isinstance(candidates, list):
                break
    if not isinstance(candidates, list):
        return []
    results: list[dict[str, str]] = []
    for item in candidates:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("name") or "")
        url = str(item.get("url") or item.get("link") or item.get("href") or "")
        snippet = str(item.get("snippet") or item.get("description") or item.get("content") or item.get("summary") or "")
        if not title and not url and not snippet:
            continue
        results.append({"title": title[:300], "url": url[:1000], "snippet": snippet[:1000]})
        if len(results) >= limit:
            break
    return results


def _local_workspace_search(root: Path, *, query: str, limit: int) -> list[dict[str, str]]:
    terms = [term.casefold() for term in re.findall(r"[A-Za-z0-9_./-]+", query) if len(term) >= 2]
    if not terms:
        return []
    results: list[dict[str, str]] = []
    for path in _iter_searchable_workspace_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        haystack = text.casefold()
        if not all(term in haystack for term in terms[:4]):
            continue
        rel = path.relative_to(root).as_posix()
        line_no, snippet = _search_snippet(text, terms)
        results.append(
            {
                "title": rel,
                "url": f"workspace://{rel}",
                "snippet": snippet,
                "line": str(line_no),
            }
        )
        if len(results) >= limit:
            break
    return results


def _iter_searchable_workspace_files(root: Path) -> list[Path]:
    excluded_dirs = {".aegis", ".git", "__pycache__", ".pytest_cache", ".mypy_cache", "node_modules", "dist", "build"}
    allowed_suffixes = {".md", ".txt", ".py", ".toml", ".json", ".yaml", ".yml", ".html", ".css", ".js"}
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in excluded_dirs for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() not in allowed_suffixes:
            continue
        try:
            if path.stat().st_size > 256_000:
                continue
        except OSError:
            continue
        files.append(path)
        if len(files) >= 500:
            break
    return files


def _search_snippet(text: str, terms: list[str]) -> tuple[int, str]:
    for line_no, line in enumerate(text.splitlines(), start=1):
        folded = line.casefold()
        if any(term in folded for term in terms):
            return line_no, " ".join(line.strip().split())[:1000]
    return 1, " ".join(text[:1000].split())


def _normalize_github_record(decoded: dict[str, Any], *, kind: str) -> dict[str, Any]:
    user = decoded.get("user")
    if not isinstance(user, dict):
        user = {}
    normalized: dict[str, Any] = {
        "kind": kind,
        "number": decoded.get("number"),
        "id": decoded.get("id"),
        "title": str(decoded.get("title", ""))[:500],
        "state": str(decoded.get("state", ""))[:100],
        "url": str(decoded.get("url", ""))[:1000],
        "html_url": str(decoded.get("html_url", ""))[:1000],
        "user": str(user.get("login", ""))[:200],
        "created_at": str(decoded.get("created_at", ""))[:100],
        "updated_at": str(decoded.get("updated_at", ""))[:100],
        "body_preview": str(decoded.get("body", ""))[:1000],
    }
    if kind == "pull_request":
        base = decoded.get("base") if isinstance(decoded.get("base"), dict) else {}
        head = decoded.get("head") if isinstance(decoded.get("head"), dict) else {}
        normalized.update(
            {
                "merged": bool(decoded.get("merged", False)),
                "draft": bool(decoded.get("draft", False)),
                "base_ref": str(base.get("ref", ""))[:200],
                "head_ref": str(head.get("ref", ""))[:200],
            }
        )
    return normalized


def _normalize_github_pr_comment(decoded: dict[str, Any]) -> dict[str, Any]:
    user = decoded.get("user")
    if not isinstance(user, dict):
        user = {}
    return {
        "id": decoded.get("id"),
        "path": str(decoded.get("path", ""))[:1000],
        "line": decoded.get("line") or decoded.get("position"),
        "side": str(decoded.get("side", ""))[:50],
        "user": str(user.get("login", ""))[:200],
        "created_at": str(decoded.get("created_at", ""))[:100],
        "updated_at": str(decoded.get("updated_at", ""))[:100],
        "html_url": str(decoded.get("html_url", ""))[:1000],
        "body_preview": str(decoded.get("body", ""))[:1000],
        "diff_hunk_preview": str(decoded.get("diff_hunk", ""))[:1000],
    }


def _github_pr_autofix_plan(comments_result: dict[str, Any]) -> dict[str, Any]:
    data = comments_result.get("data", {})
    if not isinstance(data, dict):
        data = {}
    comments = data.get("comments")
    if not isinstance(comments, list):
        comments = data.get("pull_request_comments")
    if not isinstance(comments, list):
        comments = []
    action_items = []
    for item in comments[:50]:
        if not isinstance(item, dict):
            continue
        body = str(item.get("body_preview") or item.get("body") or "")
        action_items.append(
            {
                "comment_id": item.get("id"),
                "path": str(item.get("path") or "")[:1000],
                "line": item.get("line") or item.get("position"),
                "reviewer": str(item.get("user") or item.get("author") or "")[:200],
                "summary": _first_sentence(body),
                "recommended_action": _github_autofix_action(body),
                "status": "needs_human_review",
            }
        )
    return {
        "ok": bool(comments_result.get("ok")),
        "operation": "pr_autofix_plan",
        "source_operation": comments_result.get("operation"),
        "connector": comments_result.get("connector"),
        "mode": "review_comments_to_local_patch_plan",
        "taint": comments_result.get("taint", "CONNECTOR_CONTENT"),
        "status": "autofix_plan_ready" if action_items else "no_review_comments",
        "comment_count": len(comments),
        "action_items": action_items,
        "auto_apply": False,
        "provider_writes_performed": False,
        "raw_secret_values_included": False,
        "required_controls": [
            "human_review_before_patch",
            "workspace_diff_review",
            "tests_before_commit",
            "approval_before_provider_write",
        ],
        "next_actions": [
            "Inspect each referenced file and line locally.",
            "Apply patches through the governed workspace workflow.",
            "Run targeted tests before posting any PR response.",
        ],
        "error": comments_result.get("error"),
    }


def _first_sentence(text: str) -> str:
    compact = " ".join(str(text or "").split())
    if not compact:
        return ""
    match = re.search(r"(?<=[.!?])\s+", compact)
    if match:
        compact = compact[: match.start()]
    return compact[:300]


def _github_autofix_action(text: str) -> str:
    lowered = str(text or "").lower()
    if "test" in lowered or "coverage" in lowered:
        return "add_or_update_test_coverage"
    if "security" in lowered or "secret" in lowered or "token" in lowered:
        return "review_security_boundary_and_redaction"
    if "doc" in lowered or "readme" in lowered:
        return "update_documentation"
    if "revocation" in lowered or "expiry" in lowered or "expire" in lowered:
        return "check_lifecycle_and_state_transition"
    return "inspect_and_patch_referenced_code"


def _github_pr_autofix_response_body(params: dict[str, Any]) -> str:
    explicit_body = str(params.get("body") or params.get("comment") or "").strip()
    if explicit_body:
        return str(redact(explicit_body))[:4000]
    action_items = _github_pr_action_items(params)
    lines = [
        "Aegis PR autofix response",
        "",
        "Status: local patch plan prepared; this approved response is the only provider write.",
        "Auto-apply: false",
        "Provider writes before this response: false",
        "Required controls: human review, workspace diff review, tests before commit, approval before provider write.",
        "",
        "Action items:",
    ]
    rendered_items = 0
    for item in action_items[:20]:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "unscoped")[:160]
        line = item.get("line")
        location = f"{path}:{line}" if line else path
        recommended = str(item.get("recommended_action") or "inspect_and_patch_referenced_code")[:120]
        summary = str(item.get("summary") or "")[:180]
        comment_id = item.get("comment_id")
        prefix = f"- comment {comment_id} at {location}" if comment_id is not None else f"- {location}"
        lines.append(f"{prefix}: {recommended}" + (f" - {summary}" if summary else ""))
        rendered_items += 1
    if rendered_items == 0:
        lines.append("- No review action items were supplied.")
    return str(redact("\n".join(lines)))[:4000]


def _github_pr_action_items(params: dict[str, Any]) -> list[dict[str, Any]]:
    action_items = params.get("action_items")
    plan = params.get("autofix_plan")
    if not isinstance(action_items, list) and isinstance(plan, dict):
        action_items = plan.get("action_items")
    if not isinstance(action_items, list):
        return []
    return [item for item in action_items[:50] if isinstance(item, dict)]


def _github_pr_referenced_files(action_items: list[dict[str, Any]]) -> set[str]:
    referenced: set[str] = set()
    for item in action_items:
        candidates: list[Any] = [item.get("path")]
        for key in ("planned_files", "changed_files"):
            values = item.get(key)
            if isinstance(values, list):
                candidates.extend(values)
        for value in candidates:
            text = str(value or "").strip()
            if not text:
                continue
            path = Path(text)
            if path.is_absolute() or ".." in path.parts:
                raise ToolExecutionError(f"review comment path {text!r} escapes workspace root")
            referenced.add(text)
    return referenced


def _normalize_gitlab_record(decoded: dict[str, Any], *, kind: str) -> dict[str, Any]:
    author = decoded.get("author")
    if not isinstance(author, dict):
        author = {}
    normalized: dict[str, Any] = {
        "kind": kind,
        "iid": decoded.get("iid"),
        "id": decoded.get("id"),
        "title": str(decoded.get("title", ""))[:500],
        "state": str(decoded.get("state", ""))[:100],
        "web_url": str(decoded.get("web_url", ""))[:1000],
        "author": str(author.get("username") or author.get("name") or "")[:200],
        "created_at": str(decoded.get("created_at", ""))[:100],
        "updated_at": str(decoded.get("updated_at", ""))[:100],
        "description_preview": str(decoded.get("description", ""))[:1000],
    }
    if kind == "merge_request":
        normalized.update(
            {
                "merged": str(decoded.get("state", "")).lower() == "merged" or bool(decoded.get("merged", False)),
                "draft": bool(decoded.get("draft", False)) or str(decoded.get("work_in_progress", "")).lower() == "true",
                "source_branch": str(decoded.get("source_branch", ""))[:200],
                "target_branch": str(decoded.get("target_branch", ""))[:200],
            }
        )
    return normalized


def _extract_productivity_records(decoded: Any, *, output_key: str) -> list[dict[str, Any]]:
    candidates = decoded
    if isinstance(decoded, dict):
        candidates = decoded.get(output_key, decoded.get("value", decoded.get("items", decoded.get("data", []))))
    if isinstance(candidates, dict):
        candidates = candidates.get("value", candidates.get("items", []))
    if not isinstance(candidates, list):
        return []
    return [item for item in candidates if isinstance(item, dict)]


def _normalize_calendar_event(record: dict[str, Any]) -> dict[str, str]:
    start = record.get("start")
    end = record.get("end")
    if isinstance(start, dict):
        start_value = start.get("dateTime") or start.get("date") or ""
    else:
        start_value = start or record.get("start_time") or record.get("startTime") or ""
    if isinstance(end, dict):
        end_value = end.get("dateTime") or end.get("date") or ""
    else:
        end_value = end or record.get("end_time") or record.get("endTime") or ""
    return {
        "id": str(record.get("id", ""))[:300],
        "subject": str(record.get("subject") or record.get("summary") or record.get("title") or "")[:500],
        "start": str(start_value)[:200],
        "end": str(end_value)[:200],
        "location": str(record.get("location", ""))[:500],
        "web_link": str(record.get("webLink") or record.get("htmlLink") or record.get("url") or "")[:1000],
    }


def _normalize_contact_record(record: dict[str, Any]) -> dict[str, str]:
    emails = record.get("emailAddresses")
    email = record.get("email") or record.get("mail") or record.get("userPrincipalName") or ""
    if not email and isinstance(emails, list) and emails:
        first = emails[0]
        if isinstance(first, dict):
            email = first.get("address", "")
        else:
            email = first
    return {
        "id": str(record.get("id", ""))[:300],
        "displayName": str(record.get("displayName") or record.get("name") or record.get("fullName") or "")[:500],
        "email": str(email)[:500],
        "company": str(record.get("companyName") or record.get("organization") or "")[:500],
    }


def _extract_service_tickets(decoded: Any) -> list[dict[str, Any]]:
    candidates = decoded
    if isinstance(decoded, dict):
        candidates = decoded.get("tickets", decoded.get("result", decoded.get("value", decoded.get("items", decoded))))
    if isinstance(candidates, dict):
        candidates = [candidates]
    if not isinstance(candidates, list):
        return []
    return [item for item in candidates if isinstance(item, dict)]


def _normalize_service_ticket(record: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(record.get("id") or record.get("sys_id") or record.get("key") or "")[:300],
        "number": str(record.get("number") or record.get("ticket") or record.get("key") or "")[:300],
        "state": str(record.get("state") or record.get("status") or "")[:200],
        "summary": str(record.get("summary") or record.get("short_description") or record.get("title") or "")[:500],
        "description_preview": str(record.get("description") or record.get("body") or "")[:1000],
        "priority": str(record.get("priority") or record.get("severity") or "")[:100],
        "assignee": str(record.get("assignee") or record.get("assigned_to") or "")[:300],
        "url": str(record.get("url") or record.get("html_url") or record.get("web_url") or "")[:1000],
    }


def _extract_text(content: str) -> str:
    without_scripts = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", content)
    without_tags = re.sub(r"(?s)<[^>]+>", " ", without_scripts)
    return re.sub(r"\s+", " ", without_tags).strip() or content[:4000]


def _parse_rss_items(content: str, *, limit: int) -> list[dict[str, str]]:
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return []
    items: list[dict[str, str]] = []
    for item in root.findall(".//item"):
        items.append(
            {
                "title": _xml_text(item, "title"),
                "link": _xml_text(item, "link"),
                "summary": _xml_text(item, "description")[:500],
                "published": _xml_text(item, "pubDate"),
            }
        )
        if len(items) >= limit:
            break
    if items:
        return items
    for entry in root.findall(".//{http://www.w3.org/2005/Atom}entry"):
        link = entry.find("{http://www.w3.org/2005/Atom}link")
        items.append(
            {
                "title": _xml_text(entry, "{http://www.w3.org/2005/Atom}title"),
                "link": str(link.attrib.get("href", "")) if link is not None else "",
                "summary": _xml_text(entry, "{http://www.w3.org/2005/Atom}summary")[:500],
                "published": _xml_text(entry, "{http://www.w3.org/2005/Atom}updated"),
            }
        )
        if len(items) >= limit:
            break
    return items


def _xml_text(parent: ElementTree.Element, tag: str) -> str:
    node = parent.find(tag)
    return "".join(node.itertext()).strip() if node is not None else ""


def _summarize_text(value: str) -> str:
    sentences = [segment.strip() for segment in re.split(r"(?<=[.!?])\s+", value) if segment.strip()]
    if not sentences:
        return value[:500]
    return " ".join(sentences[:3])[:500]


def _is_read_only_sql(query: str) -> bool:
    normalized = re.sub(r"\s+", " ", query.strip().lower())
    if ";" in normalized.rstrip(";"):
        return False
    if not normalized.startswith(("select ", "with ", "pragma ", "explain ")):
        return False
    blocked = (" insert ", " update ", " delete ", " drop ", " alter ", " create ", " replace ", " attach ", " detach ", " vacuum ", " reindex ")
    padded = f" {normalized.rstrip(';')} "
    return not any(token in padded for token in blocked)


def _workspace_root(connectors: ConnectorRegistry) -> Path:
    filesystem = connectors.get("filesystem")
    root = getattr(filesystem, "root", None)
    if root is None:
        raise ToolExecutionError("filesystem connector does not expose a workspace root")
    return Path(root).expanduser().resolve()


def _artifact_receipt(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "artifact_bytes": len(content),
    }


def _run_media_artifact_worker(*, artifact_dir: Path, artifact_name: str, tool: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = {"artifact_name": artifact_name, "tool": tool, **payload}
    python_path_entries = [entry for entry in sys.path if entry]
    if os.environ.get("PYTHONPATH"):
        python_path_entries.extend(os.environ["PYTHONPATH"].split(os.pathsep))
    env = {"PATH": os.environ.get("PATH", "")}
    if python_path_entries:
        env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(python_path_entries))
    completed = subprocess.run(
        [sys.executable, "-m", "aegis.tools.media_worker"],
        input=json.dumps(request),
        cwd=artifact_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        preexec_fn=_media_worker_preexec if os.name == "posix" else None,
        start_new_session=os.name == "posix",
    )
    if completed.returncode != 0:
        error = str(redact((completed.stderr or completed.stdout or "media artifact worker failed")[:500]))
        raise ToolExecutionError(error)
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ToolExecutionError("media artifact worker returned invalid JSON") from exc
    if not isinstance(result, dict) or not result.get("ok"):
        raise ToolExecutionError(str(redact(str(result.get("error", "media artifact worker failed"))[:500])) if isinstance(result, dict) else "media artifact worker failed")
    if not (artifact_dir / artifact_name).is_file():
        raise ToolExecutionError("media artifact worker did not create artifact")
    return {**result, "worker_process": "subprocess", "os_resource_limits": os.name == "posix", "process_session_isolated": os.name == "posix"}


def _media_worker_preexec() -> None:
    try:
        import resource
    except ImportError:  # pragma: no cover - platform fallback
        return
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))


def _write_tool_artifact_metadata(
    *,
    artifact_dir: Path,
    tool: str,
    artifact_path: Path,
    mode: str,
    artifact_receipt: dict[str, Any],
    sandbox_receipt: dict[str, Any],
    details: dict[str, Any],
) -> Path:
    metadata_path = artifact_dir / f"{artifact_path.stem}.metadata.json"
    metadata = {
        "version": 1,
        "tool": tool,
        "mode": mode,
        "artifact_name": artifact_path.name,
        "artifact_receipt": dict(artifact_receipt),
        "sandbox_receipt": dict(sandbox_receipt),
        "details": details,
        "limitations": list(
            sandbox_receipt.get(
                "limitations",
                [
                    "Receipt metadata avoids storing raw prompt or text content.",
                ],
            )
        ),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    metadata_path.chmod(0o600)
    return metadata_path


def _media_sandbox_receipt(*, tool: str, mode: str, worker_result: dict[str, Any] | None = None) -> dict[str, Any]:
    worker_result = worker_result or {}
    live_provider_used = "provider_domain" in worker_result
    return {
        "sandbox_profile": "live_provider_media_artifact" if live_provider_used else "local_artifact_worker_subprocess_no_provider",
        "tool": tool,
        "mode": mode,
        "worker_process": worker_result.get("worker_process", "provider_https_request" if live_provider_used else "subprocess"),
        "worker_pid": worker_result.get("worker_pid"),
        "stdin_payload_only": not live_provider_used,
        "minimal_environment": not live_provider_used,
        "os_resource_limits": bool(worker_result.get("os_resource_limits")),
        "process_session_isolated": bool(worker_result.get("process_session_isolated")),
        "ambient_workspace_read": False,
        "ambient_network": "allowlisted_https_provider_only" if live_provider_used else False,
        "raw_prompt_or_text_persisted": False,
        "writes_confined_to": ".aegis/tool-artifacts",
        "live_provider_used": live_provider_used,
        "provider_domain": worker_result.get("provider_domain"),
        "provider_adapter": worker_result.get("provider_adapter"),
        "limitations": [
            "Provider-backed media execution stores only the returned local artifact and redacted receipts.",
            "No microphone, speaker, camera, browser capture device, raw prompt/text persistence, raw provider response body, or raw secret value is used.",
        ]
        if live_provider_used
        else [
            "Deterministic local artifact worker only.",
            "No external media provider, microphone, speaker, camera, or browser capture device is invoked.",
        ],
    }


def _live_media_required_controls() -> list[str]:
    return ["human_approval", "live_rest_writes_enabled", "network_allowlist", "secret_broker", "artifact_hashing", "redacted_receipts"]


def _live_media_provider_adapter(*, name: str, params: dict[str, Any]) -> dict[str, str | None]:
    raw = str(params.get("provider_adapter") or params.get("adapter") or "generic").strip().lower().replace("-", "_")
    if raw in {"", "generic", "generic_json", "aegis_generic"}:
        return {"name": "generic", "error": None}
    if raw in {"openai_image", "openai_images", "openai_images_json", "openai_compatible_images"}:
        if name != "image_generate":
            return {"name": raw, "error": "openai_images provider adapter currently supports image_generate only"}
        return {"name": "openai_images", "error": None}
    if raw in {"openai_image_edit", "openai_images_edit", "openai_images_edits", "openai_compatible_image_edit"}:
        if name != "image_edit":
            return {"name": raw, "error": "openai_image_edit provider adapter currently supports image_edit only"}
        return {"name": "openai_image_edit", "error": None}
    if raw in {"openai_tts", "openai_speech", "openai_audio_speech", "openai_compatible_tts"}:
        if name != "tts":
            return {"name": raw, "error": "openai_tts provider adapter currently supports tts only"}
        return {"name": "openai_tts", "error": None}
    if raw in {"openai_transcription", "openai_transcriptions", "openai_audio_transcription", "openai_compatible_transcription"}:
        if name != "voice_transcribe":
            return {"name": raw, "error": "openai_transcription provider adapter currently supports voice_transcribe only"}
        return {"name": "openai_transcription", "error": None}
    return {"name": raw[:80], "error": f"unsupported media provider adapter: {raw[:80]}"}


def _live_media_request_payload(
    *,
    name: str,
    prompt: str,
    text: str,
    source_path: str,
    params: dict[str, Any],
    provider_adapter: str,
    source_file: dict[str, Any] | None = None,
    mask_file: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if provider_adapter == "openai_images":
        payload: dict[str, Any] = {
            "model": str(params.get("model") or "gpt-image-1")[:200],
            "prompt": prompt,
            "n": 1,
        }
        size = str(params.get("size") or "").strip()
        if size:
            payload["size"] = size[:80]
        quality = str(params.get("quality") or "").strip()
        if quality:
            payload["quality"] = quality[:80]
        background = str(params.get("background") or "").strip()
        if background:
            payload["background"] = background[:80]
        return payload
    if provider_adapter == "openai_image_edit":
        payload = {
            "model": str(params.get("model") or "gpt-image-1.5")[:200],
            "prompt": prompt,
            "n": 1,
            "image_present": bool(source_file),
        }
        if source_file:
            payload.update(
                {
                    "image_sha256": str(source_file["sha256"]),
                    "image_mime_type": str(source_file["mime_type"]),
                    "image_bytes": int(source_file["bytes"]),
                }
            )
        if mask_file:
            payload.update(
                {
                    "mask_present": True,
                    "mask_sha256": str(mask_file["sha256"]),
                    "mask_mime_type": str(mask_file["mime_type"]),
                    "mask_bytes": int(mask_file["bytes"]),
                }
            )
        for key in ("size", "quality", "background", "input_fidelity", "output_format", "output_compression", "moderation", "response_format"):
            value = str(params.get(key) or "").strip()
            if value:
                payload[key] = value[:80]
        return payload
    if provider_adapter == "openai_tts":
        payload = {
            "model": str(params.get("model") or "gpt-4o-mini-tts")[:200],
            "input": text,
            "voice": str(params.get("voice") or "alloy")[:80],
        }
        response_format = str(params.get("response_format") or params.get("format") or "").strip()
        if response_format:
            payload["response_format"] = response_format[:40]
        return payload
    if provider_adapter == "openai_transcription":
        payload = {
            "model": str(params.get("model") or "gpt-4o-mini-transcribe")[:200],
        }
        prompt_hint = str(params.get("prompt") or "").strip()
        if prompt_hint:
            payload["prompt"] = prompt_hint[:2000]
        response_format = str(params.get("response_format") or params.get("format") or "json").strip()
        if response_format:
            payload["response_format"] = response_format[:40]
        language = str(params.get("language") or "").strip()
        if language:
            payload["language"] = language[:40]
        temperature = params.get("temperature")
        if temperature is not None:
            payload["temperature"] = _bounded_float(temperature, minimum=0.0, maximum=1.0, label="temperature")
        return payload
    payload: dict[str, Any] = {"tool": name}
    if name in {"image_generate", "image_edit"}:
        payload["prompt"] = prompt
    if name == "tts":
        payload["text"] = text
    if source_path:
        payload["source_present"] = True
        payload["source_sha256"] = hashlib.sha256(source_path.encode("utf-8", errors="replace")).hexdigest()
    return payload


def _live_media_provider_receipt(*, domain: str, http_status: int, request_payload: dict[str, Any], handle_present: bool, provider_adapter: str = "generic") -> dict[str, Any]:
    encoded = json.dumps(request_payload, sort_keys=True, default=str).encode("utf-8")
    return {
        "receipt_schema": "redacted_media_provider_receipt_v1",
        "provider_adapter": provider_adapter,
        "request_format": "multipart/form-data" if provider_adapter in {"openai_image_edit", "openai_transcription"} else "application/json",
        "domain": domain,
        "http_status": http_status,
        "payload_sha256": hashlib.sha256(encoded).hexdigest(),
        "payload_keys": sorted(request_payload),
        "payload_bytes": len(encoded),
        "secret_handle_present": handle_present,
        "raw_secret_values_included": False,
        "raw_prompt_or_text_included": False,
        "raw_response_body_included": False,
    }


def _send_live_media_provider_request(
    *,
    url: str,
    token: str,
    tool: str,
    payload: dict[str, Any],
    provider_adapter: str = "generic",
    source_file: dict[str, Any] | None = None,
    mask_file: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if provider_adapter == "openai_image_edit":
        if source_file is None:
            return {"ok": False, "http_status": 0, "error": "openai_image_edit requires a workspace-scoped source image"}
        body, content_type = _encode_openai_image_edit_multipart(payload=payload, source_file=source_file, mask_file=mask_file)
    else:
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        content_type = "application/json"
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type,
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(request, timeout=30)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed media provider adapter"}
        return {"ok": False, "http_status": exc.code, "error": f"media provider failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"media provider request failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        raw = response.read(12 * 1024 * 1024)
        content_type = str(getattr(response, "headers", {}).get("Content-Type", ""))
    if not 200 <= status < 300:
        return {"ok": False, "http_status": status, "error": f"media provider failed with status {status}"}
    decoded_json: dict[str, Any] | None = None
    if "json" in content_type.lower() or raw.strip().startswith(b"{"):
        try:
            candidate = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"ok": False, "http_status": status, "error": "media provider JSON response could not be decoded"}
        if not isinstance(candidate, dict):
            return {"ok": False, "http_status": status, "error": "media provider JSON response must be an object"}
        decoded_json = candidate
        encoded_media = _media_base64_from_provider_json(candidate, tool=tool)
        if not encoded_media:
            return {"ok": False, "http_status": status, "error": "media provider JSON response did not include base64 media"}
        try:
            content = base64.b64decode(encoded_media, validate=True)
        except ValueError:
            return {"ok": False, "http_status": status, "error": "media provider returned invalid base64 media"}
        mime_type = str(candidate.get("mime_type") or candidate.get("mime") or candidate.get("content_type") or "")
    else:
        content = raw
        mime_type = content_type
    if not content:
        return {"ok": False, "http_status": status, "error": "media provider returned an empty artifact"}
    if len(content) > 10 * 1024 * 1024:
        return {"ok": False, "http_status": status, "error": "media provider artifact exceeds the 10 MiB local artifact limit"}
    result: dict[str, Any] = {"ok": True, "http_status": status, "content": content, "mime_type": mime_type}
    if decoded_json is not None and decoded_json.get("duration_seconds") is not None:
        try:
            result["duration_seconds"] = round(float(decoded_json["duration_seconds"]), 3)
        except (TypeError, ValueError):
            pass
    return result


def _live_media_source_file(*, root: Path, source_path: str, field: str) -> dict[str, Any]:
    if not str(source_path or "").strip():
        raise ToolExecutionError(f"openai_image_edit requires a {field}_path inside the workspace")
    path = _resolve_under_root(root, source_path)
    if not path.is_file():
        raise ToolExecutionError(f"openai_image_edit {field}_path does not exist or is not a file")
    content = path.read_bytes()
    if not content:
        raise ToolExecutionError(f"openai_image_edit {field}_path is empty")
    if len(content) > 10 * 1024 * 1024:
        raise ToolExecutionError(f"openai_image_edit {field}_path exceeds the 10 MiB upload limit")
    mime_type, extension = _source_image_upload_mime(content)
    return {
        "field": field,
        "filename": f"{field}.{extension}",
        "content": content,
        "mime_type": mime_type,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _source_image_upload_mime(content: bytes) -> tuple[str, str]:
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "png"
    if content.startswith(b"\xff\xd8"):
        return "image/jpeg", "jpg"
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "image/webp", "webp"
    raise ToolExecutionError("openai_image_edit source images must be PNG, JPEG, or WEBP")


def _live_media_audio_file(*, root: Path, audio_path: str) -> dict[str, Any]:
    if not str(audio_path or "").strip():
        raise ToolExecutionError("openai_transcription requires an audio_path inside the workspace")
    path = _resolve_under_root(root, audio_path)
    if not path.is_file():
        raise ToolExecutionError("openai_transcription audio_path does not exist or is not a file")
    content = path.read_bytes()
    if not content:
        raise ToolExecutionError("openai_transcription audio_path is empty")
    if len(content) > 10 * 1024 * 1024:
        raise ToolExecutionError("openai_transcription audio_path exceeds the 10 MiB upload limit")
    mime_type, extension = _source_audio_upload_mime(path)
    return {
        "path": path,
        "filename": f"audio.{extension}",
        "content": content,
        "mime_type": mime_type,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _source_audio_upload_mime(path: Path) -> tuple[str, str]:
    extension = path.suffix.lower().lstrip(".")
    mime_by_extension = {
        "flac": "audio/flac",
        "mp3": "audio/mpeg",
        "mp4": "audio/mp4",
        "mpeg": "audio/mpeg",
        "mpga": "audio/mpeg",
        "m4a": "audio/mp4",
        "ogg": "audio/ogg",
        "wav": "audio/wav",
        "webm": "audio/webm",
    }
    if extension in mime_by_extension:
        return mime_by_extension[extension], extension
    raise ToolExecutionError("openai_transcription audio files must be FLAC, MP3, MP4, MPEG, MPGA, M4A, OGG, WAV, or WEBM")


def _encode_openai_image_edit_multipart(*, payload: dict[str, Any], source_file: dict[str, Any], mask_file: dict[str, Any] | None = None) -> tuple[bytes, str]:
    boundary = f"aegis-{uuid4().hex}"
    body = bytearray()
    metadata_keys = {"image_present", "image_sha256", "image_mime_type", "image_bytes", "mask_present", "mask_sha256", "mask_mime_type", "mask_bytes"}
    for key in sorted(payload):
        if key in metadata_keys:
            continue
        value = payload[key]
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("ascii"))
        body.extend(str(value).encode("utf-8"))
        body.extend(b"\r\n")
    for upload in (source_file, mask_file):
        if not upload:
            continue
        field = str(upload["field"])
        filename = str(upload["filename"])
        mime_type = str(upload["mime_type"])
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        body.extend(f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode("ascii"))
        body.extend(f"Content-Type: {mime_type}\r\n\r\n".encode("ascii"))
        body.extend(upload["content"])
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("ascii"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _encode_openai_transcription_multipart(*, payload: dict[str, Any], audio_file: dict[str, Any]) -> tuple[bytes, str]:
    boundary = f"aegis-{uuid4().hex}"
    body = bytearray()
    for key in sorted(payload):
        value = payload[key]
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("ascii"))
        body.extend(str(value).encode("utf-8"))
        body.extend(b"\r\n")
    body.extend(f"--{boundary}\r\n".encode("ascii"))
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{audio_file["filename"]}"\r\n'.encode("ascii"))
    body.extend(f'Content-Type: {audio_file["mime_type"]}\r\n\r\n'.encode("ascii"))
    body.extend(audio_file["content"])
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("ascii"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _send_live_transcription_provider_request(
    *,
    url: str,
    token: str,
    payload: dict[str, Any],
    provider_adapter: str,
    audio_file: dict[str, Any],
) -> dict[str, Any]:
    if provider_adapter != "openai_transcription":
        return {"ok": False, "http_status": 0, "error": f"unsupported transcription provider adapter: {provider_adapter}"}
    body, content_type = _encode_openai_transcription_multipart(payload=payload, audio_file=audio_file)
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type,
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(request, timeout=30)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed transcription adapter"}
        return {"ok": False, "http_status": exc.code, "error": f"transcription provider failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"transcription provider request failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        raw = response.read(2 * 1024 * 1024)
        content_type = str(getattr(response, "headers", {}).get("Content-Type", ""))
    if not 200 <= status < 300:
        return {"ok": False, "http_status": status, "error": f"transcription provider failed with status {status}"}
    if "json" in content_type.lower() or raw.strip().startswith(b"{"):
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"ok": False, "http_status": status, "error": "transcription provider JSON response could not be decoded"}
        if not isinstance(decoded, dict):
            return {"ok": False, "http_status": status, "error": "transcription provider JSON response must be an object"}
        text = decoded.get("text") or decoded.get("transcript")
        if not isinstance(text, str) or not text.strip():
            return {"ok": False, "http_status": status, "error": "transcription provider response did not include text"}
        return {"ok": True, "http_status": status, "text": text.strip()}
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return {"ok": False, "http_status": status, "error": "transcription provider text response could not be decoded"}
    if not text:
        return {"ok": False, "http_status": status, "error": "transcription provider returned an empty transcript"}
    return {"ok": True, "http_status": status, "text": text}


def _media_base64_from_provider_json(decoded: dict[str, Any], *, tool: str) -> str:
    keys = ("audio_base64", "wav_base64", "data_base64", "data") if tool == "tts" else ("image_base64", "png_base64", "b64_json", "data_base64", "data")
    for key in keys:
        value = decoded.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    images = decoded.get("images")
    if isinstance(images, list) and images:
        first = images[0]
        if isinstance(first, dict):
            for key in ("b64_json", "image_base64", "data"):
                value = first.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    data_items = decoded.get("data")
    if isinstance(data_items, list) and data_items:
        first = data_items[0]
        if isinstance(first, dict):
            keys = ("data", "audio_base64", "b64_json") if tool == "tts" else ("b64_json", "image_base64", "data")
            for key in keys:
                value = first.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    audio = decoded.get("audio")
    if isinstance(audio, dict):
        for key in ("data", "audio_base64", "b64_json"):
            value = audio.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _live_media_extension_and_mime(*, name: str, declared_mime: str, content: bytes) -> tuple[str, str]:
    normalized = declared_mime.split(";", 1)[0].strip().lower()
    if name == "tts":
        if content.startswith(b"RIFF") and content[8:12] == b"WAVE":
            return "wav", "audio/wav"
        if normalized in {"audio/mpeg", "audio/mp3"}:
            return "mp3", normalized
        if normalized == "audio/wav":
            return "wav", normalized
        raise ToolExecutionError("media provider TTS response must be WAV or MP3")
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "image/png"
    if content.startswith(b"\xff\xd8"):
        return "jpg", "image/jpeg"
    if content.startswith(b"GIF87a") or content.startswith(b"GIF89a"):
        return "gif", "image/gif"
    if normalized in {"image/png", "image/jpeg", "image/jpg", "image/gif"}:
        return {"image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/gif": "gif"}[normalized], normalized
    raise ToolExecutionError("media provider image response must be PNG, JPEG, or GIF")


def _backend_activation_requirements(*, name: str, backend: str, backend_record: dict[str, Any] | None = None) -> dict[str, Any]:
    activation = backend_record.get("activation") if backend_record is not None else None
    if isinstance(activation, dict):
        return {
            "activation": activation,
            "activation_status": activation.get("status", "backend_adapter_required"),
            "preflight_status": activation.get("preflight_status", "unknown"),
            "required_controls": activation.get("required_controls", []),
            "configured_controls": activation.get("configured_controls", []),
            "blockers": activation.get("blockers", []),
            "verification_gates": activation.get("verification_gates", []),
            "next_steps": activation.get("next_steps", []),
        }
    fallback = {
        "status": "backend_adapter_required",
        "preflight_status": "unknown",
        "required_controls": ["brokered_backend_auth", "scope_limits", "resource_limits", "rollback_receipts"],
        "configured_controls": [],
        "blockers": [{"control": "backend_registry", "detail": f"{backend} backend metadata is not configured"}],
        "verification_gates": ["disabled_backend_denial", "approved_activation", "cleanup_receipt", "scope_escape_rejection"],
        "next_steps": [
            f"Configure the {backend} adapter for {name} with brokered credentials.",
            "Define workspace, network, CPU/memory/time, and artifact boundaries before enabling.",
            "Add cleanup and rollback receipts before any remote or container command can run.",
        ],
    }
    return {
        "activation": fallback,
        "activation_status": "backend_adapter_required",
        "preflight_status": fallback["preflight_status"],
        "required_controls": fallback["required_controls"],
        "configured_controls": fallback["configured_controls"],
        "blockers": fallback["blockers"],
        "verification_gates": fallback["verification_gates"],
        "next_steps": fallback["next_steps"],
    }


def _resolve_executable(executable: str) -> str | None:
    path = Path(executable).expanduser()
    if path.is_absolute():
        return str(path) if path.exists() and path.is_file() else None
    return shutil.which(executable)


def _host_allowed(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    if not host or not allowed_hosts:
        return False
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts)


def _safe_remote_command_args(command: str) -> list[str]:
    if not command.strip():
        raise ToolExecutionError("ssh_exec requires command")
    if re.search(r"[;&|`$<>\\\n\r]", command):
        raise ToolExecutionError("ssh command contains shell metacharacters that are not allowed")
    args = shlex.split(command)
    if not args:
        raise ToolExecutionError("ssh_exec requires command")
    for arg in args:
        if arg.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_./:=,@+-]+", arg):
            raise ToolExecutionError("ssh command arguments must be simple non-option tokens")
    return args


def _send_hosted_sandbox_request(
    *,
    url: str,
    token: str,
    backend: str,
    command_args: list[str],
    command_hash: str,
    timeout: int,
) -> dict[str, Any]:
    payload = {
        "backend": backend,
        "command_args": command_args,
        "command_sha256": command_hash,
        "requested_at": now_utc(),
    }
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(request, timeout=timeout)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed hosted sandbox adapter"}
        return {"ok": False, "http_status": exc.code, "error": f"hosted sandbox request failed with status {exc.code}"}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"hosted sandbox request failed: {exc.reason}"}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        raw_body = response.read(4096).decode("utf-8", errors="replace")
    job_id = ""
    try:
        decoded = json.loads(raw_body)
        if isinstance(decoded, dict):
            job_id = str(decoded.get("job_id") or decoded.get("id") or "")[:200]
    except json.JSONDecodeError:
        job_id = ""
    return {"ok": 200 <= status < 300, "http_status": status, "job_id": job_id or None, "error": None if 200 <= status < 300 else f"hosted sandbox request failed with status {status}"}


def _hosted_sandbox_action(params: dict[str, Any]) -> str | None:
    raw = str(params.get("action") or params.get("operation") or "submit").strip().lower().replace("-", "_")
    aliases = {
        "": "submit",
        "run": "submit",
        "submit": "submit",
        "execute": "submit",
        "status": "status",
        "poll": "status",
        "logs": "logs",
        "log": "logs",
        "tail": "logs",
        "cancel": "cancel",
        "stop": "cancel",
        "artifact": "artifact",
        "download": "artifact",
        "download_artifact": "artifact",
        "rollback": "rollback",
        "delete": "rollback",
        "cleanup": "rollback",
    }
    return aliases.get(raw)


def _safe_hosted_sandbox_job_id(job_id: str) -> bool:
    return bool(job_id and len(job_id) <= 200 and re.fullmatch(r"[A-Za-z0-9._:@+-]+", job_id))


def _send_hosted_sandbox_lifecycle_request(*, url: str, token: str, backend: str, action: str, job_id: str, timeout: int) -> dict[str, Any]:
    payload = {
        "backend": backend,
        "action": action,
        "job_id": job_id,
        "job_id_sha256": hashlib.sha256(job_id.encode("utf-8")).hexdigest(),
        "requested_at": now_utc(),
    }
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Aegis-Agent/0.1",
        },
    )
    try:
        response_context = _open_without_redirects(request, timeout=timeout)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "http_status": exc.code, "error": "HTTP redirects are not followed by the governed hosted sandbox lifecycle adapter", "response_summary": {}}
        return {"ok": False, "http_status": exc.code, "error": f"hosted sandbox lifecycle request failed with status {exc.code}", "response_summary": {}}
    except URLError as exc:
        return {"ok": False, "http_status": 0, "error": f"hosted sandbox lifecycle request failed: {exc.reason}", "response_summary": {}}
    with response_context as response:
        status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
        content_type = str(getattr(response, "headers", {}).get("Content-Type", ""))
        raw_body = response.read(12 * 1024 * 1024 if action == "artifact" else 64 * 1024)
    decoded: dict[str, Any] = {}
    if "json" in content_type.lower() or raw_body.strip().startswith(b"{"):
        try:
            candidate = json.loads(raw_body.decode("utf-8"))
            if isinstance(candidate, dict):
                decoded = candidate
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = {}
    response_summary = _hosted_sandbox_response_summary(decoded, action=action)
    result: dict[str, Any] = {
        "ok": 200 <= status < 300,
        "http_status": status,
        "provider_status": response_summary.get("state") or response_summary.get("status"),
        "response_summary": response_summary,
        "error": None if 200 <= status < 300 else f"hosted sandbox lifecycle request failed with status {status}",
    }
    if action == "logs":
        log_tail = _hosted_sandbox_log_tail(decoded.get("logs") or decoded.get("log_tail") or decoded.get("stdout") or "")
        result.update({"log_tail": log_tail, "log_line_count": len(log_tail)})
    if action == "artifact":
        artifact_content, artifact_name, artifact_mime = _hosted_sandbox_artifact_from_response(decoded, raw_body=raw_body, content_type=content_type)
        if artifact_content:
            result.update({"artifact_content": artifact_content, "artifact_name": artifact_name, "artifact_mime": artifact_mime})
    return result


def _hosted_sandbox_response_summary(decoded: dict[str, Any], *, action: str) -> dict[str, Any]:
    summary: dict[str, Any] = {"action": action, "response_keys": sorted(str(key)[:80] for key in decoded)}
    for key in ("status", "state", "message", "artifact_id", "artifact_name", "created_at", "started_at", "completed_at"):
        value = decoded.get(key)
        if value is not None:
            summary[key] = str(redact(str(value)))[:500]
    if action == "logs":
        summary["log_line_count"] = len(_hosted_sandbox_log_tail(decoded.get("logs") or decoded.get("log_tail") or decoded.get("stdout") or ""))
    return summary


def _hosted_sandbox_log_tail(value: Any) -> list[str]:
    if isinstance(value, list):
        lines = [str(item) for item in value]
    else:
        lines = str(value or "").splitlines()
    return [str(redact(line))[:500] for line in lines[-20:]]


def _hosted_sandbox_artifact_from_response(decoded: dict[str, Any], *, raw_body: bytes, content_type: str) -> tuple[bytes | None, str, str]:
    artifact_name = str(decoded.get("artifact_name") or decoded.get("filename") or "artifact.bin")[:120]
    artifact_mime = str(decoded.get("mime_type") or decoded.get("content_type") or "application/octet-stream")[:120]
    for key in ("artifact_base64", "data_base64", "content_base64"):
        value = decoded.get(key)
        if isinstance(value, str) and value.strip():
            try:
                content = base64.b64decode(value.strip(), validate=True)
            except ValueError:
                return None, artifact_name, artifact_mime
            if len(content) <= 10 * 1024 * 1024:
                return content, artifact_name, artifact_mime
            return None, artifact_name, artifact_mime
    if content_type and "json" not in content_type.lower() and raw_body:
        if len(raw_body) > 10 * 1024 * 1024:
            return None, artifact_name, artifact_mime
        return raw_body, artifact_name, content_type.split(";", 1)[0].strip().lower() or artifact_mime
    return None, artifact_name, artifact_mime


def _hosted_sandbox_lifecycle_receipt(*, backend: str, action: str, domain: str, job_id: str, http_status: int, handle_present: bool, response_summary: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(response_summary, sort_keys=True, default=str).encode("utf-8")
    return {
        "receipt_schema": "hosted_sandbox_lifecycle_receipt_v1",
        "backend": backend,
        "action": action,
        "domain": domain,
        "http_status": http_status,
        "job_id_sha256": hashlib.sha256(job_id.encode("utf-8")).hexdigest(),
        "response_summary_sha256": hashlib.sha256(encoded).hexdigest(),
        "response_keys": response_summary.get("response_keys", []),
        "secret_handle_present": handle_present,
        "raw_job_id_logged": False,
        "raw_command_logged": False,
        "raw_secret_values_included": False,
        "raw_response_body_included": False,
    }


def _hosted_sandbox_artifact_extension(artifact_name: str, mime_type: str) -> str:
    suffix = Path(artifact_name).suffix.lower().lstrip(".")
    if suffix and re.fullmatch(r"[a-z0-9]{1,12}", suffix):
        return suffix
    normalized = mime_type.split(";", 1)[0].strip().lower()
    return {
        "application/json": "json",
        "text/plain": "txt",
        "application/zip": "zip",
        "application/gzip": "gz",
        "image/png": "png",
        "image/jpeg": "jpg",
    }.get(normalized, "bin")


def _docker_args_for_tool(*, name: str, params: dict[str, Any], config: dict[str, Any]) -> list[str]:
    if name == "container_run":
        image = str(params.get("image", "")).strip()
        if not image or not re.fullmatch(r"[A-Za-z0-9._:/@-]+", image):
            raise ToolExecutionError("container image must be a simple registry reference")
        command = str(params.get("command", "")).strip()
        command_args = shlex.split(command) if command else []
        _reject_unsafe_docker_args(command_args)
        args = [
            "run",
            "--rm",
            "--network",
            str(config.get("network", "none")),
            "--cpus",
            str(config.get("cpus", "1")),
            "--memory",
            str(config.get("memory", "512m")),
            image,
            *command_args,
        ]
        _reject_unsafe_docker_args(args)
        return args
    raw_command = str(params.get("command", "")).strip()
    if not raw_command:
        raise ToolExecutionError("docker_run requires command")
    args = shlex.split(raw_command)
    if args and args[0] == "docker":
        args = args[1:]
    _reject_unsafe_docker_args(args)
    return args


def _reject_unsafe_docker_args(args: list[str]) -> None:
    denied_exact = {"--privileged", "--pid=host", "--ipc=host", "--network=host", "--net=host", "-v", "--volume", "--mount"}
    denied_prefixes = ("--volume=", "--mount=", "-v=", "--network=host", "--net=host")
    for index, arg in enumerate(args):
        if arg in denied_exact or any(arg.startswith(prefix) for prefix in denied_prefixes):
            raise ToolExecutionError(f"docker argument {arg!r} is not allowed")
        if arg in {"--network", "--net"} and index + 1 < len(args) and args[index + 1] == "host":
            raise ToolExecutionError("docker host networking is not allowed")


def _docker_limit_receipt(config: dict[str, Any]) -> dict[str, str | int]:
    return {
        "timeout_seconds": int(config.get("timeout_seconds", 30)),
        "memory": str(config.get("memory", "512m")),
        "cpus": str(config.get("cpus", "1")),
        "network": str(config.get("network", "none")),
    }


def _resolve_under_root(root: Path, value: Any) -> Path:
    path = (root / str(value or ".")).expanduser().resolve() if not Path(str(value or ".")).is_absolute() else Path(str(value)).expanduser().resolve()
    if root not in (path, *path.parents):
        raise ToolExecutionError(f"path {path} escapes workspace root")
    return path


def _safe_archive_member_path(destination: Path, member_name: str) -> Path:
    member = Path(member_name)
    if member.is_absolute() or ".." in member.parts:
        raise ToolExecutionError(f"archive member {member_name!r} escapes destination")
    target = (destination / member).resolve()
    if destination not in (target, *target.parents):
        raise ToolExecutionError(f"archive member {member_name!r} escapes destination")
    return target


def _changed_files_from_patch(patch: str) -> list[str]:
    changed: list[str] = []
    for line in patch.splitlines():
        if not line.startswith(("+++ ", "--- ")):
            continue
        raw = line[4:].strip()
        if raw == "/dev/null":
            continue
        if raw.startswith(("a/", "b/")):
            raw = raw[2:]
        path = Path(raw)
        if path.is_absolute() or ".." in path.parts:
            raise ToolExecutionError(f"patch path {raw!r} escapes workspace root")
        if raw not in changed:
            changed.append(raw)
    if not changed:
        raise ToolExecutionError("diff_apply requires a unified diff with changed files")
    return changed


def _run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(("git", "-C", str(root), *args), text=True, capture_output=True, timeout=10, check=False)


def _operation_for_tool(name: str, permission: str) -> str:
    if name in {"file_write", "memory_store", "image_generate", "tts", "subagent_delegate", "mcp_call"}:
        return "write"
    if name == "shell":
        return "execute"
    if "execute" in permission:
        return "execute"
    if "write" in permission:
        return "write"
    return "read"


def _scopes_for_tool(permission: str, operation: str) -> tuple[str, ...]:
    scopes = {scope for scope in permission.split("/") if scope and scope != "none"}
    if operation == "write":
        scopes.add("write")
    if operation == "execute":
        scopes.add("execute")
    return tuple(sorted(scopes))
