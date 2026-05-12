"""Dependency-free local development API server."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import hashlib
import json
import mimetypes
import re
import secrets
import time
from urllib.parse import parse_qs, unquote, urlparse

from aegis.agent.orchestrator import build_orchestrator
from aegis.approvals.actions import approval_action_hints
from aegis.approvals.models import ApprovalRequest
from aegis.channels.base import ChannelResponse
from aegis.hooks.manager import HOOK_EVENTS
from aegis.memory.models import MemoryType
from aegis.migration.openclaw import preview_hermes_memory_import, preview_openclaw_memory_import
from aegis.product.capabilities import build_product_dashboard
from aegis.research.harness import ResearchHarness
from aegis.remote_control import REMOTE_CONTROL_TOKEN_HEADER, RemoteControlPairingRegistry, build_remote_control_directory
from aegis.scheduler.worker import ScheduleWorker
from aegis.security.policy_engine import PolicyDecision, PolicyRequest
from aegis.security.policy_profile import activate_due_policy_rollouts, apply_policy_bundle, apply_policy_bundle_text, diff_policy_bundle, diff_policy_bundle_text, import_policy_bundle_text, list_policy_bundles, list_policy_promotions, list_policy_rollouts, policy_profile_to_dict, promote_policy_bundle, rollback_policy_bundle, schedule_policy_bundle
from aegis.security.taint import RiskLevel, Sensitivity, TrustClass
from aegis.skills.signing import DEFAULT_SKILL_SIGNING_KEY
from aegis.tools.executor import ToolExecutionError


_TERMINAL_TASK_STATUSES = {"completed", "failed", "blocked", "cancelled"}
_STREAM_TIMEOUT_MAX_SECONDS = 30.0
_LIVE_STREAM_TIMEOUT_MAX_SECONDS = 300.0
_SAFE_ARTIFACT_CONTENT_TYPES = {
    ".csv": "text/csv; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".txt": "text/plain; charset=utf-8",
    ".wav": "audio/wav",
}


def _tool_artifact_dir(orchestrator: Any) -> Path:
    return (Path(orchestrator.workspace) / ".aegis" / "tool-artifacts").expanduser().resolve()


def _browser_artifact_dir(orchestrator: Any) -> Path:
    return (Path(orchestrator.config.data_dir) / "browser").expanduser().resolve()


def _safe_artifact_content_type(path: Path) -> str:
    return _SAFE_ARTIFACT_CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream")


def _hooks_payload(orchestrator: Any) -> dict[str, Any]:
    return {
        "status": "governed_local_ready",
        "hooks": orchestrator.hooks.list_hooks(),
        "supported_events": list(HOOK_EVENTS),
        "allowed_executables": list(orchestrator.config.allowed_shell_commands),
        "raw_secret_values_included": False,
    }


def _plugins_payload(orchestrator: Any) -> dict[str, Any]:
    return {
        "status": "governed_local_ready",
        "plugins": orchestrator.plugins.list_plugins(),
        "skills": orchestrator.skills.list_public(),
        "mcp_servers": orchestrator.mcp.list_servers(),
        "hooks": orchestrator.hooks.list_hooks(),
        "raw_secret_values_included": False,
    }


def _with_tool_artifact_url(orchestrator: Any, result: dict[str, Any]) -> dict[str, Any]:
    artifact_dir = _tool_artifact_dir(orchestrator)
    updated = dict(result)
    for source_key, url_key in (("artifact_path", "artifact_url"), ("asset_path", "artifact_url"), ("metadata_path", "metadata_url")):
        artifact_path = result.get(source_key)
        if not artifact_path:
            continue
        try:
            path = Path(str(artifact_path)).expanduser().resolve()
        except OSError:
            continue
        if artifact_dir in (path, *path.parents) and path.is_file():
            updated[url_key] = f"/tool-artifacts/{path.name}"
    return updated


def _with_browser_artifact_urls(orchestrator: Any, result: dict[str, Any]) -> dict[str, Any]:
    browser_artifact_dir = _browser_artifact_dir(orchestrator)
    updated = dict(result)
    for source_key, url_key in (
        ("artifact_path", "artifact_url"),
        ("metadata_path", "metadata_url"),
        ("evidence_path", "evidence_url"),
    ):
        artifact_path = result.get(source_key)
        if not artifact_path:
            continue
        try:
            path = Path(str(artifact_path)).expanduser().resolve()
        except OSError:
            continue
        if browser_artifact_dir in (path, *path.parents) and path.is_file():
            updated[url_key] = f"/browser-artifacts/{path.name}"
    return updated


def serve(*, data_dir: str | Path, workspace: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    orchestrator = build_orchestrator(data_dir=data_dir, workspace=workspace)
    schedule_worker = ScheduleWorker(orchestrator)
    static_root = Path(__file__).resolve().parents[1] / "web" / "static"
    api_token = secrets.token_urlsafe(32)
    allowed_hosts = _allowed_hosts(host, port)
    allowed_origins = _allowed_origins(host, port)
    remote_control = RemoteControlPairingRegistry(orchestrator.config.data_dir / "remote_control_pairings.json")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisAgent/0.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler name.
            try:
                self._do_GET()
            except KeyError as exc:
                self._json({"error": "not found", "detail": _exception_detail(exc)}, status=404)
            except PermissionError as exc:
                self._json({"error": "forbidden", "detail": str(exc)}, status=403)
            except ToolExecutionError as exc:
                self._json({"error": "bad request", "detail": str(exc)}, status=400)
            except ValueError as exc:
                self._json({"error": "bad request", "detail": str(exc)}, status=400)

        def _do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if path == "/":
                self._static(static_root / "index.html")
                return
            if path.startswith("/static/"):
                requested = (static_root / path.removeprefix("/static/")).resolve()
                if static_root not in (requested, *requested.parents):
                    self._json({"error": "invalid static path"}, status=403)
                    return
                self._static(requested)
                return
            if path == "/health":
                self._json(
                    {
                        "ok": True,
                        "audit_chain_ok": orchestrator.audit_logger.verify_chain(),
                        "connectors": orchestrator.connectors.status(),
                        "channels": orchestrator.channels.status(),
                    }
                )
                return
            if path == "/auth":
                self._require_allowed_host()
                self._json({"token": api_token})
                return
            if path == "/remote-control/status":
                auth = self._authorize_remote_control_status()
                if auth.get("auth_kind") == "remote_control":
                    self._json({"status": "remote_pairing_active", "pairing": auth["pairing"], "token_header": REMOTE_CONTROL_TOKEN_HEADER})
                else:
                    self._json(remote_control.status())
                return
            if path == "/remote-control/directory":
                auth = self._authorize_remote_control_status()
                if auth.get("auth_kind") == "remote_control":
                    pairing = auth["pairing"]
                else:
                    pairing_id = query.get("pairing_id", [None])[0]
                    if not pairing_id:
                        raise ValueError("pairing_id is required for local remote-control directory reads")
                    pairing = remote_control.public_pairing(pairing_id)
                self._json(
                    build_remote_control_directory(
                        pairing,
                        store=orchestrator.store,
                        limit=_limit(query, default=10),
                    )
                )
                return
            if path == "/remote-control/relay":
                self._authorize_remote_control_status()
                self._json(remote_control.relay_preflight(relay_url=query.get("relay_url", [None])[0]))
                return
            match_remote_task = re.fullmatch(r"/remote-control/tasks/([^/]+)", path)
            if match_remote_task:
                task_id = match_remote_task.group(1)
                self._authorize_remote_control_action("status", task_id)
                self._json(orchestrator.status(task_id))
                return
            match_remote_task_events = re.fullmatch(r"/remote-control/tasks/([^/]+)/events", path)
            if match_remote_task_events:
                task_id = match_remote_task_events.group(1)
                self._authorize_remote_control_action("events", task_id)
                self._json(orchestrator.evidence.run_events(task_id))
                return
            self._authorize_read()
            if path.startswith("/tool-artifacts/"):
                self._tool_artifact(path.removeprefix("/tool-artifacts/"))
                return
            if path.startswith("/browser-artifacts/"):
                self._browser_artifact(path.removeprefix("/browser-artifacts/"))
                return
            if path == "/dashboard":
                self._json(build_product_dashboard(orchestrator))
                return
            if path == "/connectors":
                self._json({"connectors": orchestrator.connectors.list()})
                return
            if path == "/channels":
                self._json({"channels": orchestrator.channels.list_channels()})
                return
            if path == "/channel-events":
                self._json({"events": orchestrator.channels.events(limit=_limit(query, default=50))})
                return
            if path == "/policy":
                self._json(_policy_summary(orchestrator))
                return
            if path == "/policy/bundles":
                self._json({"bundles": list_policy_bundles()})
                return
            if path == "/policy/rollouts":
                self._json(list_policy_rollouts(data_dir=orchestrator.config.data_dir))
                return
            if path == "/policy/promotions":
                self._json(list_policy_promotions(data_dir=orchestrator.config.data_dir, limit=_limit(query, default=20)))
                return
            if path == "/models":
                self._json({"models": orchestrator.models.list_models()})
                return
            if path == "/model-providers":
                self._json({"providers": orchestrator.models.list_providers()})
                return
            if path == "/models/auth/targets":
                self._json(orchestrator.models.auth_targets())
                return
            if path == "/model-usage":
                self._json(orchestrator.models.usage_summary())
                return
            if path == "/models/route":
                identifier = query.get("identifier", [""])[0]
                if not identifier:
                    raise ValueError("missing required query parameter: identifier")
                self._json(_model_route_payload(orchestrator.models.route(identifier)))
                return
            if path == "/tools":
                self._json({"tools": [*orchestrator.tool_catalog.list(), *orchestrator.mcp.virtual_tool_specs()]})
                return
            if path == "/backends":
                self._json({"backends": orchestrator.execution_backends.list()})
                return
            if path == "/browser/sessions":
                self._json({"sessions": orchestrator.browser.list_sessions()})
                return
            if path == "/skill-hub":
                self._json(orchestrator.skill_hub.search(query.get("q", [""])[0]))
                return
            if path == "/skills":
                self._json({"skills": orchestrator.skills.list_public()})
                return
            if path == "/plugins":
                self._json(_plugins_payload(orchestrator))
                return
            if path == "/plugins/marketplace":
                self._json(orchestrator.plugins.marketplace(query=query.get("q", [""])[0], catalog_path=query.get("catalog_path", [None])[0]))
                return
            if path == "/plugins/updates":
                self._json(orchestrator.plugins.update_plan(catalog_path=query.get("catalog_path", [None])[0]))
                return
            if path == "/mcp/servers":
                self._json({"servers": orchestrator.mcp.list_servers()})
                return
            if path == "/hooks":
                self._json(_hooks_payload(orchestrator))
                return
            if path == "/schedules/due":
                self._json({"schedules": orchestrator.schedules.due()})
                return
            if path == "/schedules":
                self._json({"schedules": orchestrator.schedules.list_schedules()})
                return
            if path == "/sessions":
                self._json({"sessions": orchestrator.sessions.list_sessions()})
                return
            match_session_messages = re.fullmatch(r"/sessions/([^/]+)/messages", path)
            if match_session_messages:
                self._json({"messages": orchestrator.sessions.history(match_session_messages.group(1), limit=_limit(query, default=100))})
                return
            match_session_memory_preview = re.fullmatch(r"/sessions/([^/]+)/memory-preview", path)
            if match_session_memory_preview:
                session_id = match_session_memory_preview.group(1)
                self._json(
                    orchestrator.memory.preview_session_memory_candidates(
                        session_id=session_id,
                        messages=orchestrator.sessions.history(session_id, limit=1000),
                        owner=query.get("owner", ["local-user"])[0],
                        scope=query.get("scope", ["workspace"])[0],
                        limit=_limit(query, default=25),
                    )
                )
                return
            match_session_tasks = re.fullmatch(r"/sessions/([^/]+)/tasks", path)
            if match_session_tasks:
                self._json({"tasks": [_task_summary(row, orchestrator=orchestrator) for row in orchestrator.store.list_tasks(limit=_limit(query, default=25), session_id=match_session_tasks.group(1))]})
                return
            if path == "/tasks":
                self._json({"tasks": [_task_summary(row, orchestrator=orchestrator) for row in orchestrator.store.list_tasks(limit=_limit(query, default=25))]})
                return
            if path == "/approvals":
                status = query.get("status", [None])[0]
                self._json({"approvals": [_approval_summary(orchestrator, row) for row in orchestrator.approvals.list(status=status, limit=_limit(query, default=50))]})
                return
            match_approval = re.fullmatch(r"/approvals/([^/]+)", path)
            if match_approval:
                self._json(_approval_summary(orchestrator, orchestrator.approvals.get(match_approval.group(1))))
                return
            if path == "/improvements":
                status = query.get("status", [None])[0]
                self._json({"proposals": orchestrator.list_improvement_proposals(status=status, limit=_limit(query, default=50))})
                return
            if path == "/improvements/readiness":
                status = query.get("status", [None])[0]
                self._json(orchestrator.repair_readiness_summary(status=status, limit=_limit(query, default=50)))
                return
            match_improvement = re.fullmatch(r"/improvements/([^/]+)", path)
            if match_improvement:
                self._json(orchestrator.get_improvement_proposal(match_improvement.group(1)))
                return
            match_task_evidence = re.fullmatch(r"/tasks/([^/]+)/evidence", path)
            if match_task_evidence:
                self._json(orchestrator.evidence.build(match_task_evidence.group(1)))
                return
            match_task_timeline = re.fullmatch(r"/tasks/([^/]+)/timeline", path)
            if match_task_timeline:
                self._json(orchestrator.evidence.timeline(match_task_timeline.group(1)))
                return
            match_task_events = re.fullmatch(r"/tasks/([^/]+)/events", path)
            if match_task_events:
                self._json(orchestrator.evidence.run_events(match_task_events.group(1)))
                return
            match_task_event_stream = re.fullmatch(r"/tasks/([^/]+)/events/stream", path)
            if match_task_event_stream:
                self._event_stream(
                    match_task_event_stream.group(1),
                    follow=_truthy(query.get("follow", ["0"])[0]),
                    live=_truthy(query.get("live", ["0"])[0]),
                    timeout_seconds=_stream_timeout(query),
                    since_sequence=_since_sequence(query, self.headers.get("Last-Event-ID")),
                )
                return
            if path == "/memory":
                search = query.get("q", [""])[0]
                self._json({"memories": orchestrator.memory.retrieve_relevant(search) if search else []})
                return
            if path == "/memory/review-queue":
                self._json(orchestrator.memory.review_queue(limit=_limit(query, default=50), scope=query.get("scope", ["workspace"])[0]))
                return
            if path == "/memory/review-digest":
                self._json(orchestrator.memory.review_digest(limit=_limit(query, default=10), scope=query.get("scope", ["workspace"])[0]))
                return
            if path == "/memory/review-escalation":
                self._json(
                    orchestrator.memory.review_escalation(
                        max_age_days=int(query.get("max_age_days", ["7"])[0]),
                        limit=_limit(query, default=10),
                        scope=query.get("scope", ["workspace"])[0],
                        route=query.get("route", ["operator"])[0],
                    )
                )
                return
            if path == "/memory/export":
                search = query.get("q", [""])[0]
                self._json({"memories": orchestrator.memory.export_memory(search), "query": search})
                return
            if path == "/migration/memory-preview":
                self._json(
                    _migration_memory_preview(
                        platform=query.get("platform", ["openclaw"])[0],
                        path=query.get("path", [""])[0],
                        owner=query.get("owner", ["local-user"])[0],
                        scope=query.get("scope", ["workspace"])[0],
                    )
                )
                return
            if path == "/evaluation/queue":
                reviewer = query.get("reviewer", [None])[0]
                self._json(ResearchHarness(data_dir=orchestrator.config.data_dir).evaluation_review_queue(limit=_limit(query, default=20), reviewer=reviewer))
                return
            if path == "/evaluation/trends":
                self._json(ResearchHarness(data_dir=orchestrator.config.data_dir).evaluation_trends(limit=_limit(query, default=20)))
                return
            if path == "/evaluation/delta":
                self._json(
                    ResearchHarness(data_dir=orchestrator.config.data_dir).evaluation_regression_delta(
                        baseline_report_id=query.get("baseline_report_id", [None])[0],
                        candidate_report_id=query.get("candidate_report_id", [None])[0],
                        scenario=query.get("scenario", [None])[0],
                    )
                )
                return
            if path == "/evaluation/readiness":
                include_live_gaps = _truthy(query.get("include_live_gaps", ["0"])[0])
                self._json(
                    ResearchHarness(data_dir=orchestrator.config.data_dir).release_readiness_summary(
                        baseline_report_id=query.get("baseline_report_id", [None])[0],
                        candidate_report_id=query.get("candidate_report_id", [None])[0],
                        scenario=query.get("scenario", [None])[0],
                        reviewer=query.get("reviewer", [None])[0],
                        limit=_limit(query, default=20),
                        live_gap_backlog=build_product_dashboard(orchestrator).get("live_gap_backlog", []) if include_live_gaps else None,
                        deferred_live_gap_areas=query.get("defer_live_gap", []),
                        live_gap_deferral_reason=query.get("live_gap_deferral_reason", [None])[0],
                    )
                )
                return
            match_memory_explain = re.fullmatch(r"/memory/([^/]+)/explain", path)
            if match_memory_explain:
                search = query.get("q", [""])[0]
                self._json({"memory_id": match_memory_explain.group(1), "query": search, "explanation": orchestrator.memory.explain_usage(match_memory_explain.group(1), search)})
                return
            if path == "/audit":
                self._json({"events": orchestrator.audit_logger.tail(_limit(query, default=50))})
                return
            if path == "/audit/export-siem":
                self._json(
                    orchestrator.audit_logger.export_siem(
                        limit=_limit(query, default=1000),
                        task_id=query.get("task_id", [None])[0],
                        event_type=query.get("event_type", [None])[0],
                    )
                )
                return
            if path == "/kanban/boards":
                self._json({"boards": orchestrator.kanban.list_boards()})
                return
            match_cards = re.fullmatch(r"/kanban/boards/([^/]+)/cards", path)
            if match_cards:
                self._json({"cards": orchestrator.kanban.list_cards(match_cards.group(1))})
                return
            if path == "/subagents/status":
                self._json(orchestrator.kanban.subagent_status(limit=_limit(query, default=20)))
                return
            match = re.fullmatch(r"/tasks/([^/]+)", path)
            if match:
                self._json(orchestrator.status(match.group(1)))
                return
            self._json({"error": "not found"}, status=404)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler name.
            try:
                self._do_POST()
            except json.JSONDecodeError:
                self._json({"error": "bad request", "detail": "request body must be valid JSON"}, status=400)
            except KeyError as exc:
                self._json({"error": "not found", "detail": _exception_detail(exc)}, status=404)
            except PermissionError as exc:
                self._json({"error": "forbidden", "detail": str(exc)}, status=403)
            except ToolExecutionError as exc:
                self._json({"error": "bad request", "detail": str(exc)}, status=400)
            except ValueError as exc:
                self._json({"error": "bad request", "detail": str(exc)}, status=400)

        def _do_POST(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path in {"/remote-control/pair", "/remote-control/revoke", "/remote-control/relay", "/remote-control/relay/pull"}:
                self._authorize_local_mutation()
            elif path == "/remote-control/relay/action":
                pass
            elif re.fullmatch(r"/remote-control/tasks/[^/]+/(resume|pause|cancel)", path):
                pass
            elif path != "/channels/webhook":
                self._authorize_mutation()

            if path == "/tasks":
                payload = self._read_json()
                self._json(orchestrator.submit_task(str(_required(payload, "request")), path=payload.get("path"), session_id=payload.get("session_id")))
                return
            if path == "/remote-control/pair":
                payload = self._read_json()
                result = remote_control.create_pairing(
                    label=str(payload.get("label") or ""),
                    session_id=_optional_str(payload, "session_id"),
                    task_id=_optional_str(payload, "task_id"),
                    allowed_actions=_optional_str_list(payload, "allowed_actions"),
                    ttl_seconds=_optional_int(payload, "expires_in_seconds"),
                    endpoint_host=host,
                    endpoint_port=port,
                )
                orchestrator.audit_logger.append(
                    "remote_control.pairing_created",
                    {
                        "pairing_id": result["pairing"]["id"],
                        "label": result["pairing"]["label"],
                        "session_id": result["pairing"].get("session_id"),
                        "task_id": result["pairing"].get("task_id"),
                        "allowed_actions": result["pairing"].get("allowed_actions"),
                        "expires_at": result["pairing"]["expires_at"],
                        "token_header": result["token_header"],
                        "token_captured": False,
                    },
                )
                self._json(result)
                return
            if path == "/remote-control/revoke":
                payload = self._read_json()
                relay_auth_token = None
                if payload.get("relay_auth_secret") or payload.get("approved"):
                    if not bool(payload.get("approved", False)):
                        raise PermissionError("remote-control relay revocation requires explicit approval")
                    relay_secret = str(_required(payload, "relay_auth_secret"))
                    handle = orchestrator.secrets_broker.request_handle(
                        name=relay_secret,
                        requester="remote_control_relay",
                        reason="propagate scoped remote-control relay revocation",
                        scopes=("remote_control:relay",),
                    )
                    relay_auth_token = orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                result = remote_control.revoke(
                    str(_required(payload, "pairing_id")),
                    relay_auth_token=relay_auth_token,
                    notify_relay=bool(relay_auth_token),
                )
                orchestrator.audit_logger.append(
                    "remote_control.pairing_revoked",
                    {
                        "pairing_id": result["pairing"]["id"],
                        "label": result["pairing"]["label"],
                        "session_id": result["pairing"].get("session_id"),
                        "token_captured": False,
                        "relay_revocation_propagated": result["relay_revocation_propagated"],
                    },
                )
                self._json(result)
                return
            if path == "/remote-control/relay":
                payload = self._read_json()
                if not bool(payload.get("approved", False)):
                    raise PermissionError("remote-control relay registration requires explicit approval")
                relay_secret = str(_required(payload, "relay_auth_secret"))
                handle = orchestrator.secrets_broker.request_handle(
                    name=relay_secret,
                    requester="remote_control_relay",
                    reason="register scoped remote-control pairing with relay",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                result = remote_control.relay_pairing(
                    str(_required(payload, "pairing_id")),
                    relay_url=str(_required(payload, "relay_url")),
                    allowlist=orchestrator.config.network_allowlist,
                    relay_auth_token=relay_auth_token,
                    approved=True,
                )
                orchestrator.audit_logger.append(
                    "remote_control.relay_registered",
                    {
                        "pairing_id": result["pairing"]["id"],
                        "relay_target": result["relay_target"],
                        "relay_auth_secret": "[REDACTED]",
                        "pairing_token_relayed": result["pairing_token_relayed"],
                        "raw_secret_values_included": False,
                        "source": "api",
                    },
                )
                self._json(result)
                return
            if path == "/remote-control/relay/pull":
                payload = self._read_json()
                relay_secret = str(_required(payload, "relay_auth_secret"))
                handle = orchestrator.secrets_broker.request_handle(
                    name=relay_secret,
                    requester="remote_control_relay",
                    reason="pull queued scoped remote-control relay actions",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = orchestrator.secrets_broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                pulled = remote_control.pull_relay_actions(
                    str(_required(payload, "pairing_id")),
                    relay_auth_token=relay_auth_token,
                    allowlist=orchestrator.config.network_allowlist,
                    approved=bool(payload.get("approved", False)),
                    limit=int(payload.get("limit", 10)),
                )
                dry_run = bool(payload.get("dry_run", False))
                actor = f"remote-control-relay:{pulled['pairing'].get('label') or pulled['pairing']['id']}"
                executed_actions = []
                if not dry_run:
                    for action_row in pulled["actions"]:
                        if not action_row["accepted"]:
                            continue
                        result = _execute_remote_control_action(orchestrator, action_row, actor=actor)
                        orchestrator.audit_logger.append(
                            "remote_control.relay_action",
                            {
                                "pairing_id": pulled["pairing"]["id"],
                                "relay_target": pulled["relay_target"],
                                "task_id": action_row["task_id"],
                                "action": action_row["action"],
                                "actor": actor,
                                "request_id": action_row.get("request_id"),
                                "pairing_token_relayed": False,
                                "relay_auth_token_captured": False,
                                "raw_secret_values_included": False,
                                "source": "api_pull",
                            },
                        )
                        executed_actions.append(
                            {
                                "request_id": action_row.get("request_id"),
                                "action": action_row["action"],
                                "task_id": action_row["task_id"],
                                "status": "executed",
                                "result": result,
                            }
                        )
                orchestrator.audit_logger.append(
                    "remote_control.relay_actions_pulled",
                    {
                        "pairing_id": pulled["pairing"]["id"],
                        "relay_target": pulled["relay_target"],
                        "action_count": pulled["action_count"],
                        "executable_action_count": pulled["executable_action_count"],
                        "executed_action_count": len(executed_actions),
                        "dry_run": dry_run,
                        "pairing_token_relayed": False,
                        "relay_auth_token_captured": False,
                        "raw_secret_values_included": False,
                        "source": "api",
                    },
                )
                self._json({**pulled, "dry_run": dry_run, "executed_action_count": len(executed_actions), "executed_actions": executed_actions})
                return
            if path == "/remote-control/relay/action":
                require_allowed_host(self.headers, allowed_hosts=allowed_hosts)
                origin = self.headers.get("Origin")
                if origin and origin not in allowed_origins:
                    raise PermissionError("origin is not allowed")
                payload = self._read_json()
                action = str(_required(payload, "action")).strip().lower().replace("-", "_")
                task_id = str(_required(payload, "task_id"))
                relay_auth = remote_control.authorize_relay_action(
                    str(_required(payload, "pairing_id")),
                    _authorization_bearer(self.headers),
                    action=action,
                    task_id=task_id,
                )
                if relay_auth is None:
                    raise PermissionError("missing or invalid remote-control relay authorization")
                actor = f"remote-control-relay:{relay_auth['pairing'].get('label') or relay_auth['pairing']['id']}"
                if action == "status":
                    result = orchestrator.status(task_id)
                elif action == "events":
                    result = orchestrator.evidence.run_events(task_id)
                elif action == "resume":
                    result = orchestrator.resume_task(task_id, session_id=payload.get("session_id"), actor=actor)
                elif action == "pause":
                    result = orchestrator.pause_task(task_id, session_id=payload.get("session_id"), actor=actor, reason=str(payload.get("reason", "remote control relay pause")))
                elif action == "cancel":
                    result = orchestrator.cancel_task(task_id, session_id=payload.get("session_id"), actor=actor, reason=str(payload.get("reason", "remote control relay cancel")))
                else:
                    raise PermissionError("remote-control relay action is not allowed")
                orchestrator.audit_logger.append(
                    "remote_control.relay_action",
                    {
                        "pairing_id": relay_auth["pairing"]["id"],
                        "relay_target": relay_auth["relay_target"],
                        "task_id": task_id,
                        "action": action,
                        "actor": actor,
                        "pairing_token_relayed": False,
                        "relay_auth_token_captured": False,
                        "raw_secret_values_included": False,
                        "source": "api",
                    },
                )
                self._json(
                    {
                        "status": "relay_action_proxied",
                        "mode": "approved_relay_action_proxy",
                        "action": action,
                        "task_id": task_id,
                        "pairing": relay_auth["pairing"],
                        "relay_target": relay_auth["relay_target"],
                        "pairing_token_relayed": False,
                        "relay_auth_token_captured": False,
                        "raw_secret_values_included": False,
                        "result": result,
                    }
                )
                return
            match_remote_action = re.fullmatch(r"/remote-control/tasks/([^/]+)/(resume|pause|cancel)", path)
            if match_remote_action:
                task_id = match_remote_action.group(1)
                action = match_remote_action.group(2)
                auth = self._authorize_remote_control_action(action, task_id)
                payload = self._read_json()
                actor = f"remote-control:{auth['pairing'].get('label') or auth['pairing']['id']}"
                if action == "resume":
                    result = orchestrator.resume_task(task_id, session_id=payload.get("session_id"), actor=actor)
                elif action == "pause":
                    result = orchestrator.pause_task(task_id, session_id=payload.get("session_id"), actor=actor, reason=str(payload.get("reason", "remote control pause")))
                else:
                    result = orchestrator.cancel_task(task_id, session_id=payload.get("session_id"), actor=actor, reason=str(payload.get("reason", "remote control cancel")))
                orchestrator.audit_logger.append(
                    "remote_control.task_action",
                    {
                        "pairing_id": auth["pairing"]["id"],
                        "task_id": task_id,
                        "action": action,
                        "actor": actor,
                        "token_captured": False,
                    },
                )
                self._json(result)
                return
            if path == "/sessions":
                payload = self._read_json()
                self._json(
                    orchestrator.sessions.create_session(
                        title=str(payload.get("title", "New session")),
                        channel=str(payload.get("channel", "web")),
                        model=payload.get("model"),
                        personality=payload.get("personality"),
                    )
                )
                return
            match_session_update = re.fullmatch(r"/sessions/([^/]+)/update", path)
            if match_session_update:
                payload = self._read_json()
                self._json(
                    orchestrator.sessions.update_session(
                        match_session_update.group(1),
                        title=_optional_str(payload, "title"),
                        model=_optional_str(payload, "model"),
                        personality=_optional_str(payload, "personality"),
                        status=_optional_str(payload, "status"),
                    )
                )
                return
            match_session_compact = re.fullmatch(r"/sessions/([^/]+)/compact", path)
            if match_session_compact:
                payload = self._read_json()
                self._json(orchestrator.sessions.compact_history(match_session_compact.group(1), keep_last=int(payload.get("keep_last", 20))))
                return
            match_session_message = re.fullmatch(r"/sessions/([^/]+)/messages", path)
            if match_session_message:
                payload = self._read_json()
                session_id = match_session_message.group(1)
                request = str(_required(payload, "content"))
                if payload.get("submit", True):
                    self._json(orchestrator.submit_task(request, path=payload.get("path"), session_id=session_id))
                else:
                    trust_class = None
                    if payload.get("trust_class"):
                        trust_class = TrustClass(str(payload["trust_class"]))
                    self._json(
                        orchestrator.sessions.add_message(
                            session_id,
                            role=str(payload.get("role", "user")),
                            content=request,
                            trust_class=trust_class,
                            metadata={"source": "web", "submitted": False},
                        )
                    )
                return
            if path == "/models/auth/login":
                payload = self._read_json()
                provider = str(_required(payload, "provider"))
                method = str(payload.get("method") or "api_key").replace("-", "_")
                if method in {"subscription", "oauth", "oauth_device", "cloud_identity"}:
                    if payload.get("api_key"):
                        raise ValueError(f"{method} login does not accept API key input")
                    auth = orchestrator.models.login_provider_external(provider, method=method, verify_external=bool(payload.get("verify_external")) and not bool(payload.get("run_external")))
                    if payload.get("run_external"):
                        auth = {
                            **auth,
                            "status": "external_login_requires_local_terminal",
                            "api_run_external_allowed": False,
                            "external_login_attempted": False,
                            "external_login_error": "interactive provider login must be run from the local CLI or TUI",
                        }
                else:
                    auth = orchestrator.models.login_provider(provider, str(_required(payload, "api_key")))
                self._json(
                    {
                        "ok": True,
                        "auth": auth,
                    }
                )
                return
            if path == "/models/auth/logout":
                payload = self._read_json()
                self._json(
                    {
                        "ok": True,
                        "auth": orchestrator.models.logout_provider(str(_required(payload, "provider"))),
                    }
                )
                return
            if path == "/models/alias":
                payload = self._read_json()
                alias = str(_required(payload, "alias"))
                identifier = str(_required(payload, "identifier"))
                orchestrator.models.set_alias(alias, identifier)
                self._json({"ok": True, "alias": alias, "identifier": identifier})
                return
            if path == "/models/fallbacks":
                payload = self._read_json()
                fallbacks = payload.get("fallbacks", [])
                if not isinstance(fallbacks, list):
                    raise ValueError("fallbacks must be a JSON array")
                identifier = str(_required(payload, "identifier"))
                orchestrator.models.set_fallbacks(identifier, tuple(str(fallback) for fallback in fallbacks))
                self._json({"ok": True, "identifier": identifier, "fallbacks": [str(fallback) for fallback in fallbacks]})
                return
            if path == "/tools/run":
                payload = self._read_json()
                name = str(_required(payload, "name"))
                params = payload.get("params", {})
                if not isinstance(params, dict):
                    raise ValueError("tool params must be a JSON object")
                approval = _tool_run_approval(orchestrator, name=name, params=params, approval_id=payload.get("approval_id"))
                if approval["approved"]:
                    self._json(_with_tool_artifact_url(orchestrator, orchestrator.tools.execute(name, params, approved=True, admin_approved=bool(approval.get("admin_approved")), task_id=None)))
                    return
                result = orchestrator.tools.execute(name, params, approved=False, task_id=None)
                if result.get("status") == "approval_required":
                    self._json({**result, **approval["response"]})
                    return
                self._json(_with_tool_artifact_url(orchestrator, result))
                return
            match_skill_disable = re.fullmatch(r"/skills/([^/]+)/disable", path)
            if match_skill_disable:
                self._read_json()
                skill_id = unquote(match_skill_disable.group(1))
                orchestrator.skills.disable(skill_id)
                self._json({"ok": True, "skill_id": skill_id, "skills": orchestrator.skills.list_public()})
                return
            match_skill_enable = re.fullmatch(r"/skills/([^/]+)/enable", path)
            if match_skill_enable:
                payload = self._read_json()
                skill_id = unquote(match_skill_enable.group(1))
                result = orchestrator.enable_skill(skill_id, approval_id=str(payload["approval_id"]) if payload.get("approval_id") else None)
                self._json({**result, "skills": orchestrator.skills.list_public()})
                return
            if path == "/browser/sessions":
                payload = self._read_json()
                self._json(orchestrator.browser.create_session(label=str(payload.get("label", "Browser session"))))
                return
            match_browser_session_close = re.fullmatch(r"/browser/sessions/([^/]+)/close", path)
            if match_browser_session_close:
                self._read_json()
                self._json(orchestrator.browser.close_session(session_id=match_browser_session_close.group(1)))
                return
            if path == "/browser/navigate":
                payload = self._read_json()
                self._json(orchestrator.browser.navigate(session_id=payload.get("session_id"), url=str(_required(payload, "url"))))
                return
            if path == "/browser/extract":
                payload = self._read_json()
                self._json(orchestrator.browser.extract_text(session_id=str(_required(payload, "session_id"))))
                return
            if path == "/browser/table":
                payload = self._read_json()
                self._json(
                    orchestrator.browser.extract_table(
                        session_id=str(_required(payload, "session_id")),
                        selector=str(payload["selector"]) if payload.get("selector") else None,
                    )
                )
                return
            if path == "/browser/inspect":
                payload = self._read_json()
                self._json(orchestrator.browser.inspect(session_id=str(_required(payload, "session_id"))))
                return
            if path == "/browser/screenshot":
                payload = self._read_json()
                self._json(_with_browser_artifact_urls(orchestrator, orchestrator.browser.screenshot(session_id=str(_required(payload, "session_id")))))
                return
            if path == "/browser/render-screenshot":
                payload = self._read_json()
                self._json(_with_browser_artifact_urls(orchestrator, orchestrator.browser.render_screenshot(session_id=str(_required(payload, "session_id")))))
                return
            if path == "/browser/click":
                payload = self._read_json()
                session_id = str(_required(payload, "session_id"))
                selector = str(_required(payload, "selector"))
                approval = _browser_action_approval(
                    orchestrator,
                    action="click",
                    session_id=session_id,
                    selector=selector,
                    approval_id=payload.get("approval_id"),
                )
                if not approval["approved"]:
                    self._json(approval["response"])
                    return
                self._json(orchestrator.browser.click(session_id=session_id, selector=selector, approved=True))
                return
            if path == "/browser/fill":
                payload = self._read_json()
                session_id = str(_required(payload, "session_id"))
                fields = payload.get("fields", {})
                if not isinstance(fields, dict):
                    raise ValueError("browser fill fields must be a JSON object")
                approval = _browser_action_approval(
                    orchestrator,
                    action="fill",
                    session_id=session_id,
                    fields=fields,
                    approval_id=payload.get("approval_id"),
                )
                if not approval["approved"]:
                    self._json(approval["response"])
                    return
                self._json(orchestrator.browser.fill(session_id=session_id, fields=fields, approved=True))
                return
            if path == "/channels/render":
                payload = self._read_json()
                hints = payload.get("channel_hints", {})
                metadata = payload.get("metadata", {})
                if not isinstance(hints, dict):
                    raise ValueError("channel_hints must be a JSON object")
                if not isinstance(metadata, dict):
                    raise ValueError("metadata must be a JSON object")
                self._json(
                    {
                        "status": "rendered_pending_approval",
                        "rendered": orchestrator.channels.render(
                            ChannelResponse(
                                channel=str(_required(payload, "channel")),
                                text=str(_required(payload, "text")),
                                channel_hints=hints,
                                metadata={**metadata, "source": "web-console"},
                            )
                        ),
                    }
                )
                return
            if path == "/channels/webhook/send":
                payload = self._read_json()
                self._json(
                    orchestrator.send_webhook(
                        text=str(_required(payload, "text")),
                        approved=bool(payload.get("approved", False)),
                        session_id=str(payload["session_id"]) if payload.get("session_id") else None,
                        metadata={"source": "api"},
                    )
                )
                return
            if path == "/channels/email/send":
                payload = self._read_json()
                self._json(
                    orchestrator.send_email(
                        subject=str(_required(payload, "subject")),
                        text=str(_required(payload, "text")),
                        approved=bool(payload.get("approved", False)),
                        session_id=str(payload["session_id"]) if payload.get("session_id") else None,
                        metadata={"source": "api"},
                    )
                )
                return
            if path == "/channels/chat-webhook/send":
                payload = self._read_json()
                self._json(
                    orchestrator.send_chat_webhook(
                        text=str(_required(payload, "text")),
                        approved=bool(payload.get("approved", False)),
                        session_id=str(payload["session_id"]) if payload.get("session_id") else None,
                        metadata={"source": "api"},
                    )
                )
                return
            if path == "/channels/receive":
                payload = self._read_json()
                message_payload = {
                    "sender": str(payload.get("sender", "web-user")),
                    "text": str(_required(payload, "text")),
                    "session_id": payload.get("session_id"),
                }
                orchestrator.channels.receive(str(_required(payload, "channel")), message_payload)
                self._json({"status": "received", "message": orchestrator.channels.events(limit=1)[0]})
                return
            if path == "/channels/approval-intent/resolve":
                payload = self._read_json()
                result = orchestrator.resolve_channel_approval_intent(
                    event_id=str(_required(payload, "event_id")),
                    approval_id=str(_required(payload, "approval_id")),
                    actor=str(payload.get("actor", "")),
                    reason=str(payload.get("reason", "")),
                    admin=bool(payload.get("admin", False)),
                )
                self._json({**result, "approval": _approval_summary(orchestrator, result["approval"])})
                return
            if path == "/policy/evaluate":
                payload = self._read_json()
                decision = orchestrator.policy_gate.evaluate(_policy_request_from_payload(payload, workspace=str(workspace)))
                self._json({"decision": _policy_decision_payload(decision), "request": _safe_policy_request_payload(payload)})
                return
            if path == "/policy/import-bundle":
                payload = self._read_json()
                self._json(import_policy_bundle_text(str(_required(payload, "toml")), source=str(payload.get("name", "web-import")), base=orchestrator.config.policy_profile))
                return
            if path == "/policy/apply-bundle":
                payload = self._read_json()
                if "toml" in payload:
                    self._json(
                        apply_policy_bundle_text(
                            str(payload["toml"]),
                            data_dir=orchestrator.config.data_dir,
                            approved=bool(payload.get("approved", False)),
                            name=str(payload.get("name", "web-import")),
                            base=orchestrator.config.policy_profile,
                        )
                    )
                    return
                source = str(_required(payload, "source"))
                if source not in {bundle["name"] for bundle in list_policy_bundles()}:
                    raise ValueError("API policy apply supports built-in bundle names or inline toml")
                self._json(
                    apply_policy_bundle(
                        source,
                        data_dir=orchestrator.config.data_dir,
                        approved=bool(payload.get("approved", False)),
                        name=str(payload["name"]) if payload.get("name") else None,
                        base=orchestrator.config.policy_profile,
                    )
                )
                return
            if path == "/policy/diff-bundle":
                payload = self._read_json()
                if "toml" in payload:
                    self._json(diff_policy_bundle_text(str(payload["toml"]), current=orchestrator.config.policy_profile, name=str(payload.get("name", "web-import")), base=orchestrator.config.policy_profile))
                    return
                source = str(_required(payload, "source"))
                if source not in {bundle["name"] for bundle in list_policy_bundles()}:
                    raise ValueError("API policy diff supports built-in bundle names or inline toml")
                self._json(diff_policy_bundle(source, current=orchestrator.config.policy_profile, base=orchestrator.config.policy_profile))
                return
            if path == "/policy/rollback-bundle":
                payload = self._read_json()
                self._json(rollback_policy_bundle(data_dir=orchestrator.config.data_dir, approved=bool(payload.get("approved", False))))
                return
            if path == "/policy/schedule-bundle":
                payload = self._read_json()
                source = str(_required(payload, "source"))
                if source not in {bundle["name"] for bundle in list_policy_bundles()}:
                    raise ValueError("API policy scheduling supports built-in bundle names")
                self._json(
                    schedule_policy_bundle(
                        source,
                        data_dir=orchestrator.config.data_dir,
                        activate_at=str(_required(payload, "activate_at")),
                        environment=str(payload.get("environment", "local")),
                        approved=bool(payload.get("approved", False)),
                        name=str(payload["name"]) if payload.get("name") else None,
                        base=orchestrator.config.policy_profile,
                    )
                )
                return
            if path == "/policy/promote-bundle":
                payload = self._read_json()
                source = str(_required(payload, "source"))
                if source not in {bundle["name"] for bundle in list_policy_bundles()}:
                    raise ValueError("API policy promotion supports built-in bundle names")
                self._json(
                    promote_policy_bundle(
                        source,
                        data_dir=orchestrator.config.data_dir,
                        from_environment=str(_required(payload, "from_environment")),
                        to_environment=str(_required(payload, "to_environment")),
                        approved=bool(payload.get("approved", False)),
                        name=str(payload["name"]) if payload.get("name") else None,
                        base=orchestrator.config.policy_profile,
                        require_clean_evaluation=bool(payload.get("require_clean_evaluation", False)),
                        baseline_report_id=str(payload["baseline_report_id"]) if payload.get("baseline_report_id") else None,
                        candidate_report_id=str(payload["candidate_report_id"]) if payload.get("candidate_report_id") else None,
                        evaluation_scenario=str(payload["evaluation_scenario"]) if payload.get("evaluation_scenario") else None,
                        require_live_parity=bool(payload.get("require_live_parity", False)),
                        live_gap_backlog=build_product_dashboard(orchestrator).get("live_gap_backlog", []) if payload.get("require_live_parity") else None,
                        deferred_live_gap_areas=[str(area) for area in payload.get("deferred_live_gap_areas", [])] if isinstance(payload.get("deferred_live_gap_areas"), list) else [],
                        live_gap_deferral_reason=str(payload["live_gap_deferral_reason"]) if payload.get("live_gap_deferral_reason") else None,
                    )
                )
                return
            if path == "/policy/activate-due":
                payload = self._read_json()
                self._json(
                    activate_due_policy_rollouts(
                        data_dir=orchestrator.config.data_dir,
                        now=str(payload["now"]) if payload.get("now") else None,
                        environment=str(payload["environment"]) if payload.get("environment") else None,
                        limit=int(payload.get("limit", 20)),
                    )
                )
                return
            if path == "/channels/webhook":
                body = self._read_body(max_bytes=orchestrator.config.webhook.max_body_bytes)
                self._json(orchestrator.receive_webhook(headers={key: value for key, value in self.headers.items()}, body=body))
                return
            if path == "/memory":
                payload = self._read_json()
                tags = payload.get("tags", [])
                if not isinstance(tags, list):
                    raise ValueError("tags must be a JSON array")
                record = orchestrator.memory.create_memory(
                    memory_type=MemoryType(str(payload.get("type", MemoryType.PROJECT.value))),
                    content=str(_required(payload, "content")),
                    source=str(payload.get("source", "web-console")),
                    provenance={"web": True},
                    confidence=float(payload.get("confidence", 0.8)),
                    sensitivity=Sensitivity(str(payload.get("sensitivity", Sensitivity.INTERNAL.value))),
                    tags=tuple(str(tag) for tag in tags),
                    confirmed=bool(payload.get("confirmed", False)),
                    ttl_days=int(payload["ttl_days"]) if payload.get("ttl_days") is not None else None,
                )
                self._json(record.to_row())
                return
            match_session_memory_commit = re.fullmatch(r"/sessions/([^/]+)/memory-commit", path)
            if match_session_memory_commit:
                payload = self._read_json()
                candidate_ids = payload.get("candidate_ids")
                if candidate_ids is not None and not isinstance(candidate_ids, list):
                    raise ValueError("candidate_ids must be a list")
                session_id = match_session_memory_commit.group(1)
                self._json(
                    orchestrator.memory.commit_session_memory_candidates(
                        session_id=session_id,
                        messages=orchestrator.sessions.history(session_id, limit=1000),
                        owner=str(payload.get("owner", "local-user")),
                        scope=str(payload.get("scope", "workspace")),
                        limit=int(payload.get("limit", 25)),
                        candidate_ids=[str(candidate_id) for candidate_id in candidate_ids] if candidate_ids is not None else None,
                        confirmed=bool(payload.get("confirmed", False)),
                    )
                )
                return
            match_memory_update = re.fullmatch(r"/memory/([^/]+)/update", path)
            if match_memory_update:
                payload = self._read_json()
                self._json(
                    orchestrator.memory.update_memory(
                        match_memory_update.group(1),
                        content=str(payload["content"]) if "content" in payload else None,
                        confidence=float(payload["confidence"]) if "confidence" in payload else None,
                        confirmed=bool(payload.get("confirmed", False)),
                    )
                )
                return
            match_memory_expire = re.fullmatch(r"/memory/([^/]+)/expire", path)
            if match_memory_expire:
                self._json(orchestrator.memory.expire_memory(match_memory_expire.group(1)))
                return
            if path == "/memory/cleanup-expired":
                self._json(orchestrator.memory.cleanup_expired())
                return
            if path == "/memory/merge":
                payload = self._read_json()
                self._json(
                    orchestrator.memory.merge_duplicate(
                        str(_required(payload, "primary_id")),
                        str(_required(payload, "duplicate_id")),
                    )
                )
                return
            if path == "/memory/resolve-conflict":
                payload = self._read_json()
                self._json(
                    orchestrator.memory.resolve_conflict(
                        str(_required(payload, "primary_id")),
                        str(_required(payload, "conflicting_id")),
                        strategy=str(_required(payload, "strategy")),
                        rationale=str(_required(payload, "rationale")),
                    )
                )
                return
            if path == "/memory/review-action":
                payload = self._read_json()
                self._json(
                    orchestrator.memory.review_memory(
                        str(_required(payload, "memory_id")),
                        action=str(_required(payload, "action")),
                        confidence=float(payload["confidence"]) if payload.get("confidence") is not None else None,
                        rationale=str(payload.get("rationale", "")),
                    )
                )
                return
            if path == "/memory/review-batch":
                payload = self._read_json()
                memory_ids = payload.get("memory_ids", [])
                if not isinstance(memory_ids, list):
                    raise ValueError("memory_ids must be a list")
                self._json(
                    orchestrator.memory.review_memory_batch(
                        [str(memory_id) for memory_id in memory_ids],
                        action=str(_required(payload, "action")),
                        confidence=float(payload["confidence"]) if payload.get("confidence") is not None else None,
                        rationale=str(payload.get("rationale", "")),
                    )
                )
                return
            if path == "/memory/recertify":
                payload = self._read_json()
                self._json(
                    orchestrator.memory.recertify_due(
                        max_age_days=int(payload["max_age_days"]) if payload.get("max_age_days") is not None else None,
                        limit=int(payload.get("limit", 50)),
                        scope=str(payload.get("scope", "workspace")),
                        dry_run=bool(payload.get("dry_run", False)),
                    )
                )
                return
            if path == "/migration/memory-commit":
                payload = self._read_json()
                candidate_ids = payload.get("candidate_ids")
                if candidate_ids is not None and not isinstance(candidate_ids, list):
                    raise ValueError("candidate_ids must be a list")
                preview = _migration_memory_preview(
                    platform=str(payload.get("platform", "openclaw")),
                    path=str(_required(payload, "path")),
                    owner=str(payload.get("owner", "local-user")),
                    scope=str(payload.get("scope", "workspace")),
                )
                self._json(
                    orchestrator.memory.commit_preview_candidates(
                        preview,
                        candidate_ids=[str(candidate_id) for candidate_id in candidate_ids] if candidate_ids is not None else None,
                        confirmed=bool(payload.get("confirmed", False)),
                        reviewer=str(payload.get("reviewer", "web-console")),
                    )
                )
                return
            match_memory_delete = re.fullmatch(r"/memory/([^/]+)/delete", path)
            if match_memory_delete:
                orchestrator.memory.delete_memory(match_memory_delete.group(1))
                self._json({"ok": True, "deleted": match_memory_delete.group(1)})
                return
            if path == "/hooks":
                payload = self._read_json()
                command = payload.get("command")
                if not isinstance(command, list):
                    raise ValueError("command must be a JSON array")
                self._json(
                    {
                        "hook": orchestrator.hooks.register_hook(
                            event=str(_required(payload, "event")),
                            command=[str(part) for part in command],
                            hook_id=_optional_str(payload, "id"),
                            enabled=bool(payload.get("enabled", False)),
                            approval_required=bool(payload.get("approval_required", True)),
                            timeout_seconds=int(payload.get("timeout_seconds", 10)),
                            max_output_bytes=int(payload.get("max_output_bytes", 4096)),
                        )
                    }
                )
                return
            if path == "/hooks/run":
                payload = self._read_json()
                context = payload.get("context", {})
                if not isinstance(context, dict):
                    raise ValueError("context must be a JSON object")
                self._json(orchestrator.hooks.run_event(str(_required(payload, "event")), context=context, approved=bool(payload.get("approved", False))))
                return
            match_hook_action = re.fullmatch(r"/hooks/([^/]+)/(enable|disable|remove)", path)
            if match_hook_action:
                hook_id = unquote(match_hook_action.group(1))
                action = match_hook_action.group(2)
                if action == "enable":
                    self._json({"hook": orchestrator.hooks.set_enabled(hook_id, True)})
                elif action == "disable":
                    self._json({"hook": orchestrator.hooks.set_enabled(hook_id, False)})
                else:
                    self._json({"hook": orchestrator.hooks.remove_hook(hook_id), "removed": True})
                return
            if path == "/plugins":
                payload = self._read_json()
                self._json(
                    {
                        "plugin": orchestrator.plugins.install_plugin(
                            str(_required(payload, "manifest_path")),
                            enable=bool(payload.get("enable", False)),
                            unsigned_local=bool(payload.get("unsigned_local", False)),
                        )
                    }
                )
                return
            if path == "/plugins/reload":
                self._json({"ok": True, **_plugins_payload(orchestrator)})
                return
            if path == "/plugins/marketplace/install":
                payload = self._read_json()
                self._json(
                    orchestrator.plugins.install_marketplace_plugin(
                        str(_required(payload, "plugin_id")),
                        catalog_path=_optional_str(payload, "catalog_path"),
                        allowlist=orchestrator.config.network_allowlist,
                        enable=bool(payload.get("enable", False)),
                    )
                )
                return
            if path == "/plugins/marketplace/update":
                payload = self._read_json()
                self._json(
                    orchestrator.plugins.update_marketplace_plugin(
                        str(_required(payload, "plugin_id")),
                        catalog_path=_optional_str(payload, "catalog_path"),
                        allowlist=orchestrator.config.network_allowlist,
                        enable=payload.get("enable") if "enable" in payload else None,
                        force=bool(payload.get("force", False)),
                    )
                )
                return
            if path == "/plugins/marketplace/fetch-bundle":
                payload = self._read_json()
                self._json(
                    orchestrator.plugins.fetch_marketplace_bundle(
                        str(_required(payload, "plugin_id")),
                        catalog_path=_optional_str(payload, "catalog_path"),
                        allowlist=orchestrator.config.network_allowlist,
                        key_name=str(payload.get("key_name") or DEFAULT_SKILL_SIGNING_KEY),
                    )
                )
                return
            if path == "/plugins/marketplace/install-bundle":
                payload = self._read_json()
                self._json(
                    orchestrator.plugins.install_marketplace_bundle(
                        str(_required(payload, "plugin_id")),
                        catalog_path=_optional_str(payload, "catalog_path"),
                        allowlist=orchestrator.config.network_allowlist,
                        key_name=str(payload.get("key_name") or DEFAULT_SKILL_SIGNING_KEY),
                        enable=bool(payload.get("enable", False)),
                    )
                )
                return
            match_plugin_action = re.fullmatch(r"/plugins/([^/]+)/(enable|disable|remove)", path)
            if match_plugin_action:
                plugin_id = unquote(match_plugin_action.group(1))
                action = match_plugin_action.group(2)
                if action == "enable":
                    self._json(orchestrator.plugins.enable_plugin(plugin_id))
                elif action == "disable":
                    self._json(orchestrator.plugins.disable_plugin(plugin_id))
                else:
                    self._json(orchestrator.plugins.remove_plugin(plugin_id))
                return
            if path == "/mcp/servers":
                payload = self._read_json()
                tools = payload.get("allowed_tools", payload.get("tools", payload.get("include_tools", [])))
                if not isinstance(tools, list):
                    raise ValueError("allowed_tools must be a JSON array")
                exclude_tools = payload.get("exclude_tools", [])
                if not isinstance(exclude_tools, list):
                    raise ValueError("exclude_tools must be a JSON array")
                if bool(payload.get("discover", False)):
                    self._json(
                        orchestrator.mcp.register_discovered_server(
                            name=str(_required(payload, "name")),
                            command=str(_required(payload, "command")),
                            allowed_executables=orchestrator.config.allowed_shell_commands,
                            transport=str(payload.get("transport") or "stdio"),
                            network_allowlist=orchestrator.config.network_allowlist,
                            auth_token_secret=_optional_str(payload, "token_secret"),
                            include_tools=tuple(str(tool) for tool in tools),
                            exclude_tools=tuple(str(tool) for tool in exclude_tools),
                            include_resources=bool(payload.get("resources", True)),
                            include_prompts=bool(payload.get("prompts", True)),
                            enabled=bool(payload.get("enabled", False)),
                            approval_required=bool(payload.get("approval_required", True)),
                            metadata={"source": "web-console"},
                        )
                    )
                    return
                self._json(
                    orchestrator.mcp.register_server(
                        name=str(_required(payload, "name")),
                        command=str(_required(payload, "command")),
                        allowed_tools=tuple(str(tool) for tool in tools),
                        transport=str(payload.get("transport") or "stdio"),
                        enabled=bool(payload.get("enabled", False)),
                        approval_required=bool(payload.get("approval_required", True)),
                        metadata={"source": "web-console"},
                        network_allowlist=orchestrator.config.network_allowlist,
                        auth_token_secret=_optional_str(payload, "token_secret"),
                    )
                )
                return
            if path == "/mcp/auth/token":
                payload = self._read_json()
                self._json(orchestrator.mcp.configure_auth_token(str(_required(payload, "server")), token_secret=str(_required(payload, "token_secret"))))
                return
            if path == "/mcp/call":
                payload = self._read_json()
                server = str(_required(payload, "server"))
                tool = str(_required(payload, "tool"))
                arguments = payload.get("arguments", {})
                if not isinstance(arguments, dict):
                    raise ValueError("arguments must be a JSON object")
                approval = _mcp_call_approval(
                    orchestrator,
                    server=server,
                    tool=tool,
                    arguments=arguments,
                    approval_id=payload.get("approval_id"),
                )
                if not approval["approved"]:
                    self._json(approval["response"])
                    return
                self._json(
                    orchestrator.tools.execute(
                        "mcp_call",
                        {"server": server, "tool": tool, "arguments": arguments},
                        approved=True,
                        admin_approved=bool(approval.get("admin_approved")),
                        task_id=None,
                    )
                )
                return
            if path == "/schedules":
                payload = self._read_json()
                self._json(
                    orchestrator.schedules.create_schedule(
                        name=str(_required(payload, "name")),
                        natural_language=str(payload.get("natural_language", _required(payload, "task_request"))),
                        cron=str(_required(payload, "cron")),
                        task_request=str(_required(payload, "task_request")),
                        channel=str(payload.get("channel", "web")),
                    )
                )
                return
            if path == "/schedules/memory-review-digest":
                payload = self._read_json()
                self._json(
                    orchestrator.schedules.create_memory_review_digest_schedule(
                        name=str(_required(payload, "name")),
                        cron=str(_required(payload, "cron")),
                        channel=str(payload.get("channel", "web")),
                        limit=int(payload.get("limit", 10)),
                        scope=str(payload.get("scope", "workspace")),
                    )
                )
                return
            if path == "/schedules/memory-review-escalation":
                payload = self._read_json()
                self._json(
                    orchestrator.schedules.create_memory_review_escalation_schedule(
                        name=str(_required(payload, "name")),
                        cron=str(_required(payload, "cron")),
                        channel=str(payload.get("channel", "web")),
                        max_age_days=int(payload.get("max_age_days", 7)),
                        limit=int(payload.get("limit", 10)),
                        scope=str(payload.get("scope", "workspace")),
                        route=str(payload.get("route", "operator")),
                    )
                )
                return
            if path == "/schedules/evaluation-run":
                payload = self._read_json()
                steps = payload.get("steps", [])
                if not isinstance(steps, list):
                    steps = [str(steps)]
                self._json(
                    orchestrator.schedules.create_evaluation_run_schedule(
                        name=str(_required(payload, "name")),
                        cron=str(_required(payload, "cron")),
                        scenario=str(_required(payload, "scenario")),
                        steps=[str(step) for step in steps],
                        channel=str(payload.get("channel", "web")),
                        reviewer=str(payload.get("reviewer", "scheduler")),
                    )
                )
                return
            if path == "/schedules/evaluation-suite":
                payload = self._read_json()
                scenario_ids = payload.get("scenario_ids", [])
                if not isinstance(scenario_ids, list):
                    scenario_ids = [str(scenario_ids)]
                self._json(
                    orchestrator.schedules.create_evaluation_suite_schedule(
                        name=str(_required(payload, "name")),
                        cron=str(_required(payload, "cron")),
                        suite=str(payload.get("suite", "security")),
                        scenario_ids=[str(scenario_id) for scenario_id in scenario_ids],
                        channel=str(payload.get("channel", "web")),
                        reviewer=str(payload.get("reviewer", "scheduler")),
                    )
                )
                return
            if path == "/schedules/run-due":
                self._json(orchestrator.run_due_schedules())
                return
            match_evaluation_review = re.fullmatch(r"/evaluation/reports/([^/]+)/review", path)
            if match_evaluation_review:
                payload = self._read_json()
                self._json(
                    ResearchHarness(data_dir=orchestrator.config.data_dir).review_evaluation_report(
                        match_evaluation_review.group(1),
                        status=str(_required(payload, "status")),
                        reviewer=str(payload.get("reviewer", "local")),
                        notes=str(payload.get("notes", "")),
                    )
                )
                return
            match_schedule_activate = re.fullmatch(r"/schedules/([^/]+)/activate", path)
            if match_schedule_activate:
                self._json(orchestrator.schedules.activate(match_schedule_activate.group(1)))
                return
            match_schedule_approve = re.fullmatch(r"/schedules/([^/]+)/approve", path)
            if match_schedule_approve:
                payload = self._read_json()
                self._json(orchestrator.schedules.approve(match_schedule_approve.group(1), approved_by=str(payload.get("approved_by", "local-user"))))
                return
            match_schedule_pause = re.fullmatch(r"/schedules/([^/]+)/pause", path)
            if match_schedule_pause:
                self._json(orchestrator.schedules.pause(match_schedule_pause.group(1)))
                return
            if path == "/kanban/boards":
                payload = self._read_json()
                self._json(orchestrator.kanban.create_board(str(_required(payload, "name"))))
                return
            match_card = re.fullmatch(r"/kanban/boards/([^/]+)/cards", path)
            if match_card:
                payload = self._read_json()
                self._json(
                    orchestrator.kanban.add_card(
                        match_card.group(1),
                        title=str(_required(payload, "title")),
                        description=str(payload.get("description", "")),
                        lane=str(payload.get("lane", "backlog")),
                    )
                )
                return
            match_move = re.fullmatch(r"/kanban/cards/([^/]+)/move", path)
            if match_move:
                payload = self._read_json()
                lane = str(_required(payload, "lane"))
                orchestrator.kanban.move_card(match_move.group(1), lane)
                self._json({"ok": True, "card_id": match_move.group(1), "lane": lane})
                return
            if path == "/subagents/delegate":
                payload = self._read_json()
                params = {"role": str(_required(payload, "role")), "task": str(_required(payload, "task"))}
                approval = _tool_run_approval(orchestrator, name="subagent_delegate", params=params, approval_id=payload.get("approval_id"))
                if approval["approved"]:
                    result = orchestrator.tools.execute(
                        "subagent_delegate",
                        params,
                        approved=True,
                        admin_approved=bool(approval.get("admin_approved")),
                        task_id=str(payload.get("task_id")) if payload.get("task_id") else None,
                    )
                    self._json({**result, "subagents": orchestrator.kanban.subagent_status(limit=int(payload.get("limit", 20)))})
                    return
                result = orchestrator.tools.execute("subagent_delegate", params, approved=False, task_id=str(payload.get("task_id")) if payload.get("task_id") else None)
                if result.get("status") == "approval_required":
                    self._json({**result, **approval["response"], "subagents": orchestrator.kanban.subagent_status(limit=int(payload.get("limit", 20)))})
                    return
                self._json({**result, "subagents": orchestrator.kanban.subagent_status(limit=int(payload.get("limit", 20)))})
                return
            if path == "/subagents/handoff":
                payload = self._read_json()
                result = orchestrator.kanban.move_subagent_delegation(
                    str(_required(payload, "card_id")),
                    str(_required(payload, "lane")),
                    actor=str(payload.get("actor", "api-operator")),
                    reason=str(payload.get("reason", "")),
                )
                self._json({**result, "subagents": orchestrator.kanban.subagent_status(limit=int(payload.get("limit", 20)))})
                return
            match_approval_approve = re.fullmatch(r"/approvals/([^/]+)/approve", path)
            if match_approval_approve:
                payload = self._read_json()
                self._json(
                    _approval_summary(
                        orchestrator,
                        orchestrator.approvals.approve(
                            match_approval_approve.group(1),
                            actor=str(payload.get("actor", "local-user")),
                            reason=str(payload.get("reason", "")),
                            admin=bool(payload.get("admin", False)),
                        ),
                    )
                )
                return
            match_approval_deny = re.fullmatch(r"/approvals/([^/]+)/deny", path)
            if match_approval_deny:
                payload = self._read_json()
                self._json(
                    _approval_summary(
                        orchestrator,
                        orchestrator.approvals.deny(
                            match_approval_deny.group(1),
                            actor=str(payload.get("actor", "local-user")),
                            reason=str(payload.get("reason", "")),
                            admin=bool(payload.get("admin", False)),
                        ),
                    )
                )
                return
            match_improvement_status = re.fullmatch(r"/improvements/([^/]+)/status", path)
            if match_improvement_status:
                payload = self._read_json()
                self._json(orchestrator.update_improvement_proposal(match_improvement_status.group(1), status=str(_required(payload, "status"))))
                return
            match_improvement_attempt = re.fullmatch(r"/improvements/([^/]+)/attempts", path)
            if match_improvement_attempt:
                payload = self._read_json()
                changed_files = payload.get("changed_files", [])
                if not isinstance(changed_files, list):
                    raise ValueError("changed_files must be a JSON array")
                self._json(
                    orchestrator.record_improvement_attempt(
                        match_improvement_attempt.group(1),
                        outcome=str(_required(payload, "outcome")),
                        notes=str(payload.get("notes", "")),
                        status=str(payload.get("status", "implemented")),
                        actor=str(payload.get("actor", "local-user")),
                        changed_files=tuple(str(item) for item in changed_files),
                        candidate_id=str(payload["candidate_id"]) if payload.get("candidate_id") else None,
                        test_command=str(payload.get("test_command", "")),
                        test_result=str(payload.get("test_result", "")),
                    )
                )
                return
            match_improvement_candidate = re.fullmatch(r"/improvements/([^/]+)/candidates", path)
            if match_improvement_candidate:
                payload = self._read_json()
                changed_files = payload.get("changed_files", [])
                if not isinstance(changed_files, list):
                    raise ValueError("changed_files must be a JSON array")
                self._json(
                    orchestrator.create_repair_candidate(
                        match_improvement_candidate.group(1),
                        summary=str(_required(payload, "summary")),
                        actor=str(payload.get("actor", "web-console")),
                        changed_files=tuple(str(item) for item in changed_files),
                        patch_plan=str(payload.get("patch_plan", "")),
                        unified_diff=str(payload.get("unified_diff", "")),
                    )
                )
                return
            match_improvement_generate_candidate = re.fullmatch(r"/improvements/([^/]+)/candidates/generate", path)
            if match_improvement_generate_candidate:
                payload = self._read_json()
                self._json(
                    orchestrator.generate_repair_candidate(
                        match_improvement_generate_candidate.group(1),
                        actor=str(payload.get("actor", "web-console")),
                    )
                )
                return
            match_improvement_synthesis_prompt = re.fullmatch(r"/improvements/([^/]+)/synthesis-prompt", path)
            if match_improvement_synthesis_prompt:
                payload = self._read_json()
                self._json(
                    orchestrator.create_repair_synthesis_prompt(
                        match_improvement_synthesis_prompt.group(1),
                        actor=str(payload.get("actor", "web-console")),
                    )
                )
                return
            match_improvement_synthesize_candidate = re.fullmatch(r"/improvements/([^/]+)/candidates/synthesize", path)
            if match_improvement_synthesize_candidate:
                payload = self._read_json()
                synthesis = payload.get("synthesis", payload)
                if not isinstance(synthesis, dict):
                    raise ValueError("synthesis must be a JSON object")
                self._json(
                    orchestrator.synthesize_repair_candidate(
                        match_improvement_synthesize_candidate.group(1),
                        synthesis=synthesis,
                        actor=str(payload.get("actor", "web-console")),
                    )
                )
                return
            match_improvement_review_candidate = re.fullmatch(r"/improvements/([^/]+)/candidates/([^/]+)/review", path)
            if match_improvement_review_candidate:
                payload = self._read_json()
                self._json(
                    orchestrator.review_repair_candidate(
                        match_improvement_review_candidate.group(1),
                        match_improvement_review_candidate.group(2),
                        status=str(_required(payload, "status")),
                        actor=str(payload.get("actor", "web-console")),
                    )
                )
                return
            match_improvement_apply_candidate = re.fullmatch(r"/improvements/([^/]+)/candidates/([^/]+)/apply", path)
            if match_improvement_apply_candidate:
                payload = self._read_json()
                self._json(
                    orchestrator.apply_repair_candidate(
                        match_improvement_apply_candidate.group(1),
                        match_improvement_apply_candidate.group(2),
                        actor=str(payload.get("actor", "web-console")),
                    )
                )
                return
            match_improvement_rollback_candidate = re.fullmatch(r"/improvements/([^/]+)/candidates/([^/]+)/rollback", path)
            if match_improvement_rollback_candidate:
                payload = self._read_json()
                self._json(
                    orchestrator.rollback_repair_candidate(
                        match_improvement_rollback_candidate.group(1),
                        match_improvement_rollback_candidate.group(2),
                        actor=str(payload.get("actor", "web-console")),
                    )
                )
                return
            match = re.fullmatch(r"/tasks/([^/]+)/resume", path)
            if match:
                payload = self._read_json()
                self._json(orchestrator.resume_task(match.group(1), session_id=payload.get("session_id")))
                return
            match_task_pause = re.fullmatch(r"/tasks/([^/]+)/pause", path)
            if match_task_pause:
                payload = self._read_json()
                self._json(
                    orchestrator.pause_task(
                        match_task_pause.group(1),
                        session_id=payload.get("session_id"),
                        actor=str(payload.get("actor", "web-console")),
                        reason=str(payload.get("reason", "")),
                    )
                )
                return
            match_task_cancel = re.fullmatch(r"/tasks/([^/]+)/cancel", path)
            if match_task_cancel:
                payload = self._read_json()
                self._json(
                    orchestrator.cancel_task(
                        match_task_cancel.group(1),
                        session_id=payload.get("session_id"),
                        actor=str(payload.get("actor", "web-console")),
                        reason=str(payload.get("reason", "")),
                    )
                )
                return
            self._json({"error": "not found"}, status=404)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _authorize_mutation(self) -> None:
            authorize_local_request(self.headers, token=api_token, allowed_hosts=allowed_hosts, allowed_origins=allowed_origins)

        def _authorize_read(self) -> None:
            authorize_local_request(self.headers, token=api_token, allowed_hosts=allowed_hosts, allowed_origins=allowed_origins)

        def _authorize_local_mutation(self) -> None:
            authorize_local_request(self.headers, token=api_token, allowed_hosts=allowed_hosts, allowed_origins=allowed_origins)

        def _authorize_remote_control_status(self) -> dict[str, Any]:
            return authorize_remote_control_request(self.headers, token=api_token, allowed_hosts=allowed_hosts, allowed_origins=allowed_origins, remote_control=remote_control)

        def _authorize_remote_control_action(self, action: str, task_id: str) -> dict[str, Any]:
            return authorize_remote_control_request(
                self.headers,
                token=api_token,
                allowed_hosts=allowed_hosts,
                allowed_origins=allowed_origins,
                remote_control=remote_control,
                action=action,
                task_id=task_id,
            )

        def _require_allowed_host(self) -> None:
            require_allowed_host(self.headers, allowed_hosts=allowed_hosts)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b"{}"
            decoded = json.loads(body.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise ValueError("request body must be a JSON object")
            return decoded

        def _read_body(self, *, max_bytes: int) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            if length > max_bytes:
                raise ValueError("request body exceeds configured maximum")
            return self.rfile.read(length) if length else b""

        def _json(self, payload: dict[str, Any], *, status: int = 200) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _event_stream(
            self,
            task_id: str,
            *,
            follow: bool = False,
            live: bool = False,
            timeout_seconds: float = 0.0,
            since_sequence: int = 0,
        ) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            payload = orchestrator.evidence.run_events(task_id)
            stream_mode = "live" if live else "follow" if follow else "snapshot"
            self._write_sse_retry(1000)
            self._write_sse(
                "task",
                {
                    **{key: value for key, value in payload.items() if key != "events"},
                    "stream_mode": stream_mode,
                    "since": since_sequence,
                },
                event_id=f"{task_id}:0",
            )
            seen_events: set[str] = set()
            for event in payload.get("events", []):
                seen_events.add(_event_stream_key(event))
                if int(event.get("sequence", 0) or 0) > since_sequence:
                    self._write_sse("run_event", event, event_id=f"{task_id}:{event.get('sequence', 0)}")
            if follow or live:
                deadline = time.monotonic() + timeout_seconds
                while payload.get("status") not in _TERMINAL_TASK_STATUSES and time.monotonic() < deadline:
                    time.sleep(0.25)
                    payload = orchestrator.evidence.run_events(task_id)
                    self._write_sse(
                        "task_status",
                        {
                            "task_id": payload.get("task_id"),
                            "status": payload.get("status"),
                            "events": len(payload.get("events", [])),
                            "progress": payload.get("progress", {}),
                        },
                    )
                    for event in payload.get("events", []):
                        key = _event_stream_key(event)
                        if key in seen_events:
                            continue
                        seen_events.add(key)
                        if int(event.get("sequence", 0) or 0) > since_sequence:
                            self._write_sse("run_event", event, event_id=f"{task_id}:{event.get('sequence', 0)}")
                    self._write_sse(
                        "heartbeat",
                        {
                            "task_id": task_id,
                            "status": payload.get("status"),
                            "events": len(seen_events),
                            "progress": payload.get("progress", {}),
                        },
                    )
            emitted = sum(1 for event in payload.get("events", []) if int(event.get("sequence", 0) or 0) > since_sequence)
            self._write_sse(
                "done",
                {
                    "task_id": payload.get("task_id"),
                    "status": payload.get("status"),
                    "events": len(seen_events),
                    "emitted": emitted,
                    "progress": payload.get("progress", {}),
                    "follow": follow,
                    "live": live,
                    "stream_mode": stream_mode,
                    "since": since_sequence,
                    "timeout_seconds": timeout_seconds,
                },
            )

        def _write_sse(self, event: str, payload: dict[str, Any], *, event_id: str | None = None) -> None:
            prefix = f"id: {event_id}\n" if event_id else ""
            encoded = f"{prefix}event: {event}\ndata: {json.dumps(payload, sort_keys=True)}\n\n".encode("utf-8")
            self.wfile.write(encoded)
            self.wfile.flush()

        def _write_sse_retry(self, milliseconds: int) -> None:
            self.wfile.write(f"retry: {milliseconds}\n\n".encode("utf-8"))
            self.wfile.flush()

        def _static(self, path: Path) -> None:
            if not path.exists() or not path.is_file():
                self._json({"error": "not found"}, status=404)
                return
            content = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(str(path))[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def _tool_artifact(self, raw_name: str) -> None:
            name = unquote(raw_name)
            if not name or "/" in name or "\\" in name:
                self._json({"error": "invalid artifact path"}, status=403)
                return
            artifact_dir = _tool_artifact_dir(orchestrator)
            path = (artifact_dir / name).resolve()
            if artifact_dir not in (path, *path.parents) or not path.is_file():
                self._json({"error": "not found"}, status=404)
                return
            content = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", _safe_artifact_content_type(path))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def _browser_artifact(self, raw_name: str) -> None:
            name = unquote(raw_name)
            if not name or "/" in name or "\\" in name:
                self._json({"error": "invalid artifact path"}, status=403)
                return
            artifact_dir = _browser_artifact_dir(orchestrator)
            path = (artifact_dir / name).resolve()
            if artifact_dir not in (path, *path.parents) or not path.is_file():
                self._json({"error": "not found"}, status=404)
                return
            content = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", _safe_artifact_content_type(path))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

    server = ThreadingHTTPServer((host, port), Handler)
    schedule_worker.start()
    print(f"Aegis Agent API listening on http://{host}:{port}", flush=True)
    print("Aegis Agent local API token is available to the same-origin web app at /auth", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Aegis Agent API stopped", flush=True)
    finally:
        schedule_worker.stop()
        server.server_close()


def _task_summary(row: dict[str, Any], *, orchestrator: Any | None = None) -> dict[str, Any]:
    decoded = dict(row)
    decoded["plan"] = json.loads(decoded.pop("plan_json", "[]"))
    decoded["checkpoint"] = json.loads(decoded.pop("checkpoint_json", "{}"))
    receipt_json = decoded.pop("receipt_json", None)
    decoded["receipt"] = json.loads(receipt_json) if receipt_json else None
    decoded["session"] = None
    decoded["action_hints"] = _task_action_hints(decoded.get("id"), decoded.get("session_id"), status=decoded.get("status"))
    if orchestrator is not None and decoded.get("session_id"):
        decoded["session"] = orchestrator.status(str(decoded["id"])).get("session")
    return decoded


def _task_action_hints(task_id: Any, session_id: Any, *, status: Any) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    task_id_text = str(task_id) if task_id else ""
    if session_id:
        session_id_text = str(session_id)
        hints.extend(
            [
                {"label": "Show Session", "command": f"session show {session_id_text}", "action": "session_show", "session_id": session_id_text},
                {"label": "Session History", "command": f"session history {session_id_text}", "action": "session_history", "session_id": session_id_text},
            ]
        )
    if task_id_text and status in {"waiting_approval", "paused"}:
        hints.append({"label": "Resume", "command": f"task resume {task_id_text}", "action": "task_resume", "task_id": task_id_text})
    return hints


def _approval_summary(orchestrator: Any, approval: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(approval)
    decoded["session_id"] = None
    decoded["session"] = None
    task_id = decoded.get("task_id")
    if task_id:
        try:
            task = orchestrator.status(str(task_id))
        except KeyError:
            task = {}
        decoded["session_id"] = task.get("session_id")
        decoded["session"] = task.get("session")
    elif isinstance(decoded.get("payload"), dict):
        payload_session_id = _approval_payload_session_id(decoded["payload"])
        if payload_session_id:
            decoded["session_id"] = payload_session_id
            decoded["session"] = _session_summary(orchestrator, payload_session_id)
    request_payload = decoded.get("payload") if isinstance(decoded.get("payload"), dict) else {}
    decoded["action_hints"] = approval_action_hints(
        decoded,
        task_id=task_id,
        session_id=decoded.get("session_id"),
        admin_required=bool(request_payload.get("admin_required")) if isinstance(request_payload, dict) else False,
    )
    return decoded


def _approval_payload_session_id(payload: dict[str, Any]) -> str | None:
    if isinstance(payload.get("session_id"), str):
        return payload["session_id"]
    params = payload.get("params")
    if isinstance(params, dict) and isinstance(params.get("session_id"), str):
        return params["session_id"]
    arguments = payload.get("arguments")
    if isinstance(arguments, dict) and isinstance(arguments.get("session_id"), str):
        return arguments["session_id"]
    return None


def _session_summary(orchestrator: Any, session_id: str) -> dict[str, Any] | None:
    session = orchestrator.store.get_session(session_id)
    if not session:
        return None
    return {
        "id": session["id"],
        "title": session["title"],
        "channel": session["channel"],
        "status": session["status"],
    }


def _model_route_payload(route: Any) -> dict[str, Any]:
    return {
        "identifier": route.identifier,
        "provider": route.provider.provider,
        "model": route.model,
        "fallbacks": list(route.fallback_identifiers),
        "secret_handle_id": route.secret_handle_id,
        "auth_method": route.auth_method,
    }


def _policy_summary(orchestrator: Any) -> dict[str, Any]:
    profile = orchestrator.policy_gate.engine.profile
    return {
        "profile": policy_profile_to_dict(profile),
        "bundles": list_policy_bundles(),
        "immutable_deny": ["raw_secret_exposure", "secret_data"],
        "decision_types": [
            "allow",
            "deny",
            "require_approval",
            "require_admin_approval",
            "require_dry_run_first",
            "require_additional_evidence",
            "require_safer_alternative",
            "quarantine",
        ],
    }


def _policy_request_from_payload(payload: dict[str, Any], *, workspace: str) -> PolicyRequest:
    scopes = payload.get("requested_scopes", payload.get("scopes", []))
    if isinstance(scopes, str):
        scopes = [item.strip() for item in scopes.split(",") if item.strip()]
    if not isinstance(scopes, list):
        raise ValueError("requested_scopes must be a JSON array or comma-separated string")
    return PolicyRequest(
        user_role=str(payload.get("user_role", "local-user")),
        workspace=str(payload.get("workspace", workspace)),
        task_type=str(payload.get("task_type", "ad-hoc")),
        risk_level=RiskLevel(str(payload.get("risk_level", RiskLevel.LOW.value))),
        connector=str(payload["connector"]) if payload.get("connector") is not None else None,
        operation=str(payload.get("operation", "read")),
        requested_scopes=tuple(str(scope) for scope in scopes),
        data_sensitivity=Sensitivity(str(payload.get("data_sensitivity", Sensitivity.INTERNAL.value))),
        approval_state=str(payload["approval_state"]) if payload.get("approval_state") is not None else None,
        environment=str(payload.get("environment", "local")),
        target_domain=str(payload["target_domain"]) if payload.get("target_domain") is not None else None,
    )


def _safe_policy_request_payload(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "user_role",
        "workspace",
        "task_type",
        "risk_level",
        "connector",
        "operation",
        "requested_scopes",
        "scopes",
        "data_sensitivity",
        "approval_state",
        "environment",
        "target_domain",
    }
    return {key: value for key, value in payload.items() if key in allowed}


def _policy_decision_payload(decision: PolicyDecision) -> dict[str, Any]:
    return {
        "decision": decision.decision.value,
        "allowed": decision.allowed,
        "risk_level": decision.risk_level.value,
        "reasons": list(decision.reasons),
        "requirements": list(decision.requirements),
    }


def _limit(query: dict[str, list[str]], *, default: int) -> int:
    value = int(query.get("limit", [str(default)])[0])
    if value < 1 or value > 1000:
        raise ValueError("limit must be between 1 and 1000")
    return value


def _truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def _stream_timeout(query: dict[str, list[str]]) -> float:
    raw = query.get("timeout", ["0"])[0] or "0"
    try:
        requested = float(raw)
    except ValueError as exc:
        raise ValueError("timeout must be a number of seconds") from exc
    max_timeout = _LIVE_STREAM_TIMEOUT_MAX_SECONDS if _truthy(query.get("live", ["0"])[0]) else _STREAM_TIMEOUT_MAX_SECONDS
    return max(0.0, min(requested, max_timeout))


def _since_sequence(query: dict[str, list[str]], last_event_id: str | None) -> int:
    raw = query.get("since", [""])[0] or ""
    if not raw and last_event_id:
        raw = last_event_id.rsplit(":", 1)[-1]
    if not raw:
        return 0
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise ValueError("since must be an event sequence integer") from exc
    if parsed < 0:
        raise ValueError("since must be non-negative")
    return parsed


def _required(payload: dict[str, Any], key: str) -> Any:
    if key not in payload:
        raise ValueError(f"missing required field: {key}")
    return payload[key]


def _event_stream_key(event: dict[str, Any]) -> str:
    if event.get("hash"):
        return str(event["hash"])
    if event.get("sequence") is not None:
        return f"seq:{event['sequence']}"
    return json.dumps(event, sort_keys=True)


def _optional_str(payload: dict[str, Any], key: str) -> str | None:
    if key not in payload:
        return None
    value = payload[key]
    return None if value is None else str(value)


def _optional_int(payload: dict[str, Any], key: str) -> int | None:
    if key not in payload or payload[key] is None:
        return None
    return int(payload[key])


def _optional_str_list(payload: dict[str, Any], key: str) -> list[str] | None:
    if key not in payload or payload[key] is None:
        return None
    value = payload[key]
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a JSON array")
    return [str(item) for item in value]


def _exception_detail(exc: KeyError) -> str:
    if exc.args:
        return str(exc.args[0])
    return "resource not found"


def _approved_payload(approval: dict[str, Any]) -> dict[str, Any]:
    payload = dict(approval.get("payload", {}))
    payload.pop("_decision", None)
    return payload


def _tool_run_approval(orchestrator: Any, *, name: str, params: dict[str, Any], approval_id: Any = None) -> dict[str, Any]:
    payload = _tool_run_payload(name=name, params=params)
    if approval_id:
        approval = orchestrator.approvals.get(str(approval_id))
        if _approved_payload(approval) != payload:
            raise PermissionError("tool approval does not match requested run")
        if approval["status"] == "denied":
            return {"approved": False, "response": {"status": "approval_denied", "approval_id": approval["id"], "tool": name}}
        if approval["status"] != "approved":
            return {"approved": False, "response": {"status": "approval_required", "approval_id": approval["id"], "tool": name}}
        decision = approval.get("decision") or {}
        return {"approved": True, "admin_approved": bool(decision.get("admin"))}

    virtual_mcp_tool = orchestrator.mcp.resolve_virtual_tool(name)
    if virtual_mcp_tool is not None:
        approval_required = bool(virtual_mcp_tool.get("approval_required", True))
        risk_level = RiskLevel.HIGH
    else:
        spec = orchestrator.tool_catalog.get(name)
        approval_required = spec.approval_required
        risk_level = spec.risk_level
    if not approval_required:
        return {"approved": False, "response": {}}
    approval = orchestrator.approvals.request_approval(
        ApprovalRequest(
            task_id=None,
            reason=f"tool {name} requires approval",
            risk_level=risk_level,
            payload=payload,
        )
    )
    return {
        "approved": False,
        "response": {
            "approval_id": approval.id,
            "tool": name,
            "reason": f"tool {name} requires approval",
        },
    }


def _tool_run_payload(*, name: str, params: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    payload = {
        "kind": "tool_run",
        "tool": name,
        "param_keys": sorted(str(key) for key in params),
        "params_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    if isinstance(params.get("session_id"), str):
        payload["session_id"] = params["session_id"]
    return payload


def _browser_action_approval(
    orchestrator: Any,
    *,
    action: str,
    session_id: str,
    selector: str | None = None,
    fields: dict[str, Any] | None = None,
    approval_id: Any = None,
) -> dict[str, Any]:
    payload = _browser_action_payload(action=action, session_id=session_id, selector=selector, fields=fields)
    if approval_id:
        approval = orchestrator.approvals.get(str(approval_id))
        if _approved_payload(approval) != payload:
            raise PermissionError("browser approval does not match requested action")
        if approval["status"] == "denied":
            return {"approved": False, "response": {"status": "approval_denied", "approval_id": approval["id"], "action": action}}
        if approval["status"] != "approved":
            return {"approved": False, "response": {"status": "approval_required", "approval_id": approval["id"], "action": action}}
        decision = approval.get("decision") or {}
        return {"approved": True, "admin_approved": bool(decision.get("admin"))}

    approval = orchestrator.approvals.request_approval(
        ApprovalRequest(
            task_id=None,
            reason=f"browser {action} requires approval",
            risk_level=RiskLevel.HIGH,
            payload=payload,
        )
    )
    return {
        "approved": False,
        "response": {
            "status": "approval_required",
            "approval_id": approval.id,
            "action": action,
            "session_id": session_id,
            "reason": f"browser {action} requires approval",
        },
    }


def _browser_action_payload(*, action: str, session_id: str, selector: str | None = None, fields: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"kind": "browser_action", "action": action, "session_id": session_id}
    if action == "click":
        payload["selector"] = selector or ""
        return payload
    if action == "fill":
        safe_fields = {str(key): str(value) for key, value in (fields or {}).items()}
        encoded = json.dumps(safe_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload["field_selectors"] = sorted(safe_fields)
        payload["fields_sha256"] = hashlib.sha256(encoded).hexdigest()
        return payload
    raise ValueError(f"unsupported browser approval action: {action}")


def _mcp_call_approval(
    orchestrator: Any,
    *,
    server: str,
    tool: str,
    arguments: dict[str, Any],
    approval_id: Any = None,
) -> dict[str, Any]:
    payload = _mcp_call_payload(server=server, tool=tool, arguments=arguments)
    if approval_id:
        approval = orchestrator.approvals.get(str(approval_id))
        if _approved_payload(approval) != payload:
            raise PermissionError("MCP approval does not match requested call")
        if approval["status"] == "denied":
            return {"approved": False, "response": {"status": "approval_denied", "approval_id": approval["id"], "server": server, "tool": tool}}
        if approval["status"] != "approved":
            return {"approved": False, "response": {"status": "approval_required", "approval_id": approval["id"], "server": server, "tool": tool}}
        decision = approval.get("decision") or {}
        return {"approved": True, "admin_approved": bool(decision.get("admin"))}

    approval = orchestrator.approvals.request_approval(
        ApprovalRequest(
            task_id=None,
            reason=f"MCP tool {server}.{tool} requires approval",
            risk_level=RiskLevel.HIGH,
            payload=payload,
        )
    )
    return {
        "approved": False,
        "response": {
            "status": "approval_required",
            "approval_id": approval.id,
            "server": server,
            "tool": tool,
            "reason": f"MCP tool {server}.{tool} requires approval",
        },
    }


def _execute_remote_control_action(orchestrator: Any, action_row: dict[str, Any], *, actor: str) -> dict[str, Any]:
    task_id = str(action_row["task_id"])
    action = str(action_row["action"])
    session_id = action_row.get("session_id")
    reason = str(action_row.get("reason") or "")
    if action == "status":
        return orchestrator.status(task_id)
    if action == "events":
        return orchestrator.evidence.run_events(task_id)
    if action == "resume":
        return orchestrator.resume_task(task_id, session_id=session_id, actor=actor)
    if action == "pause":
        return orchestrator.pause_task(task_id, session_id=session_id, actor=actor, reason=reason or "remote control relay pause")
    if action == "cancel":
        return orchestrator.cancel_task(task_id, session_id=session_id, actor=actor, reason=reason or "remote control relay cancel")
    raise PermissionError("remote-control relay action is not allowed")


def _mcp_call_payload(*, server: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    safe_arguments = {str(key): value for key, value in arguments.items()}
    encoded = json.dumps(safe_arguments, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return {
        "kind": "mcp_call",
        "server": server,
        "tool": tool,
        "argument_keys": sorted(safe_arguments),
        "arguments_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _migration_memory_preview(*, platform: str, path: str, owner: str, scope: str) -> dict[str, Any]:
    if not path:
        raise ValueError("missing required query parameter: path")
    if platform == "openclaw":
        return preview_openclaw_memory_import(path, owner=owner, scope=scope)
    if platform == "hermes":
        return preview_hermes_memory_import(path, owner=owner, scope=scope)
    raise ValueError("platform must be openclaw or hermes")


def _allowed_hosts(host: str, port: int) -> set[str]:
    hosts = {f"{host}:{port}"}
    if host in {"127.0.0.1", "localhost", "::1"}:
        hosts.update({f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"})
    return hosts


def _allowed_origins(host: str, port: int) -> set[str]:
    origins = {f"http://{host}:{port}"}
    if host in {"127.0.0.1", "localhost", "::1"}:
        origins.update({f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}"})
    return origins


def require_allowed_host(headers: Any, *, allowed_hosts: set[str]) -> None:
    host_header = headers.get("Host", "")
    if host_header not in allowed_hosts:
        raise PermissionError("host is not allowed")


def authorize_local_request(headers: Any, *, token: str, allowed_hosts: set[str], allowed_origins: set[str]) -> None:
    require_allowed_host(headers, allowed_hosts=allowed_hosts)
    origin = headers.get("Origin")
    if origin and origin not in allowed_origins:
        raise PermissionError("origin is not allowed")
    supplied = headers.get("X-Aegis-Token", "")
    if not secrets.compare_digest(supplied, token):
        raise PermissionError("missing or invalid local API token")


def _authorization_bearer(headers: Any) -> str:
    value = str(headers.get("Authorization", "") or "")
    if not value.lower().startswith("bearer "):
        return ""
    return value[7:].strip()


def authorize_remote_control_request(
    headers: Any,
    *,
    token: str,
    allowed_hosts: set[str],
    allowed_origins: set[str],
    remote_control: RemoteControlPairingRegistry,
    action: str | None = None,
    task_id: str | None = None,
) -> dict[str, Any]:
    require_allowed_host(headers, allowed_hosts=allowed_hosts)
    origin = headers.get("Origin")
    if origin and origin not in allowed_origins:
        raise PermissionError("origin is not allowed")
    supplied = headers.get("X-Aegis-Token", "")
    if secrets.compare_digest(supplied, token):
        return {"auth_kind": "local_api"}
    remote_token = headers.get(REMOTE_CONTROL_TOKEN_HEADER, "")
    if action and task_id:
        pairing = remote_control.authorize_action(remote_token, action=action, task_id=task_id)
    else:
        pairing = remote_control.authorize(remote_token)
    if pairing is not None:
        return {"auth_kind": "remote_control", "pairing": pairing}
    raise PermissionError("missing or invalid remote-control token")
