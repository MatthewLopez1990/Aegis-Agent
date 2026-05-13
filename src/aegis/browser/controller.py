"""Dependency-light governed browser sessions."""

from __future__ import annotations

import html
import importlib.util
import json
import hashlib
import base64
from html.parser import HTMLParser
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from typing import Any
from urllib import request as urllib_request
from urllib.parse import quote, urlencode, urljoin, urlparse
from uuid import uuid4
import zlib

from aegis.audit.logger import AuditLogger, redact
from aegis.connectors.base import ConnectorRequest
from aegis.connectors.http import _private_network_error, _validate_url
from aegis.connectors.registry import ConnectorRegistry
from aegis.security.taint import now_utc
from aegis.storage.state import ensure_private_dir, ensure_private_file


_MAX_PERSISTED_CONTENT_CHARS = 200_000
_MAX_STATIC_DOM_NODES = 120
_MAX_STATIC_DOM_DEPTH = 12
_MAX_STATIC_DOM_TEXT_CHARS = 160
_MAX_LIVE_BROWSER_DOWNLOAD_BYTES = 25 * 1024 * 1024
_MAX_LIVE_BROWSER_UPLOAD_BYTES = 10 * 1024 * 1024
_MAX_LIVE_BROWSER_DOWNLOAD_MIME_SAMPLE_BYTES = 4096
_ALLOWED_LIVE_BROWSER_DOWNLOAD_MIME_TYPES = {
    "application/json",
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/webp",
    "text/csv",
    "text/plain",
}
_ALLOWED_LIVE_BROWSER_UPLOAD_MIME_TYPES = set(_ALLOWED_LIVE_BROWSER_DOWNLOAD_MIME_TYPES)
_STATIC_DOM_ATTR_ALLOWLIST = {
    "id",
    "class",
    "name",
    "type",
    "role",
    "aria-label",
    "placeholder",
    "href",
    "action",
    "method",
    "value",
    "title",
    "data-testid",
}
_DOM_SECRETISH_TOKEN_RE = re.compile(r"\b(?=[A-Za-z0-9_-]{6,}\b)(?=[A-Za-z0-9_-]*[A-Za-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{6,}\b")


class BrowserController:
    def __init__(
        self,
        connectors: ConnectorRegistry,
        audit_logger: AuditLogger,
        artifact_dir: str | Path,
        *,
        live_browser_reads: bool = False,
        live_browser_mutations: bool = False,
        live_browser_downloads: bool = False,
        live_browser_uploads: bool = False,
        workspace_root: str | Path | None = None,
        network_allowlist: tuple[str, ...] = (),
    ) -> None:
        self.connectors = connectors
        self.audit_logger = audit_logger
        self.artifact_dir = ensure_private_dir(artifact_dir)
        self.live_browser_reads = live_browser_reads or live_browser_mutations or live_browser_downloads or live_browser_uploads
        self.live_browser_mutations = live_browser_mutations
        self.live_browser_downloads = live_browser_downloads
        self.live_browser_uploads = live_browser_uploads
        self.workspace_root = Path(workspace_root or ".").expanduser().resolve()
        self.network_allowlist = network_allowlist
        self.session_store_path = ensure_private_file(self.artifact_dir / "sessions.json")
        self._sessions: dict[str, dict[str, Any]] = {}
        self._load_sessions()

    def create_session(self, *, label: str = "Browser session") -> dict[str, Any]:
        session = {
            "id": str(uuid4()),
            "label": label,
            "status": "active",
            "current_url": None,
            "title": label,
            "created_at": now_utc(),
            "updated_at": now_utc(),
            "last_text_length": 0,
            "artifacts": [],
            "clicks": [],
            "form_state": {},
        }
        self._sessions[session["id"]] = session
        self._persist_sessions()
        self.audit_logger.append("browser.session_created", {"session_id": session["id"], "label": label})
        return dict(session)

    def get_session(self, session_id: str) -> dict[str, Any]:
        if session_id not in self._sessions:
            raise KeyError(session_id)
        return dict(self._sessions[session_id])

    def list_sessions(self) -> list[dict[str, Any]]:
        return [dict(session) for session in self._sessions.values()]

    def close_session(self, *, session_id: str) -> dict[str, Any]:
        session = self._require_session(session_id)
        removed = _public_session(session)
        del self._sessions[session_id]
        self._persist_sessions()
        response = {
            "ok": True,
            "status": "closed",
            "session_id": session_id,
            "title": removed.get("title"),
            "artifact_count": len(removed.get("artifacts", [])),
        }
        self.audit_logger.append("browser.session_closed", response)
        return response

    def navigate(self, *, session_id: str | None, url: str) -> dict[str, Any]:
        session = self._session_or_create(session_id)
        result = self.connectors.get("http").read(ConnectorRequest(operation="read", params={"url": url}, scopes=("read",)))
        if not result.ok:
            response = {"ok": False, "session": _public_session(session), "url": _redacted_string(url, limit=2000), "error": result.error}
            self.audit_logger.append("browser.navigate_failed", response)
            return response
        content = str(result.data.get("content", ""))
        title = _title_from_text(content, fallback=url)
        interactive_elements = _normalize_interactive_elements(_extract_interactive_elements(content))
        session.update(
            {
                "current_url": _redacted_string(url, limit=2000),
                "title": _redacted_string(title, limit=200),
                "updated_at": now_utc(),
                "last_text_length": len(content),
                "last_content": _bounded_redacted_content(content),
                "interactive_elements": interactive_elements,
                "clicks": [],
                "form_state": {},
            }
        )
        self._persist_sessions()
        response = {
            "ok": True,
            "session": _public_session(session),
            "url": _redacted_string(url, limit=2000),
            "domain": result.data.get("domain"),
            "title": _redacted_string(title, limit=200),
            "content_length": len(content),
            "interactive_elements": interactive_elements,
            "interactive_element_count": len(interactive_elements),
            "mode": "http_content_no_js",
            "taint": "WEB_CONTENT",
        }
        self.audit_logger.append("browser.navigated", {**response, "session": response["session"]})
        return response

    def extract_text(self, *, session_id: str) -> dict[str, Any]:
        session = self._require_session(session_id)
        content = str(session.get("last_content", ""))
        text = " ".join(content.split())
        state_text = _state_text(session)
        if state_text:
            text = f"{text}\n\n{state_text}" if text else state_text
        response = {
            "ok": True,
            "session_id": session_id,
            "url": _session_url(session),
            "text": str(redact(text[:5000])),
            "content_length": len(content),
            "mode": "http_content_no_js",
            "taint": "WEB_CONTENT",
        }
        self.audit_logger.append("browser.text_extracted", {"session_id": session_id, "url": _session_url(session), "content_length": len(content)})
        return response

    def extract_table(self, *, session_id: str, selector: str | None = None) -> dict[str, Any]:
        session = self._require_session(session_id)
        content = str(session.get("last_content", ""))
        table_result = _extract_html_tables(content, selector=selector)
        tables = table_result["tables"]
        rows = tables[0] if tables else []
        response = {
            "ok": True,
            "session_id": session_id,
            "url": _session_url(session),
            "selector": selector,
            "selector_status": table_result["selector_status"],
            "selector_note": table_result["selector_note"],
            "tables": tables,
            "rows": rows,
            "table_count": len(tables),
            "mode": "http_content_no_js",
            "taint": "WEB_CONTENT",
        }
        self.audit_logger.append(
            "browser.table_extracted",
            {"session_id": session_id, "url": _session_url(session), "table_count": len(tables), "selector": _redacted_string(selector, limit=500)},
        )
        return response

    def dom_snapshot(self, *, session_id: str, selector: str | None = None) -> dict[str, Any]:
        session = self._require_session(session_id)
        content = str(session.get("last_content", ""))
        snapshot = _static_dom_snapshot(content, selector=selector)
        response = {
            "ok": True,
            "session_id": session_id,
            "url": _session_url(session),
            "title": _redacted_string(session.get("title"), limit=200),
            "selector": _redacted_string(selector, limit=500) if selector is not None else None,
            "selector_status": snapshot["selector_status"],
            "selector_note": snapshot["selector_note"],
            "dom": snapshot["dom"],
            "node_count": snapshot["node_count"],
            "total_node_count": snapshot["total_node_count"],
            "truncated": snapshot["truncated"],
            "mode": "http_content_static_dom_no_js",
            "taint": "WEB_CONTENT",
            "javascript_executed": False,
            "cookies_persisted": False,
            "cookie_jar_persisted": False,
            "local_storage_persisted": False,
            "session_storage_persisted": False,
            "remote_subresources_loaded": False,
            "dom_mutated": False,
            "real_selector_events_dispatched": False,
            "automation_boundaries": _browser_automation_boundaries(rendered=False),
            "evidence": _browser_evidence(session, action="dom_snapshot"),
        }
        self.audit_logger.append(
            "browser.static_dom_snapshot",
            {
                "session_id": session_id,
                "url": _session_url(session),
                "selector": _redacted_string(selector, limit=500) if selector is not None else None,
                "selector_status": snapshot["selector_status"],
                "node_count": snapshot["node_count"],
                "total_node_count": snapshot["total_node_count"],
                "truncated": snapshot["truncated"],
            },
        )
        return response

    def inspect(self, *, session_id: str) -> dict[str, Any]:
        session = self._require_session(session_id)
        interactive_elements = _normalize_interactive_elements(session.get("interactive_elements"))
        selector_inventory = _selector_inventory(interactive_elements, live_mutation_supported=self.live_browser_mutations)
        activation = _live_browser_activation_preflight(
            live_browser_reads=self.live_browser_reads,
            live_browser_mutations=self.live_browser_mutations,
            live_browser_downloads=self.live_browser_downloads,
            live_browser_uploads=self.live_browser_uploads,
        )
        response = {
            "ok": True,
            "session_id": session_id,
            "url": _session_url(session),
            "title": _redacted_string(session.get("title"), limit=200),
            "interactive_elements": interactive_elements,
            "interactive_element_count": len(interactive_elements),
            "selector_inventory": selector_inventory,
            "unsupported_live_actions": _unsupported_live_browser_actions(
                live_mutation_supported=self.live_browser_mutations,
                live_download_supported=self.live_browser_downloads,
                live_upload_supported=self.live_browser_uploads,
            ),
            "readiness": {
                "live_browser_adapter": "upload_available_if_configured" if self.live_browser_uploads else "download_available_if_configured" if self.live_browser_downloads else "mutation_available_if_configured" if self.live_browser_mutations else "read_only_available_if_configured" if self.live_browser_reads else "blocked_pending_boundaries",
                "approval_required_for_mutation": True,
                "javascript_executed": bool(self.live_browser_mutations or self.live_browser_downloads or self.live_browser_uploads),
                "cookie_persistence": False,
                "real_selector_events_dispatched": bool(self.live_browser_mutations or self.live_browser_downloads or self.live_browser_uploads),
                "dom_mutation_supported": bool(self.live_browser_mutations),
                "static_dom_form_fill_supported": True,
                "live_selector_mutation_supported": bool(self.live_browser_mutations),
                "live_download_supported": bool(self.live_browser_downloads),
                "live_upload_supported": bool(self.live_browser_uploads),
            },
            "activation": activation,
            "live_browser_read_adapter": "available" if self.live_browser_reads else "disabled",
            "live_browser_mutation_adapter": "available" if self.live_browser_mutations else "disabled",
            "live_browser_download_adapter": "available" if self.live_browser_downloads else "disabled",
            "live_browser_upload_adapter": "available" if self.live_browser_uploads else "disabled",
            "preflight_status": activation["preflight_status"],
            "automation_boundaries": _browser_automation_boundaries(rendered=False),
            "mode": "http_content_no_js_selector_inventory",
            "taint": "WEB_CONTENT",
        }
        self.audit_logger.append(
            "browser.selector_inventory_inspected",
            {"session_id": session_id, "url": _session_url(session), "interactive_element_count": len(interactive_elements)},
        )
        return response

    def action_approval_payload(
        self,
        *,
        action: str,
        session_id: str,
        selector: str | None = None,
        fields: dict[str, Any] | None = None,
        url: str | None = None,
        file_path: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": "browser_action", "action": action, "session_id": session_id}
        if action == "click":
            session = self._require_session(session_id)
            payload["selector"] = selector or ""
            anchor_match = _matching_static_anchor_elements(session, selector or "")
            if anchor_match["status"] == "ambiguous":
                payload["click_effect"] = "blocked_static_anchor_navigation"
                payload["blocked_reason"] = "ambiguous_anchor_selector"
                return payload
            if anchor_match["status"] == "matched":
                target = _static_anchor_navigation_target(session, anchor_match["element"])
                payload["click_effect"] = "static_anchor_navigation"
                payload["href"] = _redacted_string(anchor_match["element"].get("href"), limit=500)
                if target["ok"]:
                    payload["target_url"] = _redacted_string(target["url"], limit=2000)
                else:
                    payload["blocked_reason"] = str(target["reason"])
                return payload
            payload["click_effect"] = "virtual_click_recorded"
            return payload
        if action == "fill":
            safe_fields = {str(key): str(value) for key, value in (fields or {}).items()}
            encoded = json.dumps(safe_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
            payload["field_selectors"] = sorted(safe_fields)
            payload["fields_sha256"] = hashlib.sha256(encoded).hexdigest()
            return payload
        if action == "submit":
            session = self._require_session(session_id)
            payload["selector"] = selector or ""
            form_match = _matching_static_form(session, selector)
            if form_match["status"] != "matched":
                payload["submit_effect"] = "blocked_static_form_submit"
                payload["blocked_reason"] = form_match["status"]
                return payload
            target = _static_form_submission_target(session, form_match["form"])
            if not target["ok"]:
                payload["submit_effect"] = "blocked_static_form_submit"
                payload["blocked_reason"] = str(target["reason"])
                return payload
            target_url = str(target["url"])
            payload["submit_effect"] = "static_form_submit"
            payload["method"] = target["method"]
            payload["field_names"] = target["field_names"]
            payload["field_count"] = target["field_count"]
            payload["target_origin"] = _url_origin(target_url)
            payload["target_path"] = _url_path(target_url)
            payload["target_url_sha256"] = hashlib.sha256(target_url.encode("utf-8", errors="replace")).hexdigest()
            return payload
        if action in {"live_click", "live_submit"}:
            session = self._require_session(session_id)
            current_url = _session_url(session) or ""
            target = _live_browser_url_check(current_url, allowlist=self.network_allowlist) if current_url else {"ok": False, "domain": "", "reason": "missing_url"}
            payload["selector"] = selector or ""
            payload["mutation_effect"] = "live_browser_selector_mutation"
            payload["target_origin"] = _url_origin(current_url) if current_url else ""
            payload["target_path"] = _url_path(current_url) if current_url else ""
            payload["target_domain"] = target["domain"]
            payload["target_url_sha256"] = hashlib.sha256(current_url.encode("utf-8", errors="replace")).hexdigest() if current_url else ""
            if not target["ok"]:
                payload["blocked_reason"] = str(target["reason"])
            return payload
        if action == "live_fill":
            session = self._require_session(session_id)
            current_url = _session_url(session) or ""
            target = _live_browser_url_check(current_url, allowlist=self.network_allowlist) if current_url else {"ok": False, "domain": "", "reason": "missing_url"}
            safe_fields = {str(key): str(value) for key, value in (fields or {}).items()}
            encoded = json.dumps(safe_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
            payload["mutation_effect"] = "live_browser_form_mutation"
            payload["field_selectors"] = sorted(safe_fields)
            payload["fields_sha256"] = hashlib.sha256(encoded).hexdigest()
            payload["target_origin"] = _url_origin(current_url) if current_url else ""
            payload["target_path"] = _url_path(current_url) if current_url else ""
            payload["target_domain"] = target["domain"]
            payload["target_url_sha256"] = hashlib.sha256(current_url.encode("utf-8", errors="replace")).hexdigest() if current_url else ""
            if not target["ok"]:
                payload["blocked_reason"] = str(target["reason"])
            return payload
        if action == "live_download":
            session = self._require_session(session_id)
            current_url = _session_url(session) or ""
            target = _live_browser_url_check(current_url, allowlist=self.network_allowlist) if current_url else {"ok": False, "domain": "", "reason": "missing_url"}
            payload["selector"] = selector or ""
            payload["download_effect"] = "live_browser_private_download"
            payload["target_origin"] = _url_origin(current_url) if current_url else ""
            payload["target_path"] = _url_path(current_url) if current_url else ""
            payload["target_domain"] = target["domain"]
            payload["target_url_sha256"] = hashlib.sha256(current_url.encode("utf-8", errors="replace")).hexdigest() if current_url else ""
            payload["max_download_bytes"] = _MAX_LIVE_BROWSER_DOWNLOAD_BYTES
            if not target["ok"]:
                payload["blocked_reason"] = str(target["reason"])
            return payload
        if action == "live_upload":
            session = self._require_session(session_id)
            current_url = _session_url(session) or ""
            target = _live_browser_url_check(current_url, allowlist=self.network_allowlist) if current_url else {"ok": False, "domain": "", "reason": "missing_url"}
            source = _live_upload_source_check(file_path, workspace_root=self.workspace_root)
            payload["selector"] = selector or ""
            payload["upload_effect"] = "live_browser_workspace_file_upload"
            payload["target_origin"] = _url_origin(current_url) if current_url else ""
            payload["target_path"] = _url_path(current_url) if current_url else ""
            payload["target_domain"] = target["domain"]
            payload["target_url_sha256"] = hashlib.sha256(current_url.encode("utf-8", errors="replace")).hexdigest() if current_url else ""
            payload["source_filename"] = source.get("filename", "")
            payload["source_bytes"] = source.get("bytes", 0)
            payload["source_mime_type"] = source.get("mime_type", "")
            payload["source_path_sha256"] = source.get("path_sha256", "")
            payload["source_sha256"] = source.get("sha256", "")
            payload["max_upload_bytes"] = _MAX_LIVE_BROWSER_UPLOAD_BYTES
            if not target["ok"]:
                payload["blocked_reason"] = str(target["reason"])
            if not source["ok"]:
                payload["source_blocked_reason"] = str(source["reason"])
            return payload
        if action == "live_navigate":
            if not url:
                raise ValueError("live browser navigation approval requires url")
            target = _live_browser_url_check(url, allowlist=self.network_allowlist)
            payload["navigation_effect"] = "live_browser_readonly_snapshot"
            payload["target_origin"] = _url_origin(url)
            payload["target_path"] = _url_path(url)
            payload["target_domain"] = target["domain"]
            payload["target_url_sha256"] = hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()
            if not target["ok"]:
                payload["blocked_reason"] = str(target["reason"])
            return payload
        if action == "live_screenshot":
            session = self._require_session(session_id)
            current_url = _session_url(session) or ""
            payload["capture_effect"] = "live_browser_readonly_snapshot"
            payload["target_origin"] = _url_origin(current_url) if current_url else ""
            payload["target_path"] = _url_path(current_url) if current_url else ""
            payload["target_url_sha256"] = hashlib.sha256(current_url.encode("utf-8", errors="replace")).hexdigest() if current_url else ""
            if not current_url:
                payload["blocked_reason"] = "missing_url"
            return payload
        raise ValueError(f"unsupported browser approval action: {action}")

    def deny_live_automation(self, *, action: str, session_id: str | None = None, selector: str | None = None) -> dict[str, Any]:
        session = self._require_session(session_id) if session_id else None
        activation = _live_browser_activation_preflight(
            live_browser_reads=self.live_browser_reads,
            live_browser_mutations=self.live_browser_mutations,
            live_browser_downloads=self.live_browser_downloads,
            live_browser_uploads=self.live_browser_uploads,
        )
        response = {
            "ok": False,
            "status": "blocked_pending_live_browser_adapter",
            "action": action,
            "session_id": session_id,
            "url": _session_url(session) if session is not None else None,
            "selector": _redacted_string(selector, limit=500) if selector is not None else None,
            "reason": "live browser automation is disabled until isolation, network, script, storage, approval, and receipt controls are implemented",
            "activation_status": activation["status"],
            "preflight_status": activation["preflight_status"],
            "activation": activation,
            "automation_boundaries": _browser_automation_boundaries(rendered=False),
            "unsupported_live_actions": _unsupported_live_browser_actions(
                live_mutation_supported=self.live_browser_mutations,
                live_download_supported=self.live_browser_downloads,
                live_upload_supported=self.live_browser_uploads,
            ),
            "mode": "live_browser_adapter_denied",
        }
        self.audit_logger.append("browser.live_automation_denied", response)
        return response

    def live_activation_status(self) -> dict[str, Any]:
        activation = _live_browser_activation_preflight(
            live_browser_reads=self.live_browser_reads,
            live_browser_mutations=self.live_browser_mutations,
            live_browser_downloads=self.live_browser_downloads,
            live_browser_uploads=self.live_browser_uploads,
        )
        return {
            "status": activation["status"] if self.live_browser_reads or self.live_browser_mutations or self.live_browser_downloads or self.live_browser_uploads else "live_browser_activation_ready_for_review",
            "activation": activation,
            "live_browser_adapter_enabled": bool(self.live_browser_reads or self.live_browser_mutations or self.live_browser_downloads or self.live_browser_uploads),
            "live_browser_mutation_adapter_enabled": bool(self.live_browser_mutations),
            "live_browser_download_adapter_enabled": bool(self.live_browser_downloads),
            "live_browser_upload_adapter_enabled": bool(self.live_browser_uploads),
            "raw_browser_content_included": False,
            "raw_secret_values_included": False,
            "model_invocation_performed": False,
        }

    def create_live_activation_packet(self, *, actor: str = "operator") -> dict[str, Any]:
        packet_id = str(uuid4())
        created_at = now_utc()
        packet_dir = ensure_private_dir(self.artifact_dir / "live-activation-packets")
        packet_path = ensure_private_file(packet_dir / f"{packet_id}.json")
        checksum_path = ensure_private_file(packet_dir / f"{packet_id}.sha256")
        packet = _browser_live_activation_packet(
            packet_id=packet_id,
            actor=actor,
            created_at=created_at,
            live_browser_reads=self.live_browser_reads,
            live_browser_mutations=self.live_browser_mutations,
            live_browser_downloads=self.live_browser_downloads,
            live_browser_uploads=self.live_browser_uploads,
        )
        packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        packet_path.chmod(0o600)
        artifact_sha256 = hashlib.sha256(packet_path.read_bytes()).hexdigest()
        checksum_path.write_text(f"{artifact_sha256}\n", encoding="utf-8")
        checksum_path.chmod(0o600)
        receipt = {
            "receipt_schema": "aegis.browser.live_activation_packet.v1",
            "event_type": "browser.live_activation_packet_created",
            "packet_id": packet_id,
            "actor": _redacted_string(actor, limit=80),
            "artifact": str(packet_path),
            "artifact_sha256": artifact_sha256,
            "checksum": str(checksum_path),
            "checksum_sha256": hashlib.sha256(checksum_path.read_bytes()).hexdigest(),
            "activation_status": packet["activation"]["status"],
            "preflight_status": packet["activation"]["preflight_status"],
            "candidate_adapter_count": packet["activation"]["candidate_adapter_count"],
            "playwright_chromium_preflight_status": _playwright_chromium_preflight_status(packet["activation"]),
            "live_browser_adapter_enabled": bool(self.live_browser_reads or self.live_browser_mutations or self.live_browser_downloads or self.live_browser_uploads),
            "live_browser_mutation_adapter_enabled": bool(self.live_browser_mutations),
            "live_browser_download_adapter_enabled": bool(self.live_browser_downloads),
            "live_browser_upload_adapter_enabled": bool(self.live_browser_uploads),
            "raw_browser_content_included": False,
            "raw_secret_values_included": False,
            "raw_cookie_values_included": False,
            "raw_storage_values_included": False,
            "model_invocation_performed": False,
            "created_at": created_at,
        }
        audit_entry = self.audit_logger.append("browser.live_activation_packet_created", receipt)
        return {
            "ok": True,
            "packet": packet,
            "receipt": receipt,
            "audit_event_hash": audit_entry["event_hash"],
        }

    def live_navigate(self, *, session_id: str | None, url: str, approved: bool = False) -> dict[str, Any]:
        if not approved:
            session = self._session_or_create(session_id)
            return {
                "status": "approval_required",
                "session_id": session["id"],
                "url": _redacted_string(url, limit=2000),
                "reason": "live browser navigation requires approval",
            }
        session = self._session_or_create(session_id)
        return self._capture_live_readonly(session=session, url=url, action="live_navigate")

    def live_screenshot(self, *, session_id: str, approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        if not approved:
            return {
                "status": "approval_required",
                "session_id": session_id,
                "url": _session_url(session),
                "reason": "live browser screenshot requires approval",
            }
        url = _session_url(session)
        if not url:
            response = {"ok": False, "status": "missing_url", "session_id": session_id, "reason": "browser session has no current URL"}
            self.audit_logger.append("browser.live_screenshot_blocked", response)
            return response
        return self._capture_live_readonly(session=session, url=url, action="live_screenshot")

    def live_click(self, *, session_id: str, selector: str, approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "selector": selector, "reason": "live browser click requires approval"}
        return self._capture_live_mutation(session=session, action="live_click", selector=selector)

    def live_fill(self, *, session_id: str, fields: dict[str, Any], approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        safe_fields = {str(key): str(value) for key, value in fields.items()}
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "fields": sorted(safe_fields), "reason": "live browser fill requires approval"}
        return self._capture_live_mutation(session=session, action="live_fill", fields=safe_fields)

    def live_submit(self, *, session_id: str, selector: str | None = None, approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "selector": selector, "reason": "live browser submit requires approval"}
        return self._capture_live_mutation(session=session, action="live_submit", selector=selector)

    def live_download(self, *, session_id: str, selector: str, approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "selector": selector, "reason": "live browser download requires approval"}
        return self._capture_live_download(session=session, selector=selector)

    def live_upload(self, *, session_id: str, selector: str, file_path: str, approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "selector": selector, "file_path": _path_hash(file_path), "reason": "live browser upload requires approval"}
        return self._capture_live_upload(session=session, selector=selector, file_path=file_path)

    def _capture_live_download(self, *, session: dict[str, Any], selector: str) -> dict[str, Any]:
        session_id = str(session["id"])
        activation = _live_browser_activation_preflight(
            live_browser_reads=self.live_browser_reads,
            live_browser_mutations=self.live_browser_mutations,
            live_browser_downloads=self.live_browser_downloads,
            live_browser_uploads=self.live_browser_uploads,
        )
        if not self.live_browser_downloads:
            return self.deny_live_automation(action="live_download", session_id=session_id, selector=selector)
        url = _session_url(session)
        if not url:
            response = {"ok": False, "status": "missing_url", "action": "live_download", "session_id": session_id, "reason": "browser session has no current URL"}
            self.audit_logger.append("browser.live_download_blocked", response)
            return response
        executable = _find_chrome_executable()
        if not executable:
            response = {
                "ok": False,
                "status": "live_browser_runtime_unavailable",
                "action": "live_download",
                "session_id": session_id,
                "url": url,
                "reason": "Chrome/Chromium executable was not found",
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_download_blocked", response)
            return response
        url_check = _live_browser_url_check(url, allowlist=self.network_allowlist)
        if not url_check["ok"]:
            response = {
                "ok": False,
                "status": "live_browser_navigation_blocked",
                "action": "live_download",
                "session_id": session_id,
                "url": url,
                "reason": url_check["reason"],
                "domain": url_check["domain"],
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_download_blocked", response)
            return response
        download_artifact = self.artifact_dir / f"{session_id}.live-download.bin"
        screenshot_artifact = self.artifact_dir / f"{session_id}.live-download.png"
        evidence_artifact = self.artifact_dir / f"{session_id}.live-download.evidence.json"
        result = _capture_live_chromium_download(
            executable=executable,
            url=url,
            selector=selector,
            output_path=download_artifact,
            screenshot_path=screenshot_artifact,
            artifact_dir=self.artifact_dir,
            allowlist=self.network_allowlist,
        )
        artifact_hashes: dict[str, str] = {}
        if download_artifact.exists():
            download_artifact.chmod(0o600)
            artifact_hashes["download_sha256"] = _file_sha256(download_artifact)
        if screenshot_artifact.exists():
            screenshot_artifact.chmod(0o600)
            artifact_hashes["live_download_png_sha256"] = _file_sha256(screenshot_artifact)
        sandbox_receipt = _browser_live_download_sandbox_receipt(executable=executable, exit_code=result["exit_code"], allowlist=self.network_allowlist)
        evidence = _browser_live_download_evidence(
            session,
            selector=selector,
            url=url,
            result=result,
            artifact_hashes=artifact_hashes,
            sandbox_receipt=sandbox_receipt,
        )
        evidence_artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
        evidence_artifact.chmod(0o600)
        artifact_hashes["evidence_json_sha256"] = _file_sha256(evidence_artifact)
        live_downloads = list(session.get("live_downloads", []))
        live_downloads.append(
            {
                "selector": _redacted_string(selector, limit=500),
                "downloaded_at": now_utc(),
                "ok": bool(result["ok"]),
                "filename": _redacted_string(result.get("filename"), limit=200),
                "bytes": _safe_int(result.get("bytes")),
                "download_domain": _redacted_string(result.get("download_domain"), limit=255),
                "download_url_sha256": _redacted_string(result.get("download_url_sha256"), limit=64),
            }
        )
        session_artifacts = list(session.get("artifacts", []))
        session_artifacts.extend(str(path) for path in (download_artifact, screenshot_artifact, evidence_artifact) if path.exists())
        session.update(
            {
                "current_url": _redacted_string(str(result.get("url_after") or url), limit=2000),
                "title": _redacted_string(f"Live download {url_check['domain']}", limit=200),
                "updated_at": now_utc(),
                "last_text_length": 0,
                "live_browser_last_capture_at": now_utc(),
                "live_browser_last_status": "downloaded" if result["ok"] else str(result.get("status") or "download_failed"),
                "live_downloads": live_downloads[-25:],
                "artifacts": session_artifacts[-50:],
            }
        )
        self._persist_sessions()
        response = {
            "ok": result["ok"],
            "status": "downloaded" if result["ok"] else str(result.get("status") or "download_failed"),
            "action": "live_download",
            "session_id": session_id,
            "session": _public_session(session),
            "url_before": url,
            "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
            "domain": url_check["domain"],
            "selector": _redacted_string(selector, limit=500),
            "artifact_path": str(download_artifact) if download_artifact.exists() else None,
            "artifact_type": "browser_live_download_artifact",
            "metadata_path": str(screenshot_artifact) if screenshot_artifact.exists() else None,
            "metadata_artifact_type": "png_live_browser_download_snapshot",
            "evidence_path": str(evidence_artifact),
            "evidence_artifact_type": "json_browser_live_download_evidence",
            "filename": _redacted_string(result.get("filename"), limit=200),
            "mime_type": _redacted_string(result.get("mime_type"), limit=120),
            "bytes": _safe_int(result.get("bytes")),
            "download_domain": _redacted_string(result.get("download_domain"), limit=255),
            "download_url_sha256": _redacted_string(result.get("download_url_sha256"), limit=64),
            "max_bytes": _MAX_LIVE_BROWSER_DOWNLOAD_BYTES,
            "mode": "live_chromium_cdp_ephemeral_download",
            "width": result["width"],
            "height": result["height"],
            "artifact_hashes": artifact_hashes,
            "sandbox_receipt": sandbox_receipt,
            "activation": activation,
            "preflight_status": activation["preflight_status"],
            "javascript_executed": True,
            "page_javascript_allowed": True,
            "cookies_persisted": False,
            "cookie_jar_persisted": False,
            "local_storage_persisted": False,
            "session_storage_persisted": False,
            "real_selector_events_dispatched": bool(result["ok"]),
            "real_page_mutation_allowed": True,
            "downloads_allowed": True,
            "uploads_allowed": False,
            "raw_browser_content_included": False,
            "raw_secret_values_included": False,
            "raw_cookie_values_included": False,
            "raw_storage_values_included": False,
            "raw_network_body_returned": False,
            "content_returned": False,
            "action_result": _safe_live_download_action_result(result.get("action_result")),
            "evidence": {
                "action": "live_download",
                "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
                "mode": "live_chromium_cdp_ephemeral_download",
                "content_returned": False,
                "artifact_hashes": artifact_hashes,
            },
            "error": result.get("error"),
        }
        self.audit_logger.append("browser.live_download_captured" if result["ok"] else "browser.live_download_failed", response)
        return response

    def _capture_live_upload(self, *, session: dict[str, Any], selector: str, file_path: str) -> dict[str, Any]:
        session_id = str(session["id"])
        activation = _live_browser_activation_preflight(
            live_browser_reads=self.live_browser_reads,
            live_browser_mutations=self.live_browser_mutations,
            live_browser_downloads=self.live_browser_downloads,
            live_browser_uploads=self.live_browser_uploads,
        )
        if not self.live_browser_uploads:
            return self.deny_live_automation(action="live_upload", session_id=session_id, selector=selector)
        url = _session_url(session)
        if not url:
            response = {"ok": False, "status": "missing_url", "action": "live_upload", "session_id": session_id, "reason": "browser session has no current URL"}
            self.audit_logger.append("browser.live_upload_blocked", response)
            return response
        source = _live_upload_source_check(file_path, workspace_root=self.workspace_root)
        if not source["ok"]:
            response = {
                "ok": False,
                "status": "upload_source_blocked",
                "action": "live_upload",
                "session_id": session_id,
                "selector": _redacted_string(selector, limit=500),
                "reason": source["reason"],
                "source_path_sha256": source.get("path_sha256", ""),
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_upload_blocked", response)
            return response
        executable = _find_chrome_executable()
        if not executable:
            response = {
                "ok": False,
                "status": "live_browser_runtime_unavailable",
                "action": "live_upload",
                "session_id": session_id,
                "url": url,
                "reason": "Chrome/Chromium executable was not found",
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_upload_blocked", response)
            return response
        url_check = _live_browser_url_check(url, allowlist=self.network_allowlist)
        if not url_check["ok"]:
            response = {
                "ok": False,
                "status": "live_browser_navigation_blocked",
                "action": "live_upload",
                "session_id": session_id,
                "url": url,
                "reason": url_check["reason"],
                "domain": url_check["domain"],
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_upload_blocked", response)
            return response
        screenshot_artifact = self.artifact_dir / f"{session_id}.live-upload.png"
        evidence_artifact = self.artifact_dir / f"{session_id}.live-upload.evidence.json"
        result = _capture_live_chromium_upload(
            executable=executable,
            url=url,
            selector=selector,
            source_path=source["path"],
            screenshot_path=screenshot_artifact,
            artifact_dir=self.artifact_dir,
            allowlist=self.network_allowlist,
        )
        artifact_hashes: dict[str, str] = {"source_sha256": str(source["sha256"])}
        if screenshot_artifact.exists():
            screenshot_artifact.chmod(0o600)
            artifact_hashes["live_upload_png_sha256"] = _file_sha256(screenshot_artifact)
        sandbox_receipt = _browser_live_upload_sandbox_receipt(executable=executable, exit_code=result["exit_code"], allowlist=self.network_allowlist)
        evidence = _browser_live_upload_evidence(
            session,
            selector=selector,
            url=url,
            source=source,
            result=result,
            artifact_hashes=artifact_hashes,
            sandbox_receipt=sandbox_receipt,
        )
        evidence_artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
        evidence_artifact.chmod(0o600)
        artifact_hashes["evidence_json_sha256"] = _file_sha256(evidence_artifact)
        live_uploads = list(session.get("live_uploads", []))
        live_uploads.append(
            {
                "selector": _redacted_string(selector, limit=500),
                "uploaded_at": now_utc(),
                "ok": bool(result["ok"]),
                "source_filename": source["filename"],
                "source_bytes": source["bytes"],
                "source_mime_type": source["mime_type"],
                "source_path_sha256": source["path_sha256"],
            }
        )
        session_artifacts = list(session.get("artifacts", []))
        session_artifacts.extend(str(path) for path in (screenshot_artifact, evidence_artifact) if path.exists())
        session.update(
            {
                "current_url": _redacted_string(str(result.get("url_after") or url), limit=2000),
                "title": _redacted_string(f"Live upload {url_check['domain']}", limit=200),
                "updated_at": now_utc(),
                "last_text_length": 0,
                "live_browser_last_capture_at": now_utc(),
                "live_browser_last_status": "uploaded" if result["ok"] else str(result.get("status") or "upload_failed"),
                "live_uploads": live_uploads[-25:],
                "artifacts": session_artifacts[-50:],
            }
        )
        self._persist_sessions()
        response = {
            "ok": result["ok"],
            "status": "uploaded" if result["ok"] else str(result.get("status") or "upload_failed"),
            "action": "live_upload",
            "session_id": session_id,
            "session": _public_session(session),
            "url_before": url,
            "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
            "domain": url_check["domain"],
            "selector": _redacted_string(selector, limit=500),
            "artifact_path": str(screenshot_artifact) if screenshot_artifact.exists() else None,
            "artifact_type": "png_live_browser_upload_snapshot",
            "evidence_path": str(evidence_artifact),
            "evidence_artifact_type": "json_browser_live_upload_evidence",
            "source_filename": source["filename"],
            "source_mime_type": source["mime_type"],
            "source_bytes": source["bytes"],
            "source_sha256": source["sha256"],
            "source_path_sha256": source["path_sha256"],
            "max_upload_bytes": _MAX_LIVE_BROWSER_UPLOAD_BYTES,
            "mode": "live_chromium_cdp_ephemeral_upload",
            "width": result["width"],
            "height": result["height"],
            "artifact_hashes": artifact_hashes,
            "sandbox_receipt": sandbox_receipt,
            "activation": activation,
            "preflight_status": activation["preflight_status"],
            "javascript_executed": True,
            "page_javascript_allowed": True,
            "cookies_persisted": False,
            "cookie_jar_persisted": False,
            "local_storage_persisted": False,
            "session_storage_persisted": False,
            "real_selector_events_dispatched": bool(result["ok"]),
            "real_page_mutation_allowed": True,
            "downloads_allowed": False,
            "uploads_allowed": True,
            "raw_browser_content_included": False,
            "raw_secret_values_included": False,
            "raw_cookie_values_included": False,
            "raw_storage_values_included": False,
            "raw_network_body_returned": False,
            "content_returned": False,
            "action_result": _safe_live_upload_action_result(result.get("action_result")),
            "evidence": {
                "action": "live_upload",
                "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
                "mode": "live_chromium_cdp_ephemeral_upload",
                "content_returned": False,
                "artifact_hashes": artifact_hashes,
            },
            "error": result.get("error"),
        }
        self.audit_logger.append("browser.live_upload_captured" if result["ok"] else "browser.live_upload_failed", response)
        return response

    def _capture_live_mutation(
        self,
        *,
        session: dict[str, Any],
        action: str,
        selector: str | None = None,
        fields: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        session_id = str(session["id"])
        activation = _live_browser_activation_preflight(
            live_browser_reads=self.live_browser_reads,
            live_browser_mutations=self.live_browser_mutations,
            live_browser_downloads=self.live_browser_downloads,
            live_browser_uploads=self.live_browser_uploads,
        )
        if not self.live_browser_mutations:
            return self.deny_live_automation(action=action, session_id=session_id, selector=selector)
        url = _session_url(session)
        if not url:
            response = {"ok": False, "status": "missing_url", "action": action, "session_id": session_id, "reason": "browser session has no current URL"}
            self.audit_logger.append("browser.live_mutation_blocked", response)
            return response
        executable = _find_chrome_executable()
        if not executable:
            response = {
                "ok": False,
                "status": "live_browser_runtime_unavailable",
                "action": action,
                "session_id": session_id,
                "url": url,
                "reason": "Chrome/Chromium executable was not found",
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_mutation_blocked", response)
            return response
        url_check = _live_browser_url_check(url, allowlist=self.network_allowlist)
        if not url_check["ok"]:
            response = {
                "ok": False,
                "status": "live_browser_navigation_blocked",
                "action": action,
                "session_id": session_id,
                "url": url,
                "reason": url_check["reason"],
                "domain": url_check["domain"],
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_mutation_blocked", response)
            return response
        artifact = self.artifact_dir / f"{session_id}.live-mutation.png"
        evidence_artifact = self.artifact_dir / f"{session_id}.live-mutation.evidence.json"
        result = _capture_live_chromium_mutation(
            executable=executable,
            url=url,
            action=action,
            selector=selector,
            fields=fields or {},
            output_path=artifact,
            artifact_dir=self.artifact_dir,
            allowlist=self.network_allowlist,
        )
        artifact_hashes: dict[str, str] = {}
        if artifact.exists():
            artifact.chmod(0o600)
            artifact_hashes["live_mutation_png_sha256"] = _file_sha256(artifact)
        sandbox_receipt = _browser_live_mutation_sandbox_receipt(executable=executable, exit_code=result["exit_code"], allowlist=self.network_allowlist)
        evidence = _browser_live_mutation_evidence(
            session,
            action=action,
            url=url,
            selector=selector,
            fields=fields or {},
            result=result,
            artifact_hashes=artifact_hashes,
            sandbox_receipt=sandbox_receipt,
        )
        evidence_artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
        evidence_artifact.chmod(0o600)
        artifact_hashes["evidence_json_sha256"] = _file_sha256(evidence_artifact)
        mutations = list(session.get("live_mutations", []))
        mutations.append(
            {
                "action": action,
                "selector": _redacted_string(selector, limit=500) if selector is not None else None,
                "field_selectors": sorted((fields or {}).keys()),
                "mutated_at": now_utc(),
                "ok": bool(result["ok"]),
            }
        )
        session_artifacts = list(session.get("artifacts", []))
        session_artifacts.extend(str(path) for path in (artifact, evidence_artifact) if path.exists())
        session.update(
            {
                "current_url": _redacted_string(str(result.get("url_after") or url), limit=2000),
                "title": _redacted_string(f"Live mutation {url_check['domain']}", limit=200),
                "updated_at": now_utc(),
                "last_text_length": 0,
                "live_browser_last_capture_at": now_utc(),
                "live_browser_last_status": "mutated" if result["ok"] else "mutation_failed",
                "live_mutations": mutations[-25:],
                "artifacts": session_artifacts[-50:],
            }
        )
        self._persist_sessions()
        response = {
            "ok": result["ok"],
            "status": "mutated" if result["ok"] else "mutation_failed",
            "action": action,
            "session_id": session_id,
            "session": _public_session(session),
            "url_before": url,
            "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
            "domain": url_check["domain"],
            "selector": _redacted_string(selector, limit=500) if selector is not None else None,
            "field_selectors": sorted((fields or {}).keys()),
            "artifact_path": str(artifact) if artifact.exists() else None,
            "artifact_type": "png_live_browser_mutation_snapshot",
            "mode": "live_chromium_cdp_ephemeral_mutation",
            "width": result["width"],
            "height": result["height"],
            "evidence_path": str(evidence_artifact),
            "evidence_artifact_type": "json_browser_live_mutation_evidence",
            "artifact_hashes": artifact_hashes,
            "sandbox_receipt": sandbox_receipt,
            "activation": activation,
            "preflight_status": activation["preflight_status"],
            "javascript_executed": True,
            "page_javascript_allowed": True,
            "cookies_persisted": False,
            "cookie_jar_persisted": False,
            "local_storage_persisted": False,
            "session_storage_persisted": False,
            "real_selector_events_dispatched": bool(result["ok"]),
            "real_page_mutation_allowed": True,
            "downloads_allowed": False,
            "uploads_allowed": False,
            "raw_browser_content_included": False,
            "raw_secret_values_included": False,
            "action_result": _safe_live_mutation_action_result(result.get("action_result")),
            "evidence": {
                "action": action,
                "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
                "mode": "live_chromium_cdp_ephemeral_mutation",
                "content_returned": False,
                "artifact_hashes": artifact_hashes,
            },
            "error": result.get("error"),
        }
        self.audit_logger.append("browser.live_mutation_captured" if result["ok"] else "browser.live_mutation_failed", response)
        return response

    def _capture_live_readonly(self, *, session: dict[str, Any], url: str, action: str) -> dict[str, Any]:
        session_id = str(session["id"])
        activation = _live_browser_activation_preflight(
            live_browser_reads=self.live_browser_reads,
            live_browser_mutations=self.live_browser_mutations,
            live_browser_downloads=self.live_browser_downloads,
            live_browser_uploads=self.live_browser_uploads,
        )
        if not self.live_browser_reads:
            return self.deny_live_automation(action=action, session_id=session_id)
        executable = _find_chrome_executable()
        if not executable:
            response = {
                "ok": False,
                "status": "live_browser_runtime_unavailable",
                "action": action,
                "session_id": session_id,
                "url": _redacted_string(url, limit=2000),
                "reason": "Chrome/Chromium executable was not found",
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_read_blocked", response)
            return response
        url_check = _live_browser_url_check(url, allowlist=self.network_allowlist)
        if not url_check["ok"]:
            response = {
                "ok": False,
                "status": "live_browser_navigation_blocked",
                "action": action,
                "session_id": session_id,
                "url": _redacted_string(url, limit=2000),
                "reason": url_check["reason"],
                "domain": url_check["domain"],
                "activation": activation,
                "preflight_status": activation["preflight_status"],
            }
            self.audit_logger.append("browser.live_read_blocked", response)
            return response
        artifact = self.artifact_dir / f"{session_id}.live.png"
        evidence_artifact = self.artifact_dir / f"{session_id}.live.evidence.json"
        result = _capture_live_chromium_snapshot(
            executable=executable,
            url=url,
            output_path=artifact,
            artifact_dir=self.artifact_dir,
            allowlist=self.network_allowlist,
        )
        artifact_hashes: dict[str, str] = {}
        if artifact.exists():
            artifact.chmod(0o600)
            artifact_hashes["live_png_sha256"] = _file_sha256(artifact)
        sandbox_receipt = _browser_live_read_sandbox_receipt(executable=executable, exit_code=result["exit_code"], allowlist=self.network_allowlist)
        evidence = _browser_live_read_evidence(
            session,
            action=action,
            url=url,
            result=result,
            artifact_hashes=artifact_hashes,
            sandbox_receipt=sandbox_receipt,
        )
        evidence_artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
        evidence_artifact.chmod(0o600)
        artifact_hashes["evidence_json_sha256"] = _file_sha256(evidence_artifact)
        session_artifacts = list(session.get("artifacts", []))
        session_artifacts.extend(str(path) for path in (artifact, evidence_artifact) if path.exists())
        session.update(
            {
                "current_url": _redacted_string(url, limit=2000),
                "title": _redacted_string(f"Live snapshot {url_check['domain']}", limit=200),
                "updated_at": now_utc(),
                "last_text_length": 0,
                "live_browser_last_capture_at": now_utc(),
                "live_browser_last_status": "captured" if result["ok"] else "capture_failed",
                "artifacts": session_artifacts[-50:],
            }
        )
        self._persist_sessions()
        response = {
            "ok": result["ok"],
            "status": "captured" if result["ok"] else "capture_failed",
            "action": action,
            "session_id": session_id,
            "session": _public_session(session),
            "url": _redacted_string(url, limit=2000),
            "domain": url_check["domain"],
            "artifact_path": str(artifact) if artifact.exists() else None,
            "artifact_type": "png_live_browser_readonly_snapshot",
            "mode": "live_chromium_readonly_no_persistent_state",
            "width": result["width"],
            "height": result["height"],
            "evidence_path": str(evidence_artifact),
            "evidence_artifact_type": "json_browser_live_read_evidence",
            "artifact_hashes": artifact_hashes,
            "sandbox_receipt": sandbox_receipt,
            "activation": activation,
            "preflight_status": activation["preflight_status"],
            "javascript_executed": False,
            "page_javascript_allowed": False,
            "cookies_persisted": False,
            "cookie_jar_persisted": False,
            "local_storage_persisted": False,
            "session_storage_persisted": False,
            "real_selector_events_dispatched": False,
            "real_page_mutation_allowed": False,
            "raw_browser_content_included": False,
            "raw_secret_values_included": False,
            "evidence": {
                "action": action,
                "url_after": _redacted_string(url, limit=2000),
                "mode": "live_chromium_readonly_no_persistent_state",
                "content_returned": False,
                "artifact_hashes": artifact_hashes,
            },
            "error": result.get("error"),
        }
        self.audit_logger.append("browser.live_read_captured" if result["ok"] else "browser.live_read_failed", response)
        return response

    def verify_live_activation_packet(self, packet: str, *, actor: str = "operator") -> dict[str, Any]:
        packet_path, checksum_path = _browser_live_activation_packet_paths(self.artifact_dir, packet)
        packet_bytes = packet_path.read_bytes()
        artifact_sha256 = hashlib.sha256(packet_bytes).hexdigest()
        checksum_value = checksum_path.read_text(encoding="utf-8").strip() if checksum_path.exists() else ""
        try:
            decoded = json.loads(packet_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = {}
        packet_payload = decoded if isinstance(decoded, dict) else {}
        controls = packet_payload.get("controls") if isinstance(packet_payload.get("controls"), dict) else {}
        activation = packet_payload.get("activation") if isinstance(packet_payload.get("activation"), dict) else {}
        boundaries = packet_payload.get("implemented_boundaries") if isinstance(packet_payload.get("implemented_boundaries"), dict) else {}
        checksum_matches = bool(checksum_value) and checksum_value == artifact_sha256
        packet_schema_valid = packet_payload.get("packet_schema") == "aegis.browser.live_activation_packet.v1"
        controls_valid = _browser_live_activation_controls_valid(controls)
        activation_valid = _browser_live_activation_preflight_valid(activation)
        boundaries_valid = _browser_live_activation_boundaries_valid(boundaries)
        forbidden_keys_present = _browser_activation_packet_forbidden_keys_present(packet_payload)
        receipt = {
            "receipt_schema": "aegis.browser.live_activation_packet_verification.v1",
            "event_type": "browser.live_activation_packet_verified",
            "packet_id": str(packet_payload.get("packet_id") or packet_path.stem),
            "actor": _redacted_string(actor, limit=80),
            "artifact": str(packet_path),
            "artifact_sha256": artifact_sha256,
            "checksum": str(checksum_path),
            "checksum_present": bool(checksum_value),
            "checksum_matches": checksum_matches,
            "packet_schema_valid": packet_schema_valid,
            "activation_preflight_valid": activation_valid,
            "playwright_chromium_preflight_status": _playwright_chromium_preflight_status(activation),
            "controls_valid": controls_valid,
            "boundaries_valid": boundaries_valid,
            "forbidden_raw_keys_present": forbidden_keys_present,
            "packet_integrity_ok": bool(packet_schema_valid and checksum_matches and activation_valid and controls_valid and boundaries_valid and not forbidden_keys_present),
            "live_browser_adapter_enabled": bool(controls.get("live_browser_adapter_enabled", False)),
            "live_browser_mutation_adapter_enabled": bool(controls.get("real_page_mutation_allowed", False)),
            "live_browser_download_adapter_enabled": bool(controls.get("downloads_allowed", False)),
            "raw_browser_content_included": False,
            "raw_secret_values_included": False,
            "raw_packet_payload_included": False,
            "model_invocation_performed": False,
            "verified_at": now_utc(),
        }
        audit_entry = self.audit_logger.append("browser.live_activation_packet_verified", receipt)
        return {
            "ok": bool(receipt["packet_integrity_ok"]),
            "packet": _browser_live_activation_packet_summary(packet_payload),
            "receipt": receipt,
            "audit_event_hash": audit_entry["event_hash"],
        }

    def screenshot(self, *, session_id: str) -> dict[str, Any]:
        session = self._require_session(session_id)
        evidence = _browser_evidence(session, action="screenshot")
        artifact = self.artifact_dir / f"{session_id}.png"
        sidecar = self.artifact_dir / f"{session_id}.txt"
        evidence_artifact = self.artifact_dir / f"{session_id}.evidence.json"
        width, height = _write_session_snapshot_png(artifact, session=session)
        artifact.chmod(0o600)
        sidecar.write_text(
            "\n".join(
                [
                    "Aegis governed browser PNG session snapshot",
                    f"url: {_session_url(session) or ''}",
                    f"title: {_redacted_string(session.get('title'), limit=200)}",
                    f"captured_at: {now_utc()}",
                    f"clicks: {', '.join(str(item.get('selector', '')) for item in _normalize_clicks(session.get('clicks')))}",
                    f"form_state: {_redacted_form_state(session)}",
                ]
            ),
            encoding="utf-8",
        )
        sidecar.chmod(0o600)
        artifact_hashes = {
            "snapshot_png_sha256": _file_sha256(artifact),
            "metadata_txt_sha256": _file_sha256(sidecar),
        }
        sandbox_receipt = _browser_sandbox_receipt()
        evidence_artifact.write_text(
            json.dumps(_browser_snapshot_evidence_document(session, evidence=evidence, artifact_hashes=artifact_hashes, sandbox_receipt=sandbox_receipt), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        evidence_artifact.chmod(0o600)
        artifact_hashes["evidence_json_sha256"] = _file_sha256(evidence_artifact)
        session_artifacts = list(session.get("artifacts", []))
        session_artifacts.append(str(artifact))
        session_artifacts.append(str(sidecar))
        session_artifacts.append(str(evidence_artifact))
        session["artifacts"] = session_artifacts
        session["updated_at"] = now_utc()
        self._persist_sessions()
        response = {
            "ok": True,
            "session_id": session_id,
            "artifact_path": str(artifact),
            "artifact_type": "png_session_snapshot",
            "mode": "local_png_session_snapshot_no_dom_render",
            "width": width,
            "height": height,
            "metadata_path": str(sidecar),
            "evidence_path": str(evidence_artifact),
            "evidence_artifact_type": "json_browser_snapshot_evidence",
            "artifact_hashes": artifact_hashes,
            "sandbox_receipt": sandbox_receipt,
            "url": _session_url(session),
            "evidence": evidence,
        }
        self.audit_logger.append("browser.screenshot_captured", response)
        return response

    def render_screenshot(self, *, session_id: str) -> dict[str, Any]:
        session = self._require_session(session_id)
        executable = _find_chrome_executable()
        if not executable:
            response = {
                "ok": False,
                "status": "renderer_unavailable",
                "session_id": session_id,
                "reason": "Chrome/Chromium executable was not found",
                "mode": "sanitized_dom_render_unavailable",
            }
            self.audit_logger.append("browser.render_screenshot_unavailable", response)
            return response
        artifact = self.artifact_dir / f"{session_id}.rendered.png"
        html_artifact = self.artifact_dir / f"{session_id}.rendered.html"
        evidence_artifact = self.artifact_dir / f"{session_id}.rendered.evidence.json"
        html_artifact.write_text(_renderable_sanitized_html(session), encoding="utf-8")
        html_artifact.chmod(0o600)
        result = _capture_chrome_screenshot(
            executable=executable,
            html_path=html_artifact,
            output_path=artifact,
            artifact_dir=self.artifact_dir,
        )
        artifact_hashes = {"render_html_sha256": _file_sha256(html_artifact)}
        if artifact.exists():
            artifact.chmod(0o600)
            artifact_hashes["rendered_png_sha256"] = _file_sha256(artifact)
        evidence = _browser_evidence(session, action="render_screenshot")
        sandbox_receipt = _browser_render_sandbox_receipt(executable=executable, exit_code=result["exit_code"])
        evidence_artifact.write_text(
            json.dumps(
                _browser_render_evidence_document(session, evidence=evidence, artifact_hashes=artifact_hashes, sandbox_receipt=sandbox_receipt, render_result=result),
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        evidence_artifact.chmod(0o600)
        artifact_hashes["evidence_json_sha256"] = _file_sha256(evidence_artifact)
        session_artifacts = list(session.get("artifacts", []))
        session_artifacts.extend(str(path) for path in (artifact, html_artifact, evidence_artifact) if path.exists())
        session["artifacts"] = session_artifacts
        session["updated_at"] = now_utc()
        self._persist_sessions()
        response = {
            "ok": result["ok"],
            "status": "rendered" if result["ok"] else "render_failed",
            "session_id": session_id,
            "artifact_path": str(artifact) if artifact.exists() else None,
            "artifact_type": "png_sanitized_dom_render",
            "mode": "sanitized_dom_render_no_page_js",
            "width": result["width"],
            "height": result["height"],
            "metadata_path": str(html_artifact),
            "evidence_path": str(evidence_artifact),
            "evidence_artifact_type": "json_browser_render_evidence",
            "artifact_hashes": artifact_hashes,
            "sandbox_receipt": sandbox_receipt,
            "url": _session_url(session),
            "evidence": evidence,
            "error": result.get("error"),
        }
        self.audit_logger.append("browser.render_screenshot_captured", response)
        return response

    def click(self, *, session_id: str, selector: str, approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "selector": selector, "reason": "browser click requires approval"}
        url_before = _session_url(session)
        content_hash_before = _content_hash(session)
        anchor_match = _matching_static_anchor_elements(session, selector)
        if anchor_match["status"] == "ambiguous":
            response = _static_anchor_navigation_blocked(
                session,
                session_id=session_id,
                selector=selector,
                reason="ambiguous_anchor_selector",
                detail="selector matched multiple static anchors",
            )
            self.audit_logger.append("browser.static_anchor_navigation_blocked", response)
            return response
        if anchor_match["status"] == "matched":
            target = _static_anchor_navigation_target(session, anchor_match["element"])
            if not target["ok"]:
                response = _static_anchor_navigation_blocked(
                    session,
                    session_id=session_id,
                    selector=selector,
                    reason=str(target["reason"]),
                    detail=str(target["detail"]),
                    href=str(anchor_match["element"].get("href") or ""),
                )
                self.audit_logger.append("browser.static_anchor_navigation_blocked", response)
                return response
            navigation = self.navigate(session_id=session_id, url=str(target["url"]))
            if not navigation.get("ok"):
                response = {
                    **navigation,
                    "status": "static_anchor_navigation_failed",
                    "effect": "static_anchor_navigation_failed",
                    "selector": _redacted_string(selector, limit=500),
                    "href": _redacted_string(anchor_match["element"].get("href"), limit=500),
                    "target_url": _redacted_string(target["url"], limit=2000),
                    "mode": "approved_static_anchor_navigation_no_js",
                    "javascript_executed": False,
                    "dom_mutated": False,
                    "real_selector_events_dispatched": False,
                }
                self.audit_logger.append("browser.static_anchor_navigation_failed", response)
                return response
            current = self._require_session(session_id)
            evidence = _browser_evidence(current, action="static_anchor_navigation", url_before=url_before, content_hash_before=content_hash_before)
            response = {
                **navigation,
                "effect": "static_anchor_navigation",
                "selector": _redacted_string(selector, limit=500),
                "href": _redacted_string(anchor_match["element"].get("href"), limit=500),
                "target_url": _redacted_string(target["url"], limit=2000),
                "mode": "approved_static_anchor_navigation_no_js",
                "javascript_executed": False,
                "dom_mutated": False,
                "real_selector_events_dispatched": False,
                "evidence": evidence,
            }
            self.audit_logger.append("browser.static_anchor_navigated", response)
            return response
        click = {"selector": _redacted_string(selector, limit=500), "clicked_at": now_utc()}
        clicks = list(session.get("clicks", []))
        clicks.append(click)
        session["clicks"] = clicks[-25:]
        session["updated_at"] = now_utc()
        self._persist_sessions()
        evidence = _browser_evidence(session, action="click", url_before=url_before, content_hash_before=content_hash_before)
        response = {
            "ok": True,
            "session_id": session_id,
            "selector": _redacted_string(selector, limit=500),
            "url": _session_url(session),
            "effect": "virtual_click_recorded",
            "mode": "virtual_state_no_dom",
            "dom_mutated": False,
            "click_count": len(session["clicks"]),
            "evidence": evidence,
        }
        self.audit_logger.append("browser.click_recorded", response)
        return response

    def fill(self, *, session_id: str, fields: dict[str, Any], approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "fields": sorted(fields), "reason": "browser form fill requires approval"}
        url_before = _session_url(session)
        content_hash_before = _content_hash(session)
        form_state = dict(session.get("form_state", {}))
        for selector, value in fields.items():
            form_state[_redacted_string(selector, limit=500)] = _redacted_string(value, limit=500)
        session["form_state"] = form_state
        fill_result = _apply_static_form_fill(str(session.get("last_content", "")), form_state)
        static_dom_mutated = bool(fill_result["mutated_selectors"])
        if static_dom_mutated:
            mutated_content = _bounded_redacted_content(str(fill_result["content"]))
            session["last_content"] = mutated_content
            session["last_content_redacted"] = True
            session["last_text_length"] = len(mutated_content)
            session["interactive_elements"] = _normalize_interactive_elements(_extract_interactive_elements(mutated_content))
        session["updated_at"] = now_utc()
        self._persist_sessions()
        evidence = _browser_evidence(session, action="fill", url_before=url_before, content_hash_before=content_hash_before)
        if static_dom_mutated:
            evidence["dom_mutated"] = True
            evidence["mode"] = "static_dom_form_fill_no_js"
            evidence["real_page_mutated"] = False
            evidence["static_dom_mutated"] = True
        response = {
            "ok": True,
            "session_id": session_id,
            "fields": sorted(form_state),
            "url": _session_url(session),
            "effect": "static_dom_form_state_updated" if static_dom_mutated else "virtual_form_state_updated",
            "mode": "static_dom_form_fill_no_js" if static_dom_mutated else "virtual_state_no_dom",
            "dom_mutated": static_dom_mutated,
            "static_dom_mutated": static_dom_mutated,
            "real_page_mutated": False,
            "mutated_selectors": fill_result["mutated_selectors"],
            "unmatched_selectors": fill_result["unmatched_selectors"],
            "form_state": dict(form_state),
            "evidence": evidence,
        }
        self.audit_logger.append("browser.fill_recorded", response)
        return response

    def submit(self, *, session_id: str, selector: str | None = None, approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        requested_selector = _redacted_string(selector, limit=500) if selector is not None else None
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "selector": requested_selector, "reason": "browser form submit requires approval"}
        url_before = _session_url(session)
        content_hash_before = _content_hash(session)
        form_match = _matching_static_form(session, selector)
        if form_match["status"] != "matched":
            response = _static_form_submit_blocked(session, session_id=session_id, selector=selector, reason=form_match["status"], detail=str(form_match["detail"]))
            self.audit_logger.append("browser.static_form_submit_blocked", response)
            return response
        target = _static_form_submission_target(session, form_match["form"])
        if not target["ok"]:
            response = _static_form_submit_blocked(session, session_id=session_id, selector=selector, reason=str(target["reason"]), detail=str(target["detail"]))
            self.audit_logger.append("browser.static_form_submit_blocked", response)
            return response
        navigation = self.navigate(session_id=session_id, url=str(target["url"]))
        if not navigation.get("ok"):
            response = {
                **navigation,
                "status": "static_form_submit_failed",
                "effect": "static_form_submit_failed",
                "selector": requested_selector,
                "method": target["method"],
                "target_origin": _url_origin(str(target["url"])),
                "target_path": _url_path(str(target["url"])),
                "field_names": target["field_names"],
                "field_count": target["field_count"],
                "mode": "approved_static_form_submit_no_js",
                "javascript_executed": False,
                "dom_mutated": False,
                "real_selector_events_dispatched": False,
                "cookies_persisted": False,
            }
            self.audit_logger.append("browser.static_form_submit_failed", response)
            return response
        current = self._require_session(session_id)
        evidence = _browser_evidence(current, action="static_form_submit", url_before=url_before, content_hash_before=content_hash_before)
        response = {
            **navigation,
            "effect": "static_form_submit",
            "selector": requested_selector,
            "method": target["method"],
            "target_origin": _url_origin(str(target["url"])),
            "target_path": _url_path(str(target["url"])),
            "field_names": target["field_names"],
            "field_count": target["field_count"],
            "mode": "approved_static_form_submit_no_js",
            "javascript_executed": False,
            "dom_mutated": False,
            "real_selector_events_dispatched": False,
            "cookies_persisted": False,
            "evidence": evidence,
        }
        self.audit_logger.append("browser.static_form_submitted", response)
        return response

    def _session_or_create(self, session_id: str | None) -> dict[str, Any]:
        if session_id is None:
            return self._sessions[self.create_session()["id"]]
        return self._require_session(session_id)

    def _require_session(self, session_id: str) -> dict[str, Any]:
        if session_id not in self._sessions:
            raise KeyError(session_id)
        return self._sessions[session_id]

    def _load_sessions(self) -> None:
        if not self.session_store_path.exists():
            return
        try:
            payload = json.loads(self.session_store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.audit_logger.append("browser.sessions_load_failed", {"path": str(self.session_store_path)})
            return
        if not isinstance(payload, dict):
            return
        sessions = payload.get("sessions", [])
        if not isinstance(sessions, list):
            return
        for item in sessions:
            session = _normalize_persisted_session(item)
            if session is not None:
                self._sessions[session["id"]] = session

    def _persist_sessions(self) -> None:
        ensure_private_file(self.session_store_path)
        payload = {
            "version": 1,
            "updated_at": now_utc(),
            "sessions": [_persistable_session(session) for session in self._sessions.values()],
        }
        self.session_store_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        ensure_private_file(self.session_store_path)


def _public_session(session: dict[str, Any]) -> dict[str, Any]:
    visible = {key: value for key, value in session.items() if key != "last_content"}
    return redact(visible)


def _persistable_session(session: dict[str, Any]) -> dict[str, Any]:
    persisted = dict(session)
    if "last_content" in persisted:
        persisted["last_content"] = _bounded_redacted_content(str(persisted["last_content"]))
        persisted["last_content_redacted"] = True
    return redact(persisted)


def _normalize_persisted_session(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    session_id = item.get("id")
    if not isinstance(session_id, str) or not session_id:
        return None
    now = now_utc()
    session = {
        "id": session_id,
        "label": _redacted_string(item.get("label") or "Browser session", limit=200),
        "status": str(item.get("status") or "active")[:50],
        "current_url": _redacted_string(item["current_url"], limit=2000) if item.get("current_url") is not None else None,
        "title": _redacted_string(item.get("title") or item.get("label") or "Browser session", limit=200),
        "created_at": str(item.get("created_at") or now),
        "updated_at": str(item.get("updated_at") or now),
        "last_text_length": _safe_int(item.get("last_text_length")),
        "artifacts": _string_list(item.get("artifacts"), limit=50, item_limit=2000),
        "clicks": _normalize_clicks(item.get("clicks")),
        "form_state": _normalize_form_state(item.get("form_state")),
        "interactive_elements": _normalize_interactive_elements(item.get("interactive_elements")),
        "live_mutations": _normalize_live_mutations(item.get("live_mutations")),
        "live_downloads": _normalize_live_downloads(item.get("live_downloads")),
        "live_uploads": _normalize_live_uploads(item.get("live_uploads")),
    }
    if item.get("last_content") is not None:
        session["last_content"] = _bounded_redacted_content(str(item.get("last_content")))
        session["last_content_redacted"] = True
    return session


def _bounded_redacted_content(content: str) -> str:
    return _redacted_dom_value(content, limit=_MAX_PERSISTED_CONTENT_CHARS)


def _redacted_string(value: Any, *, limit: int) -> str:
    return str(redact(str(value or "")))[:limit]


def _session_url(session: dict[str, Any]) -> str | None:
    if session.get("current_url") is None:
        return None
    return _redacted_string(session.get("current_url"), limit=2000)


def _string_list(value: Any, *, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:item_limit] for item in value[:limit]]


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _normalize_clicks(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    clicks: list[dict[str, str]] = []
    for item in value[-25:]:
        if isinstance(item, dict):
            clicks.append({"selector": _redacted_string(item.get("selector"), limit=500), "clicked_at": str(item.get("clicked_at") or now_utc())})
    return clicks


def _normalize_form_state(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {_redacted_string(key, limit=500): _redacted_string(val, limit=500) for key, val in value.items()}


def _normalize_live_mutations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    mutations: list[dict[str, Any]] = []
    for item in value[-25:]:
        if not isinstance(item, dict):
            continue
        mutations.append(
            {
                "action": _redacted_string(item.get("action"), limit=80),
                "selector": _redacted_string(item.get("selector"), limit=500) if item.get("selector") is not None else None,
                "field_selectors": _string_list(item.get("field_selectors"), limit=25, item_limit=500),
                "mutated_at": str(item.get("mutated_at") or now_utc()),
                "ok": bool(item.get("ok", False)),
            }
        )
    return mutations


def _normalize_live_downloads(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    downloads: list[dict[str, Any]] = []
    for item in value[-25:]:
        if not isinstance(item, dict):
            continue
        downloads.append(
            {
                "selector": _redacted_string(item.get("selector"), limit=500),
                "downloaded_at": str(item.get("downloaded_at") or now_utc()),
                "ok": bool(item.get("ok", False)),
                "filename": _redacted_string(item.get("filename"), limit=200),
                "bytes": _safe_int(item.get("bytes")),
            }
        )
    return downloads


def _normalize_live_uploads(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    uploads: list[dict[str, Any]] = []
    for item in value[-25:]:
        if not isinstance(item, dict):
            continue
        uploads.append(
            {
                "selector": _redacted_string(item.get("selector"), limit=500),
                "uploaded_at": str(item.get("uploaded_at") or now_utc()),
                "ok": bool(item.get("ok", False)),
                "source_filename": _redacted_string(item.get("source_filename"), limit=200),
                "source_bytes": _safe_int(item.get("source_bytes")),
                "source_mime_type": _redacted_string(item.get("source_mime_type"), limit=120),
                "source_path_sha256": _redacted_string(item.get("source_path_sha256"), limit=64),
            }
        )
    return uploads


def _normalize_interactive_elements(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    elements: list[dict[str, str]] = []
    allowed_keys = ("tag", "label", "id", "name", "type", "selector_hint", "href", "form_hint")
    for item in value[:50]:
        if not isinstance(item, dict):
            continue
        element: dict[str, str] = {}
        for key in allowed_keys:
            if key in item:
                element[key] = str(redact(str(item.get(key) or "")))[:500]
        if element:
            elements.append(element)
    return elements


def _selector_inventory(elements: list[dict[str, str]], *, live_mutation_supported: bool = False) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for element in elements[:50]:
        tag = _redacted_string(element.get("tag"), limit=80)
        selector = _redacted_string(element.get("selector_hint") or element.get("form_hint") or tag, limit=500)
        action = _selector_action(tag, element.get("type", ""))
        supported_actions = ["fill"] if action == "fill" else ["navigate"] if action == "navigate" else ["click"]
        inventory.append(
            {
                "selector": selector,
                "tag": tag,
                "label": _redacted_string(element.get("label"), limit=120),
                "action": action,
                "supported_virtual_actions": supported_actions,
                "supported_live_actions": supported_actions if live_mutation_supported else [],
                "requires_approval": True,
                "dom_mutation_supported": bool(live_mutation_supported),
                "static_dom_fill_supported": action == "fill",
            }
        )
    return inventory


def _static_dom_snapshot(content: str, *, selector: str | None = None) -> dict[str, Any]:
    parser = _StaticDomSnapshotParser(max_nodes=_MAX_STATIC_DOM_NODES, max_depth=_MAX_STATIC_DOM_DEPTH)
    try:
        parser.feed(content[:_MAX_PERSISTED_CONTENT_CHARS])
        parser.close()
    except Exception:
        return {
            "dom": [],
            "node_count": 0,
            "total_node_count": parser.total_node_count,
            "truncated": True,
            "selector_status": "parse_error",
            "selector_note": "Static DOM parsing failed; no page JavaScript, cookies, or storage were used.",
        }
    matcher = _dom_selector_matcher(selector) if selector else None
    if selector and matcher is None:
        return {
            "dom": [],
            "node_count": 0,
            "total_node_count": parser.total_node_count,
            "truncated": parser.truncated,
            "selector_status": "unsupported",
            "selector_note": "Only tag, #id, .class, tag#id, tag.class, [name=value], and tag[name=value] selectors are supported by the dependency-light static DOM parser.",
        }
    if matcher is None:
        nodes = parser.roots
        selector_status = "not_provided"
        selector_note = "The bounded static DOM tree was parsed from stored HTTP content without JavaScript, cookies, or storage."
    else:
        nodes = [node for node in parser.elements if matcher(node)]
        selector_status = "matched" if nodes else "no_match"
        selector_note = "Selector filtering used the dependency-light static DOM parser; no live DOM events were dispatched."
    return {
        "dom": nodes,
        "node_count": _count_static_dom_nodes(nodes),
        "total_node_count": parser.total_node_count,
        "truncated": parser.truncated,
        "selector_status": selector_status,
        "selector_note": selector_note,
    }


def _apply_static_form_fill(content: str, form_state: dict[str, str]) -> dict[str, Any]:
    if "<" not in content or not form_state:
        return {"content": content, "mutated_selectors": [], "unmatched_selectors": sorted(form_state)}
    safe_fields = {_redacted_string(selector, limit=500): _redacted_dom_value(value, limit=500) for selector, value in form_state.items()}
    parser = _StaticFormFillParser(fields=safe_fields)
    try:
        parser.feed(content[:_MAX_PERSISTED_CONTENT_CHARS])
        parser.close()
    except Exception:
        return {"content": content, "mutated_selectors": [], "unmatched_selectors": sorted(safe_fields)}
    mutated_selectors = sorted(parser.mutated_selectors)
    unmatched_selectors = sorted(selector for selector in safe_fields if selector not in parser.mutated_selectors)
    return {"content": "".join(parser.output), "mutated_selectors": mutated_selectors, "unmatched_selectors": unmatched_selectors}


class _StaticFormFillParser(HTMLParser):
    def __init__(self, *, fields: dict[str, str]) -> None:
        super().__init__(convert_charrefs=False)
        self.fields = fields
        self.output: list[str] = []
        self.mutated_selectors: set[str] = set()
        self._textarea_fill_selector: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized_tag = tag.lower()
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        matched_selector = self._matching_selector(normalized_tag, attrs_dict)
        if normalized_tag == "input" and matched_selector:
            attrs = _replace_attr(attrs, "value", self.fields[matched_selector])
            self.mutated_selectors.add(matched_selector)
        self.output.append(_format_start_tag(normalized_tag, attrs))
        if normalized_tag == "textarea" and matched_selector:
            self.output.append(html.escape(self.fields[matched_selector], quote=False))
            self._textarea_fill_selector = matched_selector
            self.mutated_selectors.add(matched_selector)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized_tag = tag.lower()
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        matched_selector = self._matching_selector(normalized_tag, attrs_dict)
        if normalized_tag == "input" and matched_selector:
            attrs = _replace_attr(attrs, "value", self.fields[matched_selector])
            self.mutated_selectors.add(matched_selector)
        self.output.append(_format_start_tag(normalized_tag, attrs, self_closing=True))

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.lower()
        if normalized_tag == "textarea" and self._textarea_fill_selector:
            self._textarea_fill_selector = None
        self.output.append(f"</{normalized_tag}>")

    def handle_data(self, data: str) -> None:
        if self._textarea_fill_selector:
            return
        self.output.append(html.escape(_redacted_dom_value(data, limit=len(data)), quote=False))

    def handle_entityref(self, name: str) -> None:
        if not self._textarea_fill_selector:
            self.output.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if not self._textarea_fill_selector:
            self.output.append(f"&#{name};")

    def handle_comment(self, data: str) -> None:
        self.output.append(f"<!--{html.escape(_redacted_dom_value(data, limit=len(data)), quote=False)}-->")

    def _matching_selector(self, tag: str, attrs: dict[str, str]) -> str | None:
        if tag not in {"input", "textarea"}:
            return None
        node = {"type": "element", "tag": tag, "attrs": _redacted_dom_attrs(attrs)}
        for selector in self.fields:
            matcher = _dom_selector_matcher(selector)
            if matcher is not None and matcher(node):
                return selector
        return None


def _replace_attr(attrs: list[tuple[str, str | None]], name: str, value: str) -> list[tuple[str, str | None]]:
    replaced = False
    output: list[tuple[str, str | None]] = []
    for key, existing_value in attrs:
        if key.lower() == name:
            output.append((key, value))
            replaced = True
        else:
            output.append((key, existing_value))
    if not replaced:
        output.append((name, value))
    return output


def _format_start_tag(tag: str, attrs: list[tuple[str, str | None]], *, self_closing: bool = False) -> str:
    attr_text = "".join(_format_html_attr(key, value) for key, value in attrs)
    suffix = " /" if self_closing else ""
    return f"<{tag}{attr_text}{suffix}>"


def _format_html_attr(key: str, value: str | None) -> str:
    normalized_key = "".join(char for char in str(key).lower() if char.isalnum() or char in {"-", "_", ":"})
    if not normalized_key:
        return ""
    if value is None:
        return f" {normalized_key}"
    return f' {normalized_key}="{html.escape(_redacted_dom_value(value, limit=1000), quote=True)}"'


def _count_static_dom_nodes(nodes: list[dict[str, Any]]) -> int:
    count = 0
    stack = list(nodes)
    while stack:
        node = stack.pop()
        count += 1
        children = node.get("children")
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, dict))
    return count


class _StaticDomSnapshotParser(HTMLParser):
    def __init__(self, *, max_nodes: int, max_depth: int) -> None:
        super().__init__(convert_charrefs=True)
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.roots: list[dict[str, Any]] = []
        self.elements: list[dict[str, Any]] = []
        self.stack: list[dict[str, Any]] = []
        self.total_node_count = 0
        self.emitted_node_count = 0
        self.truncated = False
        self._suppressed_text_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if self._suppressed_text_depth:
            if tag in {"script", "style", "noscript"}:
                self._suppressed_text_depth += 1
            return
        if tag in {"script", "style", "noscript"}:
            self._suppressed_text_depth = 1
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        self.total_node_count += 1
        if self.emitted_node_count >= self.max_nodes or len(self.stack) >= self.max_depth:
            self.truncated = True
            return
        node = {
            "type": "element",
            "tag": _redacted_string(tag, limit=80),
            "attrs": _redacted_dom_attrs(attrs_dict),
            "selector_hint": _redacted_string(_selector_hint(tag, attrs_dict), limit=500),
            "path": _redacted_string(self._path_for(tag), limit=500),
            "children": [],
        }
        self.emitted_node_count += 1
        self.elements.append(node)
        if self.stack:
            self.stack[-1]["children"].append(node)
        else:
            self.roots.append(node)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "script", "source", "style", "track", "wbr", "noscript"}:
            self.stack.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if self.stack and self.stack[-1].get("tag") == tag.lower():
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._suppressed_text_depth:
            if tag in {"script", "style", "noscript"}:
                self._suppressed_text_depth = max(0, self._suppressed_text_depth - 1)
            return
        while self.stack:
            node = self.stack.pop()
            if node.get("tag") == tag:
                break

    def handle_data(self, data: str) -> None:
        if self._suppressed_text_depth or not self.stack:
            return
        text = " ".join(data.split())
        if not text:
            return
        self.total_node_count += 1
        if self.emitted_node_count >= self.max_nodes:
            self.truncated = True
            return
        node = {
            "type": "text",
            "text": _redacted_dom_value(text, limit=_MAX_STATIC_DOM_TEXT_CHARS),
            "path": _redacted_string(f"{self.stack[-1].get('path', '')}/text()", limit=500),
        }
        self.emitted_node_count += 1
        self.stack[-1]["children"].append(node)

    def _path_for(self, tag: str) -> str:
        sibling_index = 1
        siblings = self.roots if not self.stack else self.stack[-1]["children"]
        for sibling in siblings:
            if sibling.get("type") == "element" and sibling.get("tag") == tag:
                sibling_index += 1
        prefix = "" if not self.stack else f"{self.stack[-1].get('path', '')}/"
        return f"{prefix}{tag}[{sibling_index}]"


def _redacted_dom_attrs(attrs: dict[str, str]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in attrs.items():
        normalized = key.lower()
        if normalized in _STATIC_DOM_ATTR_ALLOWLIST or normalized.startswith("aria-"):
            if normalized in {"href", "action", "placeholder", "title", "value"} or normalized.startswith("aria-"):
                safe[normalized] = _redacted_dom_value(value, limit=300)
            else:
                safe[normalized] = _redacted_string(value, limit=300)
    return safe


def _redacted_dom_value(value: Any, *, limit: int) -> str:
    redacted_value = _redacted_string(value, limit=limit)
    return _DOM_SECRETISH_TOKEN_RE.sub("[REDACTED_VALUE]", redacted_value)


def _dom_selector_matcher(selector: str | None):
    raw = str(selector or "").strip()
    if not raw:
        return None
    tag = ""
    expected_id = ""
    expected_class = ""
    expected_name = ""
    if raw.startswith("#") and _simple_selector_value(raw[1:]):
        expected_id = raw[1:]
    elif raw.startswith(".") and _simple_selector_value(raw[1:]):
        expected_class = raw[1:]
    elif raw.startswith("[name=") and raw.endswith("]"):
        expected_name = _unquote_selector_value(raw[6:-1])
        if not _simple_selector_value(expected_name):
            return None
    elif "[name=" in raw and raw.endswith("]"):
        tag_part, name_part = raw.split("[name=", 1)
        tag = tag_part.lower()
        expected_name = _unquote_selector_value(name_part[:-1])
        if not _simple_selector_value(tag) or not _simple_selector_value(expected_name):
            return None
    elif "#" in raw:
        tag_part, id_part = raw.split("#", 1)
        tag = tag_part.lower()
        expected_id = id_part
        if not _simple_selector_value(tag) or not _simple_selector_value(expected_id):
            return None
    elif "." in raw:
        tag_part, class_part = raw.split(".", 1)
        tag = tag_part.lower()
        expected_class = class_part
        if not _simple_selector_value(tag) or not _simple_selector_value(expected_class):
            return None
    elif _simple_selector_value(raw):
        tag = raw.lower()
    else:
        return None

    def matcher(node: dict[str, Any]) -> bool:
        if node.get("type") != "element":
            return False
        attrs = node.get("attrs") if isinstance(node.get("attrs"), dict) else {}
        if tag and node.get("tag") != tag:
            return False
        if expected_id and attrs.get("id") != expected_id:
            return False
        if expected_class and expected_class not in str(attrs.get("class", "")).split():
            return False
        if expected_name and attrs.get("name") != expected_name:
            return False
        return True

    return matcher


def _unquote_selector_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _selector_action(tag: str, input_type: str) -> str:
    if tag in {"textarea", "select"}:
        return "fill"
    if tag == "input":
        normalized_type = str(input_type or "").lower()
        if normalized_type in {"button", "submit", "reset", "checkbox", "radio"}:
            return "click"
        return "fill"
    if tag == "a":
        return "navigate"
    return "click"


def _unsupported_live_browser_actions(*, live_mutation_supported: bool = False, live_download_supported: bool = False, live_upload_supported: bool = False) -> list[str]:
    if live_mutation_supported or live_download_supported or live_upload_supported:
        unsupported = [
            "arbitrary_javascript_evaluate",
            "cookie_persistence",
            "raw_dom_capture",
            "persistent_browser_profile",
        ]
        if not live_upload_supported:
            unsupported.insert(3, "uploads")
        if (live_download_supported or live_upload_supported) and not live_mutation_supported:
            unsupported.insert(0, "live_selector_click_fill_submit")
        if not live_download_supported:
            unsupported.insert(3, "downloads")
        return unsupported
    return [
        "javascript_execution",
        "cookie_persistence",
        "network_subresource_loading",
        "dom_event_dispatch",
        "real_page_mutation",
        "live_form_submit",
    ]


def _live_browser_activation_preflight(*, live_browser_reads: bool = False, live_browser_mutations: bool = False, live_browser_downloads: bool = False, live_browser_uploads: bool = False) -> dict[str, Any]:
    live_browser_reads = live_browser_reads or live_browser_mutations or live_browser_downloads or live_browser_uploads
    adapter_candidates = _live_browser_adapter_candidates(
        live_browser_reads=live_browser_reads,
        live_browser_mutations=live_browser_mutations,
        live_browser_downloads=live_browser_downloads,
        live_browser_uploads=live_browser_uploads,
    )
    blockers = [
        {"control": "live_browser_adapter", "detail": "no Playwright/Chromium real browser automation mutation adapter is enabled"},
        {"control": "approval_gated_mutation", "detail": "real clicks, form fills, downloads, uploads, and page mutations must require matching approval"},
        {"control": "redacted_artifact_receipts", "detail": "screenshots, DOM captures, console logs, and network traces must be hash-receipted and secret-redacted"},
    ]
    if live_browser_uploads and live_browser_downloads:
        blockers = [
            {"control": "arbitrary_js", "detail": "arbitrary JavaScript evaluation, persistent browser state, and raw browser capture remain disabled"},
            {"control": "raw_dom_capture", "detail": "raw live DOM, cookies, storage values, console logs, and network bodies are still excluded from receipts"},
        ]
    elif live_browser_uploads:
        blockers = [
            {"control": "downloads_and_arbitrary_js", "detail": "downloads, arbitrary JavaScript evaluation, persistent browser state, and raw browser capture remain disabled"},
            {"control": "raw_dom_capture", "detail": "raw live DOM, cookies, storage values, console logs, and network bodies are still excluded from receipts"},
        ]
    elif live_browser_downloads:
        blockers = [
            {"control": "uploads_and_arbitrary_js", "detail": "uploads, arbitrary JavaScript evaluation, file chooser access, and persistent browser state remain disabled"},
            {"control": "raw_dom_capture", "detail": "raw live DOM, cookies, storage values, console logs, and network bodies are still excluded from receipts"},
        ]
    elif live_browser_mutations:
        blockers = [
            {"control": "downloads_and_uploads", "detail": "downloads, uploads, file chooser access, and persistent browser state remain disabled"},
            {"control": "raw_dom_capture", "detail": "raw live DOM, cookies, storage values, console logs, and network bodies are still excluded from receipts"},
        ]
    elif not live_browser_reads:
        blockers.insert(1, {"control": "ephemeral_profile", "detail": "live automation must use a per-run browser profile with no persistent cookies or storage"})
        blockers.insert(2, {"control": "network_allowlist", "detail": "navigation and subresource requests must pass configured provider/domain allowlists"})
        blockers.insert(3, {"control": "script_policy", "detail": "page JavaScript execution policy must be explicit before live DOM automation"})
        blockers.insert(4, {"control": "cookie_and_storage_isolation", "detail": "cookies, local storage, and session storage must be isolated and redacted in receipts"})
    feature_label = _live_browser_feature_label(
        live_browser_mutations=live_browser_mutations,
        live_browser_downloads=live_browser_downloads,
        live_browser_uploads=live_browser_uploads,
    )
    status = f"live_browser_{feature_label}_adapter_enabled" if feature_label else "live_browser_readonly_adapter_enabled" if live_browser_reads else "live_browser_adapter_required"
    preflight_status = f"ready_{feature_label}_adapter_enabled" if feature_label else "ready_readonly_mutation_blocked" if live_browser_reads else "blocked"
    selected_adapter = f"chromium-cdp-ephemeral-{feature_label.replace('_', '-')}" if feature_label else "headless-chromium-readonly" if live_browser_reads else None
    return {
        "status": status,
        "preflight_status": preflight_status,
        "selected_adapter": selected_adapter,
        "candidate_adapter_count": len(adapter_candidates),
        "adapter_candidates": adapter_candidates,
        "live_browser_adapter_enabled": bool(live_browser_reads or live_browser_mutations or live_browser_downloads or live_browser_uploads),
        "live_browser_mutation_adapter_enabled": bool(live_browser_mutations),
        "live_browser_download_adapter_enabled": bool(live_browser_downloads),
        "live_browser_upload_adapter_enabled": bool(live_browser_uploads),
        "configured_controls": [
            "http_connector_navigation_allowlist",
            "virtual_interaction_approval_gate",
            "browser_automation_boundary_receipts",
            "private_artifact_storage",
            "artifact_hash_receipts",
            "secret_redaction",
            "live_activation_packet_receipts",
            "live_activation_packet_verification",
            *(
                [
                    "headless_chromium_readonly_adapter",
                    "ephemeral_chromium_profile",
                    "main_frame_network_allowlist",
                    "cookie_storage_disposal",
                    "live_browser_readonly_receipts",
                ]
                if live_browser_reads
                else []
            ),
            *(
                [
                    "chromium_cdp_ephemeral_mutation_adapter",
                    "approval_bound_selector_mutation",
                    "download_upload_denial",
                    "live_browser_mutation_receipts",
                ]
                if live_browser_mutations
                else []
            ),
            *(
                [
                    "chromium_cdp_ephemeral_download_adapter",
                    "approval_bound_download",
                    "download_size_limit",
                    "download_artifact_receipts",
                    "upload_denial",
                ]
                if live_browser_downloads
                else []
            ),
            *(
                [
                    "chromium_cdp_ephemeral_upload_adapter",
                    "approval_bound_upload",
                    "upload_workspace_scope",
                    "upload_size_limit",
                    "upload_mime_allowlist",
                    "upload_artifact_receipts",
                ]
                if live_browser_uploads
                else []
            ),
        ],
        "required_controls": [blocker["control"] for blocker in blockers],
        "blockers": blockers,
        "verification_gates": [
            "disabled_live_browser_denial",
            "allowlisted_navigation",
            "script_policy_enforcement",
            "cookie_storage_isolation",
            "approval_required_mutation",
            "redacted_artifact_receipts",
            "live_activation_packet_integrity",
            *(["approved_live_browser_readonly_snapshot"] if live_browser_reads else []),
            *(["approved_live_browser_selector_mutation"] if live_browser_mutations else []),
            *(["approved_live_browser_download"] if live_browser_downloads else []),
            *(["approved_live_browser_upload"] if live_browser_uploads else []),
            "playwright_chromium_adapter_preflight",
        ],
        "next_steps": [
            "Enable live browser reads only with an explicit security.live_browser_reads config flag and approved action payload.",
            "Enable live browser selector mutation only with an explicit security.live_browser_mutations config flag and matching approval payload.",
            "Enable live browser downloads only with an explicit security.live_browser_downloads config flag and matching selector approval payload.",
            "Enable live browser uploads only with an explicit security.live_browser_uploads config flag, workspace-scoped source file, and matching selector approval payload.",
            "Use the headless Chromium read-only adapter for screenshot evidence only unless the mutation adapter is explicitly enabled.",
            "Keep arbitrary JavaScript evaluation, persistent cookies/storage, raw DOM capture, and raw network body capture disabled.",
            "Keep every real page mutation approval-gated and bind approvals to the exact selector/action payload.",
            "Record redacted hash receipts for screenshots, DOM snapshots, downloads, uploads, console logs, and network traces.",
        ],
    }


def _live_browser_feature_label(*, live_browser_mutations: bool = False, live_browser_downloads: bool = False, live_browser_uploads: bool = False) -> str:
    features: list[str] = []
    if live_browser_mutations:
        features.append("mutation")
    if live_browser_downloads:
        features.append("download")
    if live_browser_uploads:
        features.append("upload")
    return "_".join(features)


def _live_browser_adapter_candidates(*, live_browser_reads: bool = False, live_browser_mutations: bool = False, live_browser_downloads: bool = False, live_browser_uploads: bool = False) -> list[dict[str, Any]]:
    chrome_path = _find_chrome_executable()
    playwright_available = importlib.util.find_spec("playwright") is not None
    blockers = [
        {"control": "explicit_enablement", "detail": "browser live adapter execution is disabled by default"},
        {"control": "adapter_execution_path", "detail": "the Playwright/Chromium adapter has no approved execution path yet"},
        {"control": "approval_bound_mutation_receipts", "detail": "real selector events and page mutations still need exact approval binding and redacted receipts"},
    ]
    if not playwright_available:
        blockers.append({"control": "playwright_runtime", "detail": "python package playwright is not installed in this runtime"})
    if not chrome_path:
        blockers.append({"control": "chromium_runtime", "detail": "google-chrome, chromium, or chromium-browser is not available on PATH"})
    candidates: list[dict[str, Any]] = []
    if live_browser_reads:
        candidates.append(
            {
                "name": "headless-chromium-readonly",
                "engine": "chromium",
                "runtime": "chrome-headless-cli",
                "status": "readonly_enabled" if chrome_path else "runtime_missing",
                "preflight_status": "ready" if chrome_path else "blocked",
                "enabled": bool(chrome_path),
                "chromium_executable_available": bool(chrome_path),
                "raw_executable_path_included": False,
                "required_controls": [
                    "explicit_enablement",
                    "ephemeral_profile",
                    "main_frame_network_allowlist",
                    "script_policy",
                    "cookie_and_storage_isolation",
                    "redacted_artifact_receipts",
                ],
                "configured_controls": [
                    "explicit_enablement",
                    "ephemeral_profile",
                    "main_frame_network_allowlist",
                    "script_policy",
                    "cookie_and_storage_isolation",
                    "redacted_artifact_receipts",
                    "private_artifact_storage",
                    "artifact_hash_receipts",
                    "secret_redaction",
                ],
                "blockers": [] if chrome_path else [{"control": "chromium_runtime", "detail": "google-chrome, chromium, or chromium-browser is not available on PATH"}],
                "next_steps": [
                    "Use only approved live_navigate or live_screenshot actions.",
                    "Keep selector events, page mutation, downloads, uploads, and persistent cookies disabled.",
                ],
            }
        )
    if live_browser_mutations:
        candidates.append(
            {
                "name": "chromium-cdp-ephemeral-mutation",
                "engine": "chromium",
                "runtime": "chrome-devtools-protocol",
                "status": "mutation_enabled" if chrome_path else "runtime_missing",
                "preflight_status": "ready" if chrome_path else "blocked",
                "enabled": bool(chrome_path),
                "package_available": True,
                "chromium_executable_available": bool(chrome_path),
                "raw_executable_path_included": False,
                "required_controls": [
                    "ephemeral_profile",
                    "network_allowlist",
                    "script_policy",
                    "cookie_and_storage_isolation",
                    "approval_gated_mutation",
                    "redacted_artifact_receipts",
                ],
                "configured_controls": [
                    "http_connector_navigation_allowlist",
                    "virtual_interaction_approval_gate",
                    "browser_automation_boundary_receipts",
                    "private_artifact_storage",
                    "artifact_hash_receipts",
                    "secret_redaction",
                    "ephemeral_profile",
                    "network_allowlist",
                    "script_policy",
                    "cookie_and_storage_isolation",
                    "approval_gated_mutation",
                    "redacted_artifact_receipts",
                ],
                "blockers": [] if chrome_path else [{"control": "chromium_runtime", "detail": "google-chrome, chromium, or chromium-browser is not available on PATH"}],
                "next_steps": [
                    "Use only approved live_click, live_fill, and live_submit actions.",
                    "Keep cookies, storage, downloads, uploads, raw DOM capture, and raw network body capture disabled.",
                ],
            }
        )
    if live_browser_downloads:
        candidates.append(
            {
                "name": "chromium-cdp-ephemeral-download",
                "engine": "chromium",
                "runtime": "chrome-devtools-protocol",
                "status": "download_enabled" if chrome_path else "runtime_missing",
                "preflight_status": "ready" if chrome_path else "blocked",
                "enabled": bool(chrome_path),
                "package_available": True,
                "chromium_executable_available": bool(chrome_path),
                "raw_executable_path_included": False,
                "required_controls": [
                    "ephemeral_profile",
                    "network_allowlist",
                    "script_policy",
                    "cookie_and_storage_isolation",
                    "approval_gated_download",
                    "download_size_limit",
                    "redacted_artifact_receipts",
                    "upload_denial",
                ],
                "configured_controls": [
                    "http_connector_navigation_allowlist",
                    "virtual_interaction_approval_gate",
                    "browser_automation_boundary_receipts",
                    "private_artifact_storage",
                    "artifact_hash_receipts",
                    "secret_redaction",
                    "ephemeral_profile",
                    "network_allowlist",
                    "script_policy",
                    "cookie_and_storage_isolation",
                    "approval_gated_download",
                    "download_size_limit",
                    "redacted_artifact_receipts",
                    "upload_denial",
                ],
                "blockers": [] if chrome_path else [{"control": "chromium_runtime", "detail": "google-chrome, chromium, or chromium-browser is not available on PATH"}],
                "next_steps": [
                    "Use only approved live_download actions bound to an exact selector.",
                    "Keep uploads, raw DOM capture, raw network body capture, cookies, storage, and persistent browser profiles disabled.",
                ],
            }
        )
    if live_browser_uploads:
        candidates.append(
            {
                "name": "chromium-cdp-ephemeral-upload",
                "engine": "chromium",
                "runtime": "chrome-devtools-protocol",
                "status": "upload_enabled" if chrome_path else "runtime_missing",
                "preflight_status": "ready" if chrome_path else "blocked",
                "enabled": bool(chrome_path),
                "package_available": True,
                "chromium_executable_available": bool(chrome_path),
                "raw_executable_path_included": False,
                "required_controls": [
                    "ephemeral_profile",
                    "network_allowlist",
                    "script_policy",
                    "cookie_and_storage_isolation",
                    "approval_gated_upload",
                    "upload_workspace_scope",
                    "upload_size_limit",
                    "upload_mime_allowlist",
                    "redacted_artifact_receipts",
                ],
                "configured_controls": [
                    "http_connector_navigation_allowlist",
                    "virtual_interaction_approval_gate",
                    "browser_automation_boundary_receipts",
                    "private_artifact_storage",
                    "artifact_hash_receipts",
                    "secret_redaction",
                    "ephemeral_profile",
                    "network_allowlist",
                    "script_policy",
                    "cookie_and_storage_isolation",
                    "approval_gated_upload",
                    "upload_workspace_scope",
                    "upload_size_limit",
                    "upload_mime_allowlist",
                    "redacted_artifact_receipts",
                ],
                "blockers": [] if chrome_path else [{"control": "chromium_runtime", "detail": "google-chrome, chromium, or chromium-browser is not available on PATH"}],
                "next_steps": [
                    "Use only approved live_upload actions bound to an exact file input selector and workspace-scoped source file.",
                    "Keep downloads disabled unless live_browser_downloads is also explicitly configured.",
                    "Keep arbitrary JavaScript evaluation, raw DOM capture, raw network body capture, cookies, storage, and persistent browser profiles disabled.",
                ],
            }
        )
    candidates.append(
        {
            "name": "playwright-chromium",
            "engine": "chromium",
            "runtime": "python-playwright",
            "status": "adapter_disabled",
            "preflight_status": "blocked",
            "enabled": False,
            "package_available": playwright_available,
            "chromium_executable_available": bool(chrome_path),
            "raw_executable_path_included": False,
            "required_controls": [
                "ephemeral_profile",
                "network_allowlist",
                "script_policy",
                "cookie_and_storage_isolation",
                "approval_gated_mutation",
                "redacted_artifact_receipts",
            ],
            "configured_controls": [
                "http_connector_navigation_allowlist",
                "virtual_interaction_approval_gate",
                "browser_automation_boundary_receipts",
                "private_artifact_storage",
                "artifact_hash_receipts",
                "secret_redaction",
            ],
            "blockers": blockers,
            "next_steps": [
                "Use the dependency-free CDP mutation adapter for the approved selector mutation slice.",
                "Keep Playwright disabled until a separate adapter review is completed.",
                "Keep cookies, storage, downloads, uploads, and raw browser capture disabled.",
            ],
        }
    )
    return candidates


_BROWSER_ACTIVATION_FALSE_CONTROLS = (
    "live_browser_adapter_enabled",
    "real_page_mutation_allowed",
    "real_selector_events_dispatched",
    "page_javascript_allowed",
    "cookies_persisted",
    "cookie_jar_persisted",
    "local_storage_persisted",
    "session_storage_persisted",
    "downloads_allowed",
    "uploads_allowed",
    "raw_browser_content_included",
    "raw_secret_values_included",
    "raw_cookie_values_included",
    "raw_storage_values_included",
    "model_invocation_performed",
)

_BROWSER_ACTIVATION_REQUIRED_BLOCKERS = (
    "live_browser_adapter",
    "ephemeral_profile",
    "network_allowlist",
    "script_policy",
    "cookie_and_storage_isolation",
    "approval_gated_mutation",
    "redacted_artifact_receipts",
)

_BROWSER_ACTIVATION_REQUIRED_CONFIGURED_CONTROLS = (
    "http_connector_navigation_allowlist",
    "virtual_interaction_approval_gate",
    "browser_automation_boundary_receipts",
    "private_artifact_storage",
    "artifact_hash_receipts",
    "secret_redaction",
    "live_activation_packet_receipts",
    "live_activation_packet_verification",
)

_BROWSER_ACTIVATION_REQUIRED_GATES = (
    "disabled_live_browser_denial",
    "allowlisted_navigation",
    "script_policy_enforcement",
    "cookie_storage_isolation",
    "approval_required_mutation",
    "redacted_artifact_receipts",
    "live_activation_packet_integrity",
    "playwright_chromium_adapter_preflight",
)


def _browser_live_activation_packet(*, packet_id: str, actor: str, created_at: str, live_browser_reads: bool = False, live_browser_mutations: bool = False, live_browser_downloads: bool = False, live_browser_uploads: bool = False) -> dict[str, Any]:
    live_browser_reads = live_browser_reads or live_browser_mutations or live_browser_downloads or live_browser_uploads
    activation = _live_browser_activation_preflight(
        live_browser_reads=live_browser_reads,
        live_browser_mutations=live_browser_mutations,
        live_browser_downloads=live_browser_downloads,
        live_browser_uploads=live_browser_uploads,
    )
    chrome_path = _find_chrome_executable()
    controls = {control: False for control in _BROWSER_ACTIVATION_FALSE_CONTROLS}
    controls["live_browser_adapter_enabled"] = bool(live_browser_reads or live_browser_mutations or live_browser_downloads or live_browser_uploads)
    if live_browser_mutations:
        controls["real_page_mutation_allowed"] = True
        controls["real_selector_events_dispatched"] = True
        controls["page_javascript_allowed"] = True
    if live_browser_downloads:
        controls["real_page_mutation_allowed"] = True
        controls["real_selector_events_dispatched"] = True
        controls["page_javascript_allowed"] = True
        controls["downloads_allowed"] = True
    if live_browser_uploads:
        controls["real_page_mutation_allowed"] = True
        controls["real_selector_events_dispatched"] = True
        controls["page_javascript_allowed"] = True
        controls["uploads_allowed"] = True
    return {
        "packet_schema": "aegis.browser.live_activation_packet.v1",
        "packet_id": packet_id,
        "created_at": created_at,
        "actor": _redacted_string(actor, limit=80),
        "taint": "BROWSER_ACTIVATION_METADATA",
        "activation": activation,
        "environment": {
            "chrome_renderer_available": bool(chrome_path),
            "chrome_renderer_name": Path(chrome_path).name if chrome_path else None,
            "raw_executable_path_included": False,
            "raw_environment_included": False,
        },
        "implemented_boundaries": _browser_automation_boundaries(
            rendered=live_browser_mutations or live_browser_downloads or live_browser_uploads,
            live_mutation=live_browser_mutations,
            live_download=live_browser_downloads,
            live_upload=live_browser_uploads,
        ),
        "review_instructions": [
            "Treat this packet as local activation metadata, not proof that live browser automation is enabled.",
            "Verify checksum, schema, blockers, and control flags before implementing a live adapter.",
            "Do not use this packet to bypass approvals for real clicks, form fills, downloads, uploads, or page mutations.",
        ],
        "controls": controls,
    }


def _browser_live_activation_controls_valid(controls: dict[str, Any]) -> bool:
    expected_controls = set(_BROWSER_ACTIVATION_FALSE_CONTROLS)
    if set(controls) != expected_controls:
        return False
    mutation_enabled = controls.get("real_page_mutation_allowed") is True or controls.get("real_selector_events_dispatched") is True or controls.get("page_javascript_allowed") is True
    download_enabled = controls.get("downloads_allowed") is True
    upload_enabled = controls.get("uploads_allowed") is True
    for control in _BROWSER_ACTIVATION_FALSE_CONTROLS:
        if control == "live_browser_adapter_enabled":
            if controls.get(control) not in {False, True}:
                return False
            continue
        if control == "downloads_allowed" and download_enabled:
            continue
        if control == "uploads_allowed":
            if upload_enabled:
                continue
            if controls.get(control) is not False:
                return False
            continue
        if mutation_enabled and control in {"real_page_mutation_allowed", "real_selector_events_dispatched", "page_javascript_allowed"}:
            if controls.get(control) is not True:
                return False
            continue
        if controls.get(control) is not False:
            return False
    return True


def _browser_live_activation_feature_label(status: str) -> str:
    prefix = "live_browser_"
    suffix = "_adapter_enabled"
    if not status.startswith(prefix) or not status.endswith(suffix):
        return ""
    label = status[len(prefix) : -len(suffix)]
    return "" if label == "readonly" else label


def _browser_live_activation_preflight_valid(activation: dict[str, Any]) -> bool:
    feature_label = _browser_live_activation_feature_label(str(activation.get("status") or ""))
    features = set(feature_label.split("_")) if feature_label else set()
    mutation_enabled = "mutation" in features
    download_enabled = "download" in features
    upload_enabled = "upload" in features
    live_readonly = activation.get("status") == "live_browser_readonly_adapter_enabled"
    if features:
        if activation.get("preflight_status") != f"ready_{feature_label}_adapter_enabled":
            return False
        if activation.get("selected_adapter") != f"chromium-cdp-ephemeral-{feature_label.replace('_', '-')}" or activation.get("live_browser_adapter_enabled") is not True:
            return False
        if activation.get("live_browser_mutation_adapter_enabled") is not bool(mutation_enabled):
            return False
        if activation.get("live_browser_download_adapter_enabled") is not bool(download_enabled):
            return False
        if activation.get("live_browser_upload_adapter_enabled") is not bool(upload_enabled):
            return False
    elif live_readonly:
        if activation.get("preflight_status") != "ready_readonly_mutation_blocked":
            return False
        if activation.get("selected_adapter") != "headless-chromium-readonly" or activation.get("live_browser_adapter_enabled") is not True:
            return False
    else:
        if activation.get("status") != "live_browser_adapter_required" or activation.get("preflight_status") != "blocked":
            return False
        if activation.get("selected_adapter") is not None or activation.get("live_browser_adapter_enabled") is not False:
            return False
    if not _browser_live_adapter_candidates_valid(activation.get("adapter_candidates")):
        return False
    blockers = activation.get("blockers")
    if not isinstance(blockers, list) or not blockers:
        return False
    blocker_controls = {str(blocker.get("control", "")) for blocker in blockers if isinstance(blocker, dict)}
    required_controls = {str(control) for control in activation.get("required_controls") or []}
    configured_controls = {str(control) for control in activation.get("configured_controls") or []}
    verification_gates = {str(gate) for gate in activation.get("verification_gates") or []}
    required_blockers = (
        {"arbitrary_js", "raw_dom_capture"}
        if upload_enabled and download_enabled
        else {"downloads_and_arbitrary_js", "raw_dom_capture"}
        if upload_enabled
        else {"uploads_and_arbitrary_js", "raw_dom_capture"}
        if download_enabled
        else {"downloads_and_uploads", "raw_dom_capture"}
        if mutation_enabled
        else {"live_browser_adapter", "approval_gated_mutation", "redacted_artifact_receipts"}
        if live_readonly
        else set(_BROWSER_ACTIVATION_REQUIRED_BLOCKERS)
    )
    configured_required = set(_BROWSER_ACTIVATION_REQUIRED_CONFIGURED_CONTROLS)
    if live_readonly:
        configured_required.update(
            {
                "headless_chromium_readonly_adapter",
                "ephemeral_chromium_profile",
                "main_frame_network_allowlist",
                "cookie_storage_disposal",
                "live_browser_readonly_receipts",
            }
        )
    if mutation_enabled:
        configured_required.update(
            {
                "chromium_cdp_ephemeral_mutation_adapter",
                "approval_bound_selector_mutation",
                "live_browser_mutation_receipts",
            }
        )
        if not download_enabled:
            configured_required.add("download_upload_denial")
    if download_enabled:
        configured_required.update(
            {
                "chromium_cdp_ephemeral_download_adapter",
                "approval_bound_download",
                "download_size_limit",
                "download_artifact_receipts",
                "upload_denial",
            }
        )
    if upload_enabled:
        configured_required.update(
            {
                "chromium_cdp_ephemeral_upload_adapter",
                "approval_bound_upload",
                "upload_workspace_scope",
                "upload_size_limit",
                "upload_mime_allowlist",
                "upload_artifact_receipts",
            }
        )
    gates_required = set(_BROWSER_ACTIVATION_REQUIRED_GATES)
    if live_readonly:
        gates_required.add("approved_live_browser_readonly_snapshot")
    if mutation_enabled:
        gates_required.add("approved_live_browser_selector_mutation")
    if download_enabled:
        gates_required.add("approved_live_browser_download")
    if upload_enabled:
        gates_required.add("approved_live_browser_upload")
    return (
        required_blockers.issubset(blocker_controls)
        and required_blockers.issubset(required_controls)
        and configured_required.issubset(configured_controls)
        and gates_required.issubset(verification_gates)
    )


def _browser_live_adapter_candidates_valid(candidates: Any) -> bool:
    if not isinstance(candidates, list) or not candidates:
        return False
    playwright = next((candidate for candidate in candidates if isinstance(candidate, dict) and candidate.get("name") == "playwright-chromium"), None)
    if not isinstance(playwright, dict):
        return False
    if playwright.get("enabled") is not False or playwright.get("preflight_status") != "blocked":
        return False
    if playwright.get("raw_executable_path_included") is not False:
        return False
    if playwright.get("runtime") != "python-playwright" or playwright.get("engine") != "chromium":
        return False
    blockers = playwright.get("blockers")
    if not isinstance(blockers, list) or not blockers:
        return False
    blocker_controls = {str(blocker.get("control", "")) for blocker in blockers if isinstance(blocker, dict)}
    return {"explicit_enablement", "adapter_execution_path", "approval_bound_mutation_receipts"}.issubset(blocker_controls)


def _playwright_chromium_preflight_status(activation: dict[str, Any]) -> str:
    candidates = activation.get("adapter_candidates") if isinstance(activation, dict) else None
    if not isinstance(candidates, list):
        return "missing"
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("name") == "playwright-chromium":
            return str(candidate.get("preflight_status") or candidate.get("status") or "unknown")
    return "missing"


def _browser_live_activation_boundaries_valid(boundaries: dict[str, Any]) -> bool:
    if boundaries.get("boundary_schema") != "browser_automation_boundaries_v1":
        return False
    mutation_enabled = boundaries.get("real_page_mutation_allowed") is True or boundaries.get("real_selector_events_dispatched") is True
    download_enabled = boundaries.get("downloads_allowed") is True
    upload_enabled = boundaries.get("uploads_allowed") is True
    false_fields = (
        "cookie_jar_persisted",
        "cookies_persisted",
        "local_storage_persisted",
        "raw_secret_capture_allowed",
        "session_storage_persisted",
    )
    if any(boundaries.get(field) is not False for field in false_fields):
        return False
    if mutation_enabled:
        if boundaries.get("page_javascript_allowed") is not True or boundaries.get("real_page_mutation_allowed") is not True or boundaries.get("real_selector_events_dispatched") is not True:
            return False
        if boundaries.get("original_page_dom_executed") is not True:
            return False
        if boundaries.get("remote_subresources_loaded") != "allowlisted_only":
            return False
        if boundaries.get("virtual_interactions_only") is not False:
            return False
    else:
        if boundaries.get("page_javascript_allowed") is not False or boundaries.get("real_page_mutation_allowed") is not False or boundaries.get("real_selector_events_dispatched") is not False or boundaries.get("original_page_dom_executed") is not False or boundaries.get("remote_subresources_loaded") is not False:
            return False
        if boundaries.get("virtual_interactions_only") is not True:
            return False
    if boundaries.get("downloads_allowed") not in ({True, False} if download_enabled else {False}):
        return False
    if boundaries.get("uploads_allowed") not in ({True, False} if upload_enabled else {False}):
        return False
    required = {str(item) for item in boundaries.get("required_before_live_browser_adapter") or []}
    return set(_BROWSER_ACTIVATION_REQUIRED_BLOCKERS).difference({"live_browser_adapter"}).issubset(required)


def _browser_live_activation_packet_paths(artifact_dir: Path, packet: str) -> tuple[Path, Path]:
    packet_dir = ensure_private_dir(artifact_dir / "live-activation-packets")
    packet_ref = str(packet or "").strip()
    if not packet_ref:
        raise ValueError("browser activation packet id or path is required")
    candidate = Path(packet_ref)
    packet_path = candidate if candidate.is_absolute() or candidate.parent != Path(".") else packet_dir / (packet_ref if packet_ref.endswith(".json") else f"{packet_ref}.json")
    resolved_dir = packet_dir.resolve()
    resolved_packet = packet_path.resolve()
    try:
        resolved_packet.relative_to(resolved_dir)
    except ValueError as exc:
        raise ValueError("browser activation packet path must stay inside the private browser activation packet directory") from exc
    if resolved_packet.suffix != ".json":
        raise ValueError("browser activation packet artifact must be a .json file")
    if not resolved_packet.exists():
        raise FileNotFoundError(str(resolved_packet))
    return resolved_packet, resolved_packet.with_suffix(".sha256")


def _browser_live_activation_packet_summary(packet: dict[str, Any]) -> dict[str, Any]:
    activation = packet.get("activation") if isinstance(packet.get("activation"), dict) else {}
    environment = packet.get("environment") if isinstance(packet.get("environment"), dict) else {}
    controls = packet.get("controls") if isinstance(packet.get("controls"), dict) else {}
    adapter_candidates = activation.get("adapter_candidates") if isinstance(activation.get("adapter_candidates"), list) else []
    return {
        "packet_schema": packet.get("packet_schema"),
        "packet_id": packet.get("packet_id"),
        "created_at": packet.get("created_at"),
        "activation_status": activation.get("status"),
        "preflight_status": activation.get("preflight_status"),
        "selected_adapter": activation.get("selected_adapter"),
        "candidate_adapter_count": activation.get("candidate_adapter_count"),
        "playwright_chromium_preflight_status": _playwright_chromium_preflight_status(activation),
        "adapter_candidates": [
            {
                "name": candidate.get("name"),
                "status": candidate.get("status"),
                "preflight_status": candidate.get("preflight_status"),
                "enabled": bool(candidate.get("enabled", False)),
                "package_available": bool(candidate.get("package_available", False)),
                "chromium_executable_available": bool(candidate.get("chromium_executable_available", False)),
                "raw_executable_path_included": bool(candidate.get("raw_executable_path_included", True)),
            }
            for candidate in adapter_candidates
            if isinstance(candidate, dict)
        ],
        "required_controls": list(activation.get("required_controls") or []),
        "configured_controls": list(activation.get("configured_controls") or []),
        "verification_gates": list(activation.get("verification_gates") or []),
        "chrome_renderer_available": bool(environment.get("chrome_renderer_available", False)),
        "chrome_renderer_name": environment.get("chrome_renderer_name"),
        "live_browser_adapter_enabled": bool(controls.get("live_browser_adapter_enabled", False)),
        "live_browser_mutation_adapter_enabled": bool(controls.get("real_page_mutation_allowed", False)),
        "live_browser_download_adapter_enabled": bool(controls.get("downloads_allowed", False)),
        "live_browser_upload_adapter_enabled": bool(controls.get("uploads_allowed", False)),
        "raw_browser_content_included": False,
        "raw_secret_values_included": False,
        "raw_cookie_values_included": False,
        "raw_storage_values_included": False,
        "model_invocation_performed": bool(controls.get("model_invocation_performed", False)),
    }


def _browser_activation_packet_forbidden_keys_present(value: Any) -> bool:
    forbidden = {
        "raw_browser_content",
        "raw_content",
        "raw_dom",
        "raw_html",
        "raw_page_html",
        "raw_environment",
        "raw_executable_path",
        "raw_cookie",
        "raw_cookies",
        "raw_cookie_jar",
        "raw_local_storage",
        "raw_session_storage",
        "raw_storage",
        "raw_secret",
        "raw_response_body",
        "secret_value",
        "access_token",
        "refresh_token",
        "browser_cookie",
        "session_cookie",
    }
    allowed_raw_flags = {
        "raw_executable_path_included",
        "raw_environment_included",
        "raw_browser_content_included",
        "raw_secret_values_included",
        "raw_cookie_values_included",
        "raw_storage_values_included",
        "raw_secret_capture_allowed",
    }
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = str(key)
            if normalized_key in allowed_raw_flags and item is not False:
                return True
            if normalized_key not in allowed_raw_flags and (normalized_key in forbidden or normalized_key.startswith("raw_")):
                return True
            if _browser_activation_packet_forbidden_keys_present(item):
                return True
    if isinstance(value, list):
        return any(_browser_activation_packet_forbidden_keys_present(item) for item in value)
    return False


def _title_from_text(content: str, *, fallback: str) -> str:
    html_title = _title_from_html(content)
    if html_title:
        return html_title
    first_line = next((line.strip() for line in content.splitlines() if line.strip()), "")
    if not first_line:
        return fallback
    return str(redact(first_line[:120]))


def _title_from_html(content: str) -> str:
    if "<title" not in content.lower():
        return ""
    parser = _TitleParser()
    try:
        parser.feed(content[:20_000])
    except Exception:
        return ""
    title = " ".join(parser.title_parts).strip()
    return str(redact(title[:120])) if title else ""


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title and len(" ".join(self.title_parts)) < 120:
            self.title_parts.append(data)


def _extract_interactive_elements(content: str, *, limit: int = 50) -> list[dict[str, Any]]:
    if "<" not in content:
        return []
    parser = _InteractiveElementParser(limit=limit)
    try:
        parser.feed(content[:_MAX_PERSISTED_CONTENT_CHARS])
        parser.close()
    except Exception:
        return []
    return parser.elements[:limit]


class _InteractiveElementParser(HTMLParser):
    def __init__(self, *, limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self.limit = limit
        self.elements: list[dict[str, Any]] = []
        self._capture: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag == "a":
            self._begin_capture(tag, attrs_dict)
            return
        if tag == "button":
            self._begin_capture(tag, attrs_dict)
            return
        if tag in {"input", "textarea", "select"}:
            self._append_element(tag, attrs_dict, text=attrs_dict.get("aria-label") or attrs_dict.get("placeholder") or attrs_dict.get("value") or attrs_dict.get("name") or attrs_dict.get("id") or tag)

    def handle_data(self, data: str) -> None:
        if self._capture is not None:
            self._capture["text_parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._capture is not None and tag.lower() == self._capture["tag"]:
            capture = self._capture
            self._capture = None
            self._append_element(capture["tag"], capture["attrs"], text=" ".join(capture["text_parts"]))

    def _begin_capture(self, tag: str, attrs: dict[str, str]) -> None:
        if len(self.elements) >= self.limit:
            return
        self._capture = {"tag": tag, "attrs": attrs, "text_parts": []}

    def _append_element(self, tag: str, attrs: dict[str, str], *, text: str) -> None:
        if len(self.elements) >= self.limit:
            return
        label = " ".join(str(text or "").split()) or attrs.get("aria-label") or attrs.get("title") or tag
        selector = _selector_hint(tag, attrs)
        element = {
            "tag": tag,
            "label": str(redact(label))[:120],
            "id": str(redact(attrs.get("id", "")))[:120],
            "name": str(redact(attrs.get("name", "")))[:120],
            "type": str(redact(attrs.get("type", "")))[:80],
            "selector_hint": _redacted_string(selector, limit=500),
        }
        if tag == "a":
            element["href"] = str(redact(attrs.get("href", "")))[:300]
        if tag in {"button", "input", "textarea", "select"}:
            element["form_hint"] = _redacted_string(selector, limit=500)
        self.elements.append(element)


def _selector_hint(tag: str, attrs: dict[str, str]) -> str:
    element_id = attrs.get("id", "")
    if _simple_selector_value(element_id):
        return f"#{element_id}"
    name = attrs.get("name", "")
    if _simple_selector_value(name):
        return f'{tag}[name="{name}"]'
    return tag


def _state_text(session: dict[str, Any]) -> str:
    lines: list[str] = []
    clicks = _normalize_clicks(session.get("clicks"))
    form_state = _normalize_form_state(session.get("form_state"))
    if clicks:
        lines.append("Browser interaction state:")
        lines.extend(f"clicked {item.get('selector', '')}" for item in clicks[-10:])
    if form_state:
        if not lines:
            lines.append("Browser interaction state:")
        lines.extend(f"field {selector} = {value}" for selector, value in sorted(form_state.items()))
    return "\n".join(lines)


def _matching_static_anchor_elements(session: dict[str, Any], selector: str) -> dict[str, Any]:
    requested_selector = _redacted_string(selector, limit=500)
    matches = []
    for element in _normalize_interactive_elements(session.get("interactive_elements")):
        if element.get("tag") != "a":
            continue
        element_selector = _redacted_string(element.get("selector_hint") or element.get("tag"), limit=500)
        if element_selector == requested_selector:
            matches.append(element)
    if len(matches) > 1:
        return {"status": "ambiguous"}
    if matches:
        return {"status": "matched", "element": matches[0]}
    return {"status": "no_match"}


def _static_anchor_navigation_target(session: dict[str, Any], element: dict[str, str]) -> dict[str, Any]:
    href = str(element.get("href") or "").strip()
    if not href:
        return {"ok": False, "reason": "missing_href", "detail": "static anchor has no href"}
    parsed_href = urlparse(href)
    if parsed_href.scheme and parsed_href.scheme.lower() not in {"http", "https"}:
        return {"ok": False, "reason": "unsupported_scheme", "detail": f"static anchor scheme {parsed_href.scheme!r} is not supported"}
    if not parsed_href.scheme and not parsed_href.netloc and not parsed_href.path and not parsed_href.params and not parsed_href.query and parsed_href.fragment:
        return {"ok": False, "reason": "fragment_only_href", "detail": "fragment-only anchors do not navigate through the governed HTTP connector"}
    base_url = _session_url(session)
    if not base_url:
        return {"ok": False, "reason": "missing_base_url", "detail": "browser session has no current URL"}
    target_url = urljoin(base_url, href)
    parsed_target = urlparse(target_url)
    if parsed_target.scheme.lower() not in {"http", "https"} or not parsed_target.netloc:
        return {"ok": False, "reason": "unsupported_target_url", "detail": "resolved static anchor target is not an HTTP(S) URL"}
    return {"ok": True, "url": target_url}


def _matching_static_form(session: dict[str, Any], selector: str | None) -> dict[str, Any]:
    forms = _extract_static_forms(str(session.get("last_content", "")))
    requested_selector = _redacted_string(selector, limit=500) if selector is not None else ""
    if selector:
        matcher = _dom_selector_matcher(requested_selector)
        if matcher is None:
            return {"status": "unsupported_selector", "detail": "selector is outside the static form parser subset"}
        matches = [form for form in forms if matcher({"type": "element", "tag": "form", "attrs": form["attrs"]})]
    else:
        matches = forms
    if not matches:
        return {"status": "no_match", "detail": "no matching static form was found"}
    if len(matches) > 1:
        return {"status": "ambiguous", "detail": "selector matched multiple static forms"}
    return {"status": "matched", "form": matches[0]}


def _extract_static_forms(content: str, *, limit: int = 25) -> list[dict[str, Any]]:
    if "<" not in content:
        return []
    parser = _StaticFormParser(limit=limit)
    try:
        parser.feed(content[:_MAX_PERSISTED_CONTENT_CHARS])
        parser.close()
    except Exception:
        return []
    return parser.forms[:limit]


class _StaticFormParser(HTMLParser):
    def __init__(self, *, limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self.limit = limit
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self._textarea: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag == "form" and len(self.forms) < self.limit:
            self._current_form = {"attrs": _redacted_dom_attrs(attrs_dict), "fields": []}
            return
        if self._current_form is None:
            return
        if tag == "input":
            field = _static_form_input_field(attrs_dict)
            if field is not None:
                self._current_form["fields"].append(field)
            return
        if tag == "textarea":
            name = attrs_dict.get("name", "")
            if name:
                self._textarea = {"name": _redacted_string(name, limit=200), "value_parts": []}
            return
        if tag == "select":
            name = attrs_dict.get("name", "")
            if name:
                self._current_form["fields"].append({"name": _redacted_string(name, limit=200), "value": _redacted_dom_value(attrs_dict.get("value", ""), limit=500)})

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._textarea["value_parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "textarea" and self._textarea is not None and self._current_form is not None:
            self._current_form["fields"].append(
                {
                    "name": self._textarea["name"],
                    "value": _redacted_dom_value("".join(self._textarea["value_parts"]), limit=500),
                }
            )
            self._textarea = None
            return
        if tag == "form" and self._current_form is not None:
            attrs = self._current_form["attrs"]
            self._current_form["selector_hint"] = _redacted_string(_selector_hint("form", attrs), limit=500)
            self.forms.append(self._current_form)
            self._current_form = None
            self._textarea = None


def _static_form_input_field(attrs: dict[str, str]) -> dict[str, str] | None:
    name = attrs.get("name", "")
    if not name:
        return None
    input_type = attrs.get("type", "").lower()
    if input_type in {"button", "submit", "reset", "image", "file"}:
        return None
    if input_type in {"checkbox", "radio"} and "checked" not in attrs:
        return None
    return {"name": _redacted_string(name, limit=200), "value": _redacted_dom_value(attrs.get("value", ""), limit=500)}


def _static_form_submission_target(session: dict[str, Any], form: dict[str, Any]) -> dict[str, Any]:
    attrs = form.get("attrs") if isinstance(form.get("attrs"), dict) else {}
    method = str(attrs.get("method") or "get").strip().lower()
    if method != "get":
        return {"ok": False, "reason": "unsupported_method", "detail": "only static GET form submits are supported by the governed HTTP connector"}
    base_url = _session_url(session)
    if not base_url:
        return {"ok": False, "reason": "missing_base_url", "detail": "browser session has no current URL"}
    action = str(attrs.get("action") or base_url).strip() or base_url
    parsed_action = urlparse(action)
    if parsed_action.scheme and parsed_action.scheme.lower() not in {"http", "https"}:
        return {"ok": False, "reason": "unsupported_scheme", "detail": f"static form action scheme {parsed_action.scheme!r} is not supported"}
    target_url = urljoin(base_url, action)
    parsed_target = urlparse(target_url)
    if parsed_target.scheme.lower() not in {"http", "https"} or not parsed_target.netloc:
        return {"ok": False, "reason": "unsupported_target_url", "detail": "resolved static form target is not an HTTP(S) URL"}
    fields = [(str(field.get("name") or ""), str(field.get("value") or "")) for field in form.get("fields", []) if isinstance(field, dict) and field.get("name")]
    query = urlencode(fields, doseq=True)
    if query:
        separator = "&" if parsed_target.query else "?"
        target_url = f"{target_url}{separator}{query}"
    return {
        "ok": True,
        "url": target_url,
        "method": "GET",
        "field_names": sorted({name for name, _value in fields}),
        "field_count": len(fields),
    }


def _static_form_submit_blocked(
    session: dict[str, Any],
    *,
    session_id: str,
    selector: str | None,
    reason: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "ok": False,
        "status": "static_form_submit_blocked",
        "session_id": session_id,
        "selector": _redacted_string(selector, limit=500) if selector is not None else None,
        "url": _session_url(session),
        "reason": reason,
        "detail": _redacted_string(detail, limit=500),
        "effect": "blocked_static_form_submit",
        "mode": "approved_static_form_submit_no_js",
        "javascript_executed": False,
        "dom_mutated": False,
        "real_selector_events_dispatched": False,
        "cookies_persisted": False,
    }


def _url_origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _url_path(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


def _static_anchor_navigation_blocked(
    session: dict[str, Any],
    *,
    session_id: str,
    selector: str,
    reason: str,
    detail: str,
    href: str = "",
) -> dict[str, Any]:
    return {
        "ok": False,
        "status": "static_anchor_navigation_blocked",
        "session_id": session_id,
        "selector": _redacted_string(selector, limit=500),
        "url": _session_url(session),
        "href": _redacted_string(href, limit=500),
        "reason": reason,
        "detail": _redacted_string(detail, limit=500),
        "effect": "blocked_static_anchor_navigation",
        "mode": "approved_static_anchor_navigation_no_js",
        "javascript_executed": False,
        "dom_mutated": False,
        "real_selector_events_dispatched": False,
    }


def _redacted_form_state(session: dict[str, Any]) -> str:
    form_state = _normalize_form_state(session.get("form_state"))
    return ", ".join(f"{selector}={value}" for selector, value in sorted(form_state.items()))


def _content_hash(session: dict[str, Any]) -> str:
    content = _bounded_redacted_content(str(session.get("last_content", "")))
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _write_session_snapshot_png(path: Path, *, session: dict[str, Any]) -> tuple[int, int]:
    width = 320
    height = 180
    seed_text = json.dumps(
        {
            "url": _session_url(session),
            "title": _redacted_string(session.get("title"), limit=200),
            "content_hash": _content_hash(session),
            "clicks": [item.get("selector") for item in _normalize_clicks(session.get("clicks"))[-10:]],
            "form_state": _redacted_form_state(session),
        },
        sort_keys=True,
        default=str,
    )
    seed = hashlib.sha256(seed_text.encode("utf-8", errors="replace")).digest()
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            header = y < 24
            left_rule = x < 6
            grid = (x // 20 + y // 18) % 2
            noise = seed[(x * 3 + y * 5) % len(seed)]
            if header:
                pixel = (32 + seed[0] // 4, 42 + seed[1] // 5, 58 + seed[2] // 6)
            elif left_rule:
                pixel = (seed[3], 96 + seed[4] // 2, 128 + seed[5] // 3)
            elif grid:
                pixel = ((seed[6] + noise // 3) % 256, (seed[7] + noise // 4) % 256, (seed[8] + noise // 5) % 256)
            else:
                pixel = ((220 + noise // 12) % 256, (225 + noise // 16) % 256, (230 + noise // 20) % 256)
            rows.extend(pixel)
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(bytes(rows), level=9))
        + _png_chunk(b"IEND", b"")
    )
    return width, height


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def _browser_evidence(
    session: dict[str, Any],
    *,
    action: str,
    url_before: Any | None = None,
    content_hash_before: str | None = None,
) -> dict[str, Any]:
    url_after = _session_url(session)
    content_hash_after = _content_hash(session)
    return {
        "action": action,
        "url_before": _redacted_string(url_before, limit=2000) if url_before is not None else url_after,
        "url_after": url_after,
        "content_sha256_before": content_hash_before or content_hash_after,
        "content_sha256_after": content_hash_after,
        "content_changed": (content_hash_before or content_hash_after) != content_hash_after,
        "dom_mutated": False,
        "mode": (
            "virtual_state_no_dom"
            if action in {"click", "fill"}
            else "approved_static_anchor_navigation_no_js"
            if action == "static_anchor_navigation"
            else "approved_static_form_submit_no_js"
            if action == "static_form_submit"
            else "http_content_static_dom_no_js"
            if action == "dom_snapshot"
            else "local_png_session_snapshot_no_dom_render"
        ),
        "click_count": len(session.get("clicks", [])),
        "form_field_count": len(session.get("form_state", {})),
    }


def _browser_snapshot_evidence_document(
    session: dict[str, Any],
    *,
    evidence: dict[str, Any],
    artifact_hashes: dict[str, str],
    sandbox_receipt: dict[str, Any],
) -> dict[str, Any]:
    content = str(session.get("last_content", ""))
    table_result = _extract_html_tables(content)
    tables = table_result["tables"]
    return {
        "version": 1,
        "captured_at": now_utc(),
        "session_id": session.get("id"),
        "url": _session_url(session),
        "title": _redacted_string(session.get("title"), limit=200),
        "capture_surface": "http_content_session_state",
        "rendering_status": "not_rendered",
        "mode": "local_png_session_snapshot_no_dom_render",
        "sandbox_receipt": dict(sandbox_receipt),
        "automation_boundaries": _browser_automation_boundaries(rendered=False),
        "limitations": [
            "No page JavaScript was executed.",
            "No browser cookies or remote browser profile were used.",
            "The PNG is a deterministic local session-state snapshot, not a rendered DOM capture.",
        ],
        "content_sha256": _content_hash(session),
        "content_length": len(content),
        "artifact_hashes": dict(artifact_hashes),
        "interactive_element_count": len(session.get("interactive_elements", [])),
        "interactive_elements": _normalize_interactive_elements(session.get("interactive_elements")),
        "table_count": len(tables),
        "table_row_counts": [len(table) for table in tables],
        "clicks": _normalize_clicks(session.get("clicks")),
        "form_state": _normalize_form_state(session.get("form_state")),
        "action_evidence": evidence,
    }


def _browser_render_evidence_document(
    session: dict[str, Any],
    *,
    evidence: dict[str, Any],
    artifact_hashes: dict[str, str],
    sandbox_receipt: dict[str, Any],
    render_result: dict[str, Any],
) -> dict[str, Any]:
    content = str(session.get("last_content", ""))
    table_result = _extract_html_tables(content)
    tables = table_result["tables"]
    return {
        "version": 1,
        "captured_at": now_utc(),
        "session_id": session.get("id"),
        "url": _session_url(session),
        "title": _redacted_string(session.get("title"), limit=200),
        "capture_surface": "sanitized_http_content_dom",
        "rendering_status": "rendered" if render_result.get("ok") else "render_failed",
        "mode": "sanitized_dom_render_no_page_js",
        "sandbox_receipt": dict(sandbox_receipt),
        "automation_boundaries": _browser_automation_boundaries(rendered=True),
        "limitations": [
            "The rendered HTML is sanitized text and table content derived from the HTTP connector response.",
            "Original page scripts, styles, forms, iframes, and remote subresources were not preserved.",
            "The Chrome profile is temporary and cookies are not persisted.",
        ],
        "content_sha256": _content_hash(session),
        "content_length": len(content),
        "artifact_hashes": dict(artifact_hashes),
        "interactive_element_count": len(session.get("interactive_elements", [])),
        "interactive_elements": _normalize_interactive_elements(session.get("interactive_elements")),
        "table_count": len(tables),
        "table_row_counts": [len(table) for table in tables],
        "clicks": _normalize_clicks(session.get("clicks")),
        "form_state": _normalize_form_state(session.get("form_state")),
        "render_exit_code": render_result.get("exit_code"),
        "action_evidence": evidence,
    }


def _browser_sandbox_receipt() -> dict[str, Any]:
    return {
        "sandbox_profile": "http_content_session_state_no_js",
        "ambient_workspace_read": False,
        "ambient_network": "http_connector_allowlist_only",
        "navigation_network": "http_connector_allowlist_only",
        "remote_subresources_loaded": False,
        "cookies_persisted": False,
        "cookie_jar_persisted": False,
        "local_storage_persisted": False,
        "session_storage_persisted": False,
        "javascript_executed": False,
        "page_javascript_allowed": False,
        "dom_renderer_used": False,
        "real_page_mutation_allowed": False,
        "raw_secret_capture_allowed": False,
        "writes_confined_to": ".aegis/browser",
    }


def _browser_render_sandbox_receipt(*, executable: str, exit_code: int | None) -> dict[str, Any]:
    return {
        "sandbox_profile": "sanitized_http_content_chrome_render",
        "ambient_workspace_read": False,
        "ambient_network": "disabled_for_generated_file_capture",
        "navigation_network": "disabled_for_generated_file_capture",
        "remote_subresources_loaded": False,
        "cookies_persisted": False,
        "cookie_jar_persisted": False,
        "local_storage_persisted": False,
        "session_storage_persisted": False,
        "javascript_executed": False,
        "page_javascript_allowed": False,
        "original_page_dom_executed": False,
        "dom_renderer_used": True,
        "real_page_mutation_allowed": False,
        "renderer": Path(executable).name,
        "renderer_exit_code": exit_code,
        "raw_secret_capture_allowed": False,
        "writes_confined_to": ".aegis/browser",
    }


def _browser_automation_boundaries(*, rendered: bool, live_mutation: bool = False, live_download: bool = False, live_upload: bool = False) -> dict[str, Any]:
    live_browser_action = live_mutation or live_download or live_upload
    return {
        "boundary_schema": "browser_automation_boundaries_v1",
        "capture_surface": "live_browser_upload_snapshot" if live_upload else "live_browser_download_snapshot" if live_download else "live_browser_mutation_snapshot" if live_mutation else "sanitized_generated_html" if rendered else "http_content_session_state",
        "navigation_network": "main_frame_allowlist_only" if live_browser_action else "disabled_for_generated_file_capture" if rendered else "http_connector_allowlist_only",
        "remote_subresources_loaded": "allowlisted_only" if live_browser_action else False,
        "page_javascript_allowed": bool(live_browser_action),
        "original_page_dom_executed": bool(live_browser_action),
        "cookies_persisted": False,
        "cookie_jar_persisted": False,
        "local_storage_persisted": False,
        "session_storage_persisted": False,
        "real_selector_events_dispatched": bool(live_browser_action),
        "real_page_mutation_allowed": bool(live_browser_action),
        "virtual_interactions_only": not live_browser_action,
        "downloads_allowed": bool(live_download),
        "uploads_allowed": bool(live_upload),
        "raw_secret_capture_allowed": False,
        "required_before_live_browser_adapter": [
            "ephemeral_profile",
            "network_allowlist",
            "subresource_policy",
            "script_policy",
            "cookie_and_storage_isolation",
            "approval_gated_mutation",
            "redacted_artifact_receipts",
        ],
    }


def _find_chrome_executable() -> str | None:
    for executable in ("google-chrome", "chromium", "chromium-browser"):
        path = shutil.which(executable)
        if path:
            return path
    return None


def _renderable_sanitized_html(session: dict[str, Any]) -> str:
    content = str(session.get("last_content", ""))
    text = _redacted_dom_value(" ".join(content.split()), limit=20_000)
    tables = _extract_html_tables(content).get("tables", [])[:5]
    rows = []
    for table in tables:
        row_html = []
        for row in table[:25]:
            cells = "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row[:10])
            row_html.append(f"<tr>{cells}</tr>")
        if row_html:
            rows.append(f"<table>{''.join(row_html)}</table>")
    clicks = _normalize_clicks(session.get("clicks"))
    form_state = _normalize_form_state(session.get("form_state"))
    state_items = [f"<li>clicked {html.escape(item.get('selector', ''))}</li>" for item in clicks[-10:]]
    state_items.extend(f"<li>{html.escape(selector)} = {html.escape(value)}</li>" for selector, value in sorted(form_state.items()))
    state_html = f"<ul>{''.join(state_items)}</ul>" if state_items else "<p>No approved virtual interactions recorded.</p>"
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:;">
  <title>{html.escape(_redacted_string(session.get("title") or "Aegis render", limit=200))}</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; color: #1f2933; background: #f7f9fb; }}
    header {{ padding: 18px 24px; background: #17202a; color: white; }}
    main {{ padding: 20px 24px; display: grid; gap: 16px; }}
    section {{ background: white; border: 1px solid #d8dee4; border-radius: 6px; padding: 16px; }}
    h1 {{ font-size: 22px; margin: 0 0 6px; }}
    h2 {{ font-size: 15px; margin: 0 0 10px; color: #334155; }}
    p, li, td {{ font-size: 13px; line-height: 1.45; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
    td {{ border: 1px solid #d8dee4; padding: 6px 8px; }}
    .muted {{ color: #64748b; font-size: 12px; }}
  </style>
</head>
<body>
  <header>
    <h1>{html.escape(_redacted_string(session.get("title") or "Browser session", limit=200))}</h1>
    <div class="muted">{html.escape(_session_url(session) or "")}</div>
  </header>
  <main>
    <section><h2>Sanitized Text</h2><p>{html.escape(text)}</p></section>
    <section><h2>Tables</h2>{''.join(rows) if rows else '<p>No tables detected.</p>'}</section>
    <section><h2>Approved Virtual State</h2>{state_html}</section>
  </main>
</body>
</html>
"""


def _capture_chrome_screenshot(
    *,
    executable: str,
    html_path: Path,
    output_path: Path,
    artifact_dir: Path,
    width: int = 960,
    height: int = 720,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-browser-render-", dir=artifact_dir) as profile_dir:
        command = [
            executable,
            "--headless=new",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-gpu",
            "--disable-sync",
            "--disable-translate",
            "--hide-scrollbars",
            "--mute-audio",
            "--no-first-run",
            "--no-default-browser-check",
            f"--user-data-dir={profile_dir}",
            f"--window-size={width},{height}",
            f"--screenshot={output_path}",
            html_path.resolve().as_uri(),
        ]
        try:
            completed = subprocess.run(command, cwd=artifact_dir, capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "width": width, "height": height, "exit_code": None, "error": str(exc)}
    ok = completed.returncode == 0 and output_path.exists() and output_path.stat().st_size > 0
    return {
        "ok": ok,
        "width": width,
        "height": height,
        "exit_code": completed.returncode,
        "error": None if ok else str(redact((completed.stderr or completed.stdout or "render failed")[:500])),
    }


def _live_browser_url_check(url: str, *, allowlist: tuple[str, ...]) -> dict[str, Any]:
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    validation_error = _validate_url(parsed)
    if validation_error:
        return {"ok": False, "domain": domain, "reason": validation_error}
    if not any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowlist):
        return {"ok": False, "domain": domain, "reason": f"domain {domain!r} is not allowlisted"}
    private_error = _private_network_error(domain)
    if private_error:
        return {"ok": False, "domain": domain, "reason": private_error}
    return {"ok": True, "domain": domain, "reason": None}


def _capture_live_chromium_snapshot(
    *,
    executable: str,
    url: str,
    output_path: Path,
    artifact_dir: Path,
    allowlist: tuple[str, ...],
    width: int = 1280,
    height: int = 900,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-browser-live-", dir=artifact_dir) as profile_dir:
        command = [
            executable,
            "--headless=new",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-gpu",
            "--disable-notifications",
            "--disable-popup-blocking",
            "--disable-sync",
            "--disable-translate",
            "--hide-scrollbars",
            "--mute-audio",
            "--no-first-run",
            "--no-default-browser-check",
            "--deny-permission-prompts",
            "--blink-settings=scriptEnabled=false,imagesEnabled=false",
            "--disable-features=AutofillServerCommunication,OptimizationHints,MediaRouter,Translate",
            f"--host-resolver-rules={_chrome_host_resolver_rules(allowlist)}",
            f"--user-data-dir={profile_dir}",
            f"--window-size={width},{height}",
            f"--screenshot={output_path}",
            url,
        ]
        try:
            completed = subprocess.run(command, cwd=artifact_dir, capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "width": width, "height": height, "exit_code": None, "error": str(redact(str(exc)[:500]))}
    ok = completed.returncode == 0 and output_path.exists() and output_path.stat().st_size > 0
    return {
        "ok": ok,
        "width": width,
        "height": height,
        "exit_code": completed.returncode,
        "error": None if ok else str(redact((completed.stderr or completed.stdout or "live browser capture failed")[:500])),
    }


def _chrome_host_resolver_rules(allowlist: tuple[str, ...]) -> str:
    excludes = []
    for host in allowlist:
        normalized = str(host).strip().lower()
        if not normalized:
            continue
        excludes.append(f"EXCLUDE {normalized}")
        if not normalized.startswith("*."):
            excludes.append(f"EXCLUDE *.{normalized}")
    if not excludes:
        return "MAP * 0.0.0.0"
    return ", ".join(["MAP * 0.0.0.0", *excludes])


def _browser_live_read_sandbox_receipt(*, executable: str, exit_code: int | None, allowlist: tuple[str, ...]) -> dict[str, Any]:
    return {
        "sandbox_profile": "live_chromium_readonly_ephemeral_profile",
        "adapter": "headless-chromium-readonly",
        "ambient_workspace_read": False,
        "ambient_network": "main_frame_allowlist_with_best_effort_subresource_blocking",
        "navigation_network": "main_frame_allowlist_only",
        "network_allowlist": list(allowlist),
        "remote_subresources_allowed": False,
        "remote_subresources_loaded": False,
        "cookies_persisted": False,
        "cookie_jar_persisted": False,
        "local_storage_persisted": False,
        "session_storage_persisted": False,
        "javascript_executed": False,
        "page_javascript_allowed": False,
        "original_page_dom_returned": False,
        "dom_renderer_used": True,
        "real_selector_events_dispatched": False,
        "real_page_mutation_allowed": False,
        "downloads_allowed": False,
        "uploads_allowed": False,
        "renderer": Path(executable).name,
        "renderer_exit_code": exit_code,
        "raw_secret_capture_allowed": False,
        "writes_confined_to": ".aegis/browser",
    }


def _browser_live_read_evidence(
    session: dict[str, Any],
    *,
    action: str,
    url: str,
    result: dict[str, Any],
    artifact_hashes: dict[str, str],
    sandbox_receipt: dict[str, Any],
) -> dict[str, Any]:
    return {
        "evidence_schema": "aegis.browser.live_read_evidence.v1",
        "captured_at": now_utc(),
        "session_id": str(session.get("id", "")),
        "action": action,
        "url": _redacted_string(url, limit=2000),
        "url_sha256": hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest(),
        "capture_surface": "live_browser_readonly_screenshot",
        "rendering_status": "rendered" if result.get("ok") else "render_failed",
        "mode": "live_chromium_readonly_no_persistent_state",
        "content_returned": False,
        "raw_browser_content_included": False,
        "raw_secret_values_included": False,
        "raw_cookie_values_included": False,
        "raw_storage_values_included": False,
        "model_invocation_performed": False,
        "width": result.get("width"),
        "height": result.get("height"),
        "artifact_hashes": dict(artifact_hashes),
        "sandbox_receipt": sandbox_receipt,
        "automation_boundaries": {
            **_browser_automation_boundaries(rendered=True),
            "capture_surface": "live_browser_readonly_screenshot",
            "navigation_network": "main_frame_allowlist_only",
            "virtual_interactions_only": False,
            "dom_renderer_used": True,
            "real_selector_events_dispatched": False,
            "real_page_mutation_allowed": False,
        },
        "error": result.get("error"),
    }


def _capture_live_chromium_mutation(
    *,
    executable: str,
    url: str,
    action: str,
    selector: str | None,
    fields: dict[str, str],
    output_path: Path,
    artifact_dir: Path,
    allowlist: tuple[str, ...],
    width: int = 1280,
    height: int = 900,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-browser-mutation-", dir=artifact_dir) as profile_dir:
        command = [
            executable,
            "--headless=new",
            "--remote-debugging-port=0",
            "--remote-allow-origins=*",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-gpu",
            "--disable-notifications",
            "--disable-popup-blocking",
            "--disable-sync",
            "--disable-translate",
            "--hide-scrollbars",
            "--mute-audio",
            "--no-first-run",
            "--no-default-browser-check",
            "--deny-permission-prompts",
            "--disable-features=AutofillServerCommunication,OptimizationHints,MediaRouter,Translate",
            f"--host-resolver-rules={_chrome_host_resolver_rules(allowlist)}",
            f"--user-data-dir={profile_dir}",
            f"--window-size={width},{height}",
            "about:blank",
        ]
        process: subprocess.Popen[str] | None = None
        client: _CdpClient | None = None
        try:
            process = subprocess.Popen(command, cwd=artifact_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            port = _read_devtools_port(Path(profile_dir), timeout=8)
            target = _create_cdp_target(port, url)
            websocket_url = str(target.get("webSocketDebuggerUrl") or "")
            if not websocket_url:
                raise RuntimeError("Chrome DevTools target did not expose a websocket URL")
            client = _CdpClient(websocket_url, timeout=8)
            client.call("Page.enable")
            client.call("Runtime.enable")
            client.call("Network.enable")
            _try_cdp(client, "Browser.setDownloadBehavior", {"behavior": "deny"})
            client.call("Page.navigate", {"url": url})
            client.wait_for("Page.loadEventFired", timeout=10)
            action_result = client.evaluate(_live_mutation_expression(action=action, selector=selector, fields=fields), timeout=8)
            time.sleep(0.5)
            url_after = client.evaluate("location.href", timeout=5)
            title = client.evaluate("document.title || ''", timeout=5)
            screenshot = client.call("Page.captureScreenshot", {"format": "png", "fromSurface": True}, timeout=10)
            data = screenshot.get("data") if isinstance(screenshot, dict) else None
            if isinstance(data, str) and data:
                output_path.write_bytes(base64.b64decode(data))
            ok = bool(isinstance(action_result, dict) and action_result.get("ok")) and output_path.exists() and output_path.stat().st_size > 0
            return {
                "ok": ok,
                "status": str(action_result.get("status") if isinstance(action_result, dict) else "mutation_failed"),
                "width": width,
                "height": height,
                "exit_code": process.poll(),
                "url_after": _redacted_string(url_after, limit=2000) if isinstance(url_after, str) else _redacted_string(url, limit=2000),
                "title": _redacted_string(title, limit=200) if isinstance(title, str) else "",
                "action_result": action_result if isinstance(action_result, dict) else {"ok": False, "status": "invalid_action_result"},
                "download_policy_applied": True,
                "error": None if ok else str(redact(json.dumps(action_result, sort_keys=True, default=str)[:500] if isinstance(action_result, dict) else "live browser mutation failed")),
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": "mutation_failed",
                "width": width,
                "height": height,
                "exit_code": process.poll() if process else None,
                "url_after": _redacted_string(url, limit=2000),
                "title": "",
                "action_result": {"ok": False, "status": "mutation_failed"},
                "download_policy_applied": False,
                "error": str(redact(str(exc)[:500])),
            }
        finally:
            if client is not None:
                client.close()
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _capture_live_chromium_download(
    *,
    executable: str,
    url: str,
    selector: str,
    output_path: Path,
    screenshot_path: Path,
    artifact_dir: Path,
    allowlist: tuple[str, ...],
    width: int = 1280,
    height: int = 900,
    max_bytes: int = _MAX_LIVE_BROWSER_DOWNLOAD_BYTES,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-browser-download-", dir=artifact_dir) as profile_dir:
        download_dir = Path(profile_dir) / "downloads"
        download_dir.mkdir(mode=0o700, exist_ok=True)
        for artifact_path in (output_path, screenshot_path):
            try:
                if artifact_path.exists():
                    artifact_path.unlink()
            except OSError:
                pass
        command = [
            executable,
            "--headless=new",
            "--remote-debugging-port=0",
            "--remote-allow-origins=*",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-gpu",
            "--disable-notifications",
            "--disable-popup-blocking",
            "--disable-sync",
            "--disable-translate",
            "--hide-scrollbars",
            "--mute-audio",
            "--no-first-run",
            "--no-default-browser-check",
            "--deny-permission-prompts",
            "--disable-features=AutofillServerCommunication,OptimizationHints,MediaRouter,Translate",
            f"--host-resolver-rules={_chrome_host_resolver_rules(allowlist)}",
            f"--user-data-dir={profile_dir}",
            f"--window-size={width},{height}",
            "about:blank",
        ]
        process: subprocess.Popen[str] | None = None
        client: _CdpClient | None = None
        try:
            process = subprocess.Popen(command, cwd=artifact_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            port = _read_devtools_port(Path(profile_dir), timeout=8)
            target = _create_cdp_target(port, url)
            websocket_url = str(target.get("webSocketDebuggerUrl") or "")
            if not websocket_url:
                raise RuntimeError("Chrome DevTools target did not expose a websocket URL")
            client = _CdpClient(websocket_url, timeout=8)
            client.call("Page.enable")
            client.call("Runtime.enable")
            client.call("Network.enable")
            download_policy_applied = _try_cdp(client, "Browser.setDownloadBehavior", {"behavior": "allow", "downloadPath": str(download_dir), "eventsEnabled": True})
            client.call("Page.navigate", {"url": url})
            client.wait_for("Page.loadEventFired", timeout=10)
            action_result = client.evaluate(_live_download_expression(selector=selector), timeout=8)
            action_ok = bool(isinstance(action_result, dict) and action_result.get("ok"))
            if not action_ok:
                url_after = client.evaluate("location.href", timeout=5)
                title = client.evaluate("document.title || ''", timeout=5)
                status = str(action_result.get("status") if isinstance(action_result, dict) else "download_action_failed")
                return {
                    "ok": False,
                    "status": status,
                    "width": width,
                    "height": height,
                    "exit_code": process.poll(),
                    "url_after": _redacted_string(url_after, limit=2000) if isinstance(url_after, str) else _redacted_string(url, limit=2000),
                    "title": _redacted_string(title, limit=200) if isinstance(title, str) else "",
                    "filename": "",
                    "mime_type": "",
                    "bytes": 0,
                    "download_domain": "",
                    "download_url_sha256": "",
                    "action_result": action_result if isinstance(action_result, dict) else {"ok": False, "status": "invalid_action_result"},
                    "download_policy_applied": download_policy_applied,
                    "error": status,
                }
            download_event = client.wait_for_event("Browser.downloadWillBegin", timeout=8)
            download_url = str(download_event.get("url") or "")
            download_guid = str(download_event.get("guid") or "")
            download_url_sha256 = hashlib.sha256(download_url.encode("utf-8", errors="replace")).hexdigest() if download_url else ""
            download_url_check = _live_browser_url_check(download_url, allowlist=allowlist) if download_url else {"ok": False, "domain": "", "reason": "download URL was not reported by the browser"}
            if not download_url_check["ok"]:
                if download_guid:
                    _try_cdp(client, "Browser.cancelDownload", {"guid": download_guid})
                url_after = client.evaluate("location.href", timeout=5)
                title = client.evaluate("document.title || ''", timeout=5)
                return {
                    "ok": False,
                    "status": "download_url_blocked" if download_url else "download_url_missing",
                    "width": width,
                    "height": height,
                    "exit_code": process.poll(),
                    "url_after": _redacted_string(url_after, limit=2000) if isinstance(url_after, str) else _redacted_string(url, limit=2000),
                    "title": _redacted_string(title, limit=200) if isinstance(title, str) else "",
                    "filename": _safe_download_filename(download_event.get("suggestedFilename") or ""),
                    "mime_type": "",
                    "bytes": 0,
                    "download_domain": str(download_url_check.get("domain") or ""),
                    "download_url_sha256": download_url_sha256,
                    "action_result": action_result if isinstance(action_result, dict) else {"ok": False, "status": "invalid_action_result"},
                    "download_policy_applied": download_policy_applied,
                    "error": str(redact(str(download_url_check.get("reason") or "download URL blocked")[:500])),
                }
            download = _wait_for_chromium_download(download_dir, timeout=15, max_bytes=max_bytes)
            url_after = client.evaluate("location.href", timeout=5)
            title = client.evaluate("document.title || ''", timeout=5)
            screenshot = client.call("Page.captureScreenshot", {"format": "png", "fromSurface": True}, timeout=10)
            data = screenshot.get("data") if isinstance(screenshot, dict) else None
            if isinstance(data, str) and data:
                screenshot_path.write_bytes(base64.b64decode(data))
            if download["ok"] and isinstance(download.get("path"), Path):
                if output_path.exists():
                    output_path.unlink()
                shutil.move(str(download["path"]), output_path)
            ok = bool(isinstance(action_result, dict) and action_result.get("ok")) and bool(download["ok"]) and output_path.exists() and output_path.stat().st_size > 0
            filename = _safe_download_filename(download_event.get("suggestedFilename") or download.get("filename") or output_path.name)
            mime_type = _live_download_mime_type(output_path, filename=filename) if output_path.exists() else ""
            if ok and mime_type not in _ALLOWED_LIVE_BROWSER_DOWNLOAD_MIME_TYPES:
                byte_count = output_path.stat().st_size
                try:
                    output_path.unlink()
                except OSError:
                    pass
                return {
                    "ok": False,
                    "status": "unsupported_download_type",
                    "width": width,
                    "height": height,
                    "exit_code": process.poll(),
                    "url_after": _redacted_string(url_after, limit=2000) if isinstance(url_after, str) else _redacted_string(url, limit=2000),
                    "title": _redacted_string(title, limit=200) if isinstance(title, str) else "",
                    "filename": filename,
                    "mime_type": mime_type,
                    "bytes": byte_count,
                    "download_domain": str(download_url_check.get("domain") or ""),
                    "download_url_sha256": download_url_sha256,
                    "action_result": action_result if isinstance(action_result, dict) else {"ok": False, "status": "invalid_action_result"},
                    "download_policy_applied": download_policy_applied,
                    "error": "download MIME type is not allowed",
                }
            return {
                "ok": ok,
                "status": "downloaded" if ok else str(download.get("status") or "download_failed"),
                "width": width,
                "height": height,
                "exit_code": process.poll(),
                "url_after": _redacted_string(url_after, limit=2000) if isinstance(url_after, str) else _redacted_string(url, limit=2000),
                "title": _redacted_string(title, limit=200) if isinstance(title, str) else "",
                "filename": filename,
                "mime_type": mime_type,
                "bytes": output_path.stat().st_size if output_path.exists() else _safe_int(download.get("bytes")),
                "download_domain": str(download_url_check.get("domain") or ""),
                "download_url_sha256": download_url_sha256,
                "action_result": action_result if isinstance(action_result, dict) else {"ok": False, "status": "invalid_action_result"},
                "download_policy_applied": download_policy_applied,
                "error": None if ok else str(redact(str(download.get("error") or download.get("status") or "live browser download failed")[:500])),
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": "download_failed",
                "width": width,
                "height": height,
                "exit_code": process.poll() if process else None,
                "url_after": _redacted_string(url, limit=2000),
                "title": "",
                "filename": "",
                "mime_type": "",
                "bytes": 0,
                "download_domain": "",
                "download_url_sha256": "",
                "action_result": {"ok": False, "status": "download_failed"},
                "download_policy_applied": False,
                "error": str(redact(str(exc)[:500])),
            }
        finally:
            if client is not None:
                client.close()
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _capture_live_chromium_upload(
    *,
    executable: str,
    url: str,
    selector: str,
    source_path: Path,
    screenshot_path: Path,
    artifact_dir: Path,
    allowlist: tuple[str, ...],
    width: int = 1280,
    height: int = 900,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-browser-upload-", dir=artifact_dir) as profile_dir:
        try:
            if screenshot_path.exists():
                screenshot_path.unlink()
        except OSError:
            pass
        command = [
            executable,
            "--headless=new",
            "--remote-debugging-port=0",
            "--remote-allow-origins=*",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-gpu",
            "--disable-notifications",
            "--disable-popup-blocking",
            "--disable-sync",
            "--disable-translate",
            "--hide-scrollbars",
            "--mute-audio",
            "--no-first-run",
            "--no-default-browser-check",
            "--deny-permission-prompts",
            "--disable-features=AutofillServerCommunication,OptimizationHints,MediaRouter,Translate",
            f"--host-resolver-rules={_chrome_host_resolver_rules(allowlist)}",
            f"--user-data-dir={profile_dir}",
            f"--window-size={width},{height}",
            "about:blank",
        ]
        process: subprocess.Popen[str] | None = None
        client: _CdpClient | None = None
        try:
            process = subprocess.Popen(command, cwd=artifact_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            port = _read_devtools_port(Path(profile_dir), timeout=8)
            target = _create_cdp_target(port, url)
            websocket_url = str(target.get("webSocketDebuggerUrl") or "")
            if not websocket_url:
                raise RuntimeError("Chrome DevTools target did not expose a websocket URL")
            client = _CdpClient(websocket_url, timeout=8)
            client.call("Page.enable")
            client.call("Runtime.enable")
            client.call("Network.enable")
            client.call("DOM.enable")
            _try_cdp(client, "Browser.setDownloadBehavior", {"behavior": "deny"})
            client.call("Page.navigate", {"url": url})
            client.wait_for("Page.loadEventFired", timeout=10)
            verify_result = client.evaluate(_live_upload_verify_expression(selector=selector), timeout=5)
            if not (isinstance(verify_result, dict) and verify_result.get("ok")):
                url_after = client.evaluate("location.href", timeout=5)
                title = client.evaluate("document.title || ''", timeout=5)
                return {
                    "ok": False,
                    "status": str(verify_result.get("status") if isinstance(verify_result, dict) else "file_input_not_found"),
                    "width": width,
                    "height": height,
                    "exit_code": process.poll(),
                    "url_after": _redacted_string(url_after, limit=2000) if isinstance(url_after, str) else _redacted_string(url, limit=2000),
                    "title": _redacted_string(title, limit=200) if isinstance(title, str) else "",
                    "action_result": verify_result if isinstance(verify_result, dict) else {"ok": False, "status": "invalid_action_result"},
                    "error": str(verify_result.get("status") if isinstance(verify_result, dict) else "file input not found"),
                }
            document = client.call("DOM.getDocument", {"depth": 1, "pierce": True}, timeout=5)
            root = document.get("root") if isinstance(document, dict) else {}
            root_node_id = int(root.get("nodeId") or 0) if isinstance(root, dict) else 0
            node = client.call("DOM.querySelector", {"nodeId": root_node_id, "selector": selector}, timeout=5)
            node_id = int(node.get("nodeId") or 0) if isinstance(node, dict) else 0
            if node_id <= 0:
                raise RuntimeError("file input selector was not found after verification")
            client.call("DOM.setFileInputFiles", {"nodeId": node_id, "files": [str(source_path)]}, timeout=8)
            action_result = client.evaluate(_live_upload_finalize_expression(selector=selector), timeout=8)
            url_after = client.evaluate("location.href", timeout=5)
            title = client.evaluate("document.title || ''", timeout=5)
            screenshot = client.call("Page.captureScreenshot", {"format": "png", "fromSurface": True}, timeout=10)
            data = screenshot.get("data") if isinstance(screenshot, dict) else None
            if isinstance(data, str) and data:
                screenshot_path.write_bytes(base64.b64decode(data))
            ok = bool(isinstance(action_result, dict) and action_result.get("ok"))
            return {
                "ok": ok,
                "status": "uploaded" if ok else str(action_result.get("status") if isinstance(action_result, dict) else "upload_failed"),
                "width": width,
                "height": height,
                "exit_code": process.poll(),
                "url_after": _redacted_string(url_after, limit=2000) if isinstance(url_after, str) else _redacted_string(url, limit=2000),
                "title": _redacted_string(title, limit=200) if isinstance(title, str) else "",
                "action_result": action_result if isinstance(action_result, dict) else {"ok": False, "status": "invalid_action_result"},
                "error": None if ok else str(redact(str(action_result.get("status") if isinstance(action_result, dict) else "live browser upload failed")[:500])),
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": "upload_failed",
                "width": width,
                "height": height,
                "exit_code": process.poll() if process else None,
                "url_after": _redacted_string(url, limit=2000),
                "title": "",
                "action_result": {"ok": False, "status": "upload_failed"},
                "error": str(redact(str(exc)[:500])),
            }
        finally:
            if client is not None:
                client.close()
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _wait_for_chromium_download(download_dir: Path, *, timeout: float, max_bytes: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_path: Path | None = None
    last_size = -1
    stable_since: float | None = None
    while time.monotonic() < deadline:
        files = [path for path in download_dir.iterdir() if path.is_file()]
        partials = [path for path in files if path.name.endswith(".crdownload")]
        completed = [path for path in files if not path.name.endswith(".crdownload")]
        if completed:
            candidate = max(completed, key=lambda path: path.stat().st_mtime)
            size = candidate.stat().st_size
            if size > max_bytes:
                try:
                    candidate.unlink()
                except OSError:
                    pass
                return {"ok": False, "status": "download_too_large", "filename": candidate.name, "bytes": size, "error": "download exceeded size limit"}
            if not partials and candidate == last_path and size == last_size:
                if stable_since is None:
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= 0.3:
                    return {"ok": True, "status": "downloaded", "path": candidate, "filename": candidate.name, "bytes": size}
            else:
                last_path = candidate
                last_size = size
                stable_since = None
        time.sleep(0.1)
    return {"ok": False, "status": "download_timeout", "filename": "", "bytes": 0, "error": "download did not complete before timeout"}


def _safe_download_filename(value: Any) -> str:
    raw = Path(str(value or "download.bin")).name
    safe = "".join(char if char.isalnum() or char in {".", "-", "_"} else "_" for char in raw)[:160].strip("._")
    return safe or "download.bin"


def _path_hash(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="replace")).hexdigest()


def _live_upload_source_check(value: Any, *, workspace_root: Path) -> dict[str, Any]:
    path_hash = _path_hash(value)
    if not value:
        return {"ok": False, "reason": "missing upload source path", "path_sha256": path_hash, "filename": "", "bytes": 0, "mime_type": "", "sha256": ""}
    raw_path = Path(str(value)).expanduser()
    candidate = raw_path if raw_path.is_absolute() else workspace_root / raw_path
    try:
        candidate = candidate.resolve()
    except OSError as exc:
        return {"ok": False, "reason": str(exc), "path_sha256": path_hash, "filename": raw_path.name, "bytes": 0, "mime_type": "", "sha256": ""}
    resolved_path_hash = hashlib.sha256(str(candidate).encode("utf-8", errors="replace")).hexdigest()
    if workspace_root not in (candidate, *candidate.parents):
        return {"ok": False, "reason": "upload source path escapes workspace root", "path_sha256": resolved_path_hash, "filename": candidate.name, "bytes": 0, "mime_type": "", "sha256": ""}
    if not candidate.is_file():
        return {"ok": False, "reason": "upload source path is not a file", "path_sha256": resolved_path_hash, "filename": candidate.name, "bytes": 0, "mime_type": "", "sha256": ""}
    size = candidate.stat().st_size
    if size <= 0:
        return {"ok": False, "reason": "upload source file is empty", "path_sha256": resolved_path_hash, "filename": candidate.name, "bytes": size, "mime_type": "", "sha256": ""}
    if size > _MAX_LIVE_BROWSER_UPLOAD_BYTES:
        return {"ok": False, "reason": "upload source exceeds size limit", "path_sha256": resolved_path_hash, "filename": candidate.name, "bytes": size, "mime_type": "", "sha256": ""}
    mime_type = _live_download_mime_type(candidate, filename=candidate.name)
    if mime_type not in _ALLOWED_LIVE_BROWSER_UPLOAD_MIME_TYPES:
        return {"ok": False, "reason": "upload source MIME type is not allowed", "path_sha256": resolved_path_hash, "filename": candidate.name, "bytes": size, "mime_type": mime_type, "sha256": ""}
    return {
        "ok": True,
        "reason": None,
        "path": candidate,
        "path_sha256": resolved_path_hash,
        "filename": _safe_download_filename(candidate.name),
        "bytes": size,
        "mime_type": mime_type,
        "sha256": _file_sha256(candidate),
    }


def _live_download_mime_type(path: Path, *, filename: str) -> str:
    try:
        with path.open("rb") as handle:
            sample = handle.read(_MAX_LIVE_BROWSER_DOWNLOAD_MIME_SAMPLE_BYTES)
    except OSError:
        return "application/octet-stream"
    if sample.startswith(b"%PDF-"):
        return "application/pdf"
    if sample.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if sample.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(sample) >= 12 and sample[:4] == b"RIFF" and sample[8:12] == b"WEBP":
        return "image/webp"
    if _looks_like_utf8_text(sample):
        suffix = Path(filename).suffix.lower()
        if suffix == ".csv":
            return "text/csv"
        if suffix == ".json":
            return "application/json"
        return "text/plain"
    return "application/octet-stream"


def _looks_like_utf8_text(sample: bytes) -> bool:
    if not sample or b"\x00" in sample:
        return False
    try:
        text = sample.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    if not text:
        return False
    control_chars = sum(1 for char in text if ord(char) < 32 and char not in "\t\r\n")
    return control_chars / max(1, len(text)) < 0.02


def _read_devtools_port(profile_dir: Path, *, timeout: float) -> int:
    active_port = profile_dir / "DevToolsActivePort"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if active_port.exists():
            lines = active_port.read_text(encoding="utf-8", errors="replace").splitlines()
            if lines:
                return int(lines[0])
        time.sleep(0.05)
    raise TimeoutError("Chrome DevTools port was not published")


def _create_cdp_target(port: int, url: str) -> dict[str, Any]:
    encoded_url = quote(url, safe=":/?&=%#[]@!$'()*+,;")
    request = urllib_request.Request(f"http://127.0.0.1:{port}/json/new?{encoded_url}", method="PUT")
    with urllib_request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Chrome DevTools target response was not an object")
    return payload


def _try_cdp(client: "_CdpClient", method: str, params: dict[str, Any]) -> bool:
    try:
        client.call(method, params, timeout=3)
        return True
    except Exception:
        return False


def _live_mutation_expression(*, action: str, selector: str | None, fields: dict[str, str]) -> str:
    selector_json = json.dumps(selector or "", ensure_ascii=False)
    fields_json = json.dumps(fields, ensure_ascii=False)
    return f"""
(() => {{
  const redact = (value) => String(value || '').slice(0, 300);
  const safeElement = (element) => {{
    if (!element) return null;
    const rect = element.getBoundingClientRect();
    return {{
      tag: redact(element.tagName ? element.tagName.toLowerCase() : ''),
      id: redact(element.id || ''),
      name: redact(element.getAttribute('name') || ''),
      type: redact(element.getAttribute('type') || ''),
      role: redact(element.getAttribute('role') || ''),
      href_present: Boolean(element.getAttribute('href')),
      rect: {{ x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) }}
    }};
  }};
  const action = {json.dumps(action)};
  const selector = {selector_json};
  const fields = {fields_json};
  const before = location.href;
  if (action === 'live_click') {{
    const element = document.querySelector(selector);
    if (!element) return {{ ok: false, status: 'selector_not_found', selector }};
    element.scrollIntoView({{ block: 'center', inline: 'center' }});
    element.dispatchEvent(new MouseEvent('mouseover', {{ bubbles: true, cancelable: true, view: window }}));
    element.dispatchEvent(new MouseEvent('mousedown', {{ bubbles: true, cancelable: true, view: window }}));
    element.dispatchEvent(new MouseEvent('mouseup', {{ bubbles: true, cancelable: true, view: window }}));
    element.click();
    return {{ ok: true, status: 'clicked', selector, element: safeElement(element), url_before: before, url_after: location.href }};
  }}
  if (action === 'live_fill') {{
    const selectors = Object.keys(fields);
    const results = [];
    for (const itemSelector of selectors) {{
      const element = document.querySelector(itemSelector);
      if (!element) {{
        results.push({{ selector: itemSelector, status: 'selector_not_found' }});
        continue;
      }}
      element.scrollIntoView({{ block: 'center', inline: 'center' }});
      element.focus();
      const value = String(fields[itemSelector] ?? '');
      if ('value' in element) {{
        element.value = value;
      }} else {{
        element.textContent = value;
      }}
      element.dispatchEvent(new Event('input', {{ bubbles: true }}));
      element.dispatchEvent(new Event('change', {{ bubbles: true }}));
      results.push({{ selector: itemSelector, status: 'filled', element: safeElement(element) }});
    }}
    const filled = results.filter((item) => item.status === 'filled').length;
    return {{ ok: filled > 0 && filled === selectors.length, status: filled === selectors.length ? 'filled' : 'partial_fill', field_count: selectors.length, filled_count: filled, results, url_before: before, url_after: location.href }};
  }}
  if (action === 'live_submit') {{
    let element = selector ? document.querySelector(selector) : document.querySelector('form');
    if (!element) return {{ ok: false, status: 'selector_not_found', selector }};
    const form = element.tagName && element.tagName.toLowerCase() === 'form' ? element : element.closest('form');
    if (!form) return {{ ok: false, status: 'form_not_found', selector, element: safeElement(element) }};
    form.scrollIntoView({{ block: 'center', inline: 'center' }});
    if (typeof form.requestSubmit === 'function') {{
      form.requestSubmit();
    }} else {{
      form.submit();
    }}
    return {{ ok: true, status: 'submitted', selector: selector || '', element: safeElement(form), url_before: before, url_after: location.href }};
  }}
  return {{ ok: false, status: 'unsupported_action' }};
}})()
""".strip()


def _live_download_expression(*, selector: str) -> str:
    selector_json = json.dumps(selector or "", ensure_ascii=False)
    return f"""
(() => {{
  const redact = (value) => String(value || '').slice(0, 300);
  const safeElement = (element) => {{
    if (!element) return null;
    const rect = element.getBoundingClientRect();
    return {{
      tag: redact(element.tagName ? element.tagName.toLowerCase() : ''),
      id: redact(element.id || ''),
      name: redact(element.getAttribute('name') || ''),
      type: redact(element.getAttribute('type') || ''),
      role: redact(element.getAttribute('role') || ''),
      href_present: Boolean(element.getAttribute('href')),
      download_attr_present: Boolean(element.getAttribute('download')),
      rect: {{ x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) }}
    }};
  }};
  const selector = {selector_json};
  const before = location.href;
  const element = document.querySelector(selector);
  if (!element) return {{ ok: false, status: 'selector_not_found', selector }};
  element.scrollIntoView({{ block: 'center', inline: 'center' }});
  element.dispatchEvent(new MouseEvent('mouseover', {{ bubbles: true, cancelable: true, view: window }}));
  element.dispatchEvent(new MouseEvent('mousedown', {{ bubbles: true, cancelable: true, view: window }}));
  element.dispatchEvent(new MouseEvent('mouseup', {{ bubbles: true, cancelable: true, view: window }}));
  element.click();
  return {{ ok: true, status: 'clicked_for_download', selector, element: safeElement(element), url_before: before, url_after: location.href }};
}})()
""".strip()


def _live_upload_verify_expression(*, selector: str) -> str:
    selector_json = json.dumps(selector or "", ensure_ascii=False)
    return f"""
(() => {{
  const selector = {selector_json};
  const element = document.querySelector(selector);
  if (!element) return {{ ok: false, status: 'selector_not_found', selector }};
  const tag = element.tagName ? element.tagName.toLowerCase() : '';
  const type = String(element.getAttribute('type') || '').toLowerCase();
  if (tag !== 'input' || type !== 'file') return {{ ok: false, status: 'not_file_input', selector, tag, type }};
  const rect = element.getBoundingClientRect();
  return {{
    ok: true,
    status: 'file_input_ready',
    selector,
    element: {{
      tag,
      type,
      id: String(element.id || '').slice(0, 300),
      name: String(element.getAttribute('name') || '').slice(0, 300),
      accept: String(element.getAttribute('accept') || '').slice(0, 300),
      multiple: Boolean(element.multiple),
      rect: {{ x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) }}
    }},
    url_before: location.href
  }};
}})()
""".strip()


def _live_upload_finalize_expression(*, selector: str) -> str:
    selector_json = json.dumps(selector or "", ensure_ascii=False)
    return f"""
(() => {{
  const selector = {selector_json};
  const element = document.querySelector(selector);
  if (!element) return {{ ok: false, status: 'selector_not_found', selector }};
  const fileCount = element.files ? element.files.length : 0;
  element.dispatchEvent(new Event('input', {{ bubbles: true }}));
  element.dispatchEvent(new Event('change', {{ bubbles: true }}));
  const rect = element.getBoundingClientRect();
  return {{
    ok: fileCount === 1,
    status: fileCount === 1 ? 'uploaded' : 'file_not_attached',
    selector,
    file_count: fileCount,
    element: {{
      tag: element.tagName ? element.tagName.toLowerCase() : '',
      type: String(element.getAttribute('type') || '').toLowerCase(),
      id: String(element.id || '').slice(0, 300),
      name: String(element.getAttribute('name') || '').slice(0, 300),
      accept: String(element.getAttribute('accept') || '').slice(0, 300),
      multiple: Boolean(element.multiple),
      rect: {{ x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) }}
    }},
    url_after: location.href
  }};
}})()
""".strip()


class _CdpClient:
    def __init__(self, websocket_url: str, *, timeout: float) -> None:
        parsed = urlparse(websocket_url)
        if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("Chrome DevTools websocket must be local ws://")
        self.host = parsed.hostname
        self.port = int(parsed.port or 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path = f"{self.path}?{parsed.query}"
        self.socket = socket.create_connection((self.host, self.port), timeout=timeout)
        self.socket.settimeout(timeout)
        self._next_id = 0
        self._events: list[dict[str, Any]] = []
        self._handshake()

    def _handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode("ascii"))
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.socket.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 16384:
                break
        if b" 101 " not in response.split(b"\r\n", 1)[0]:
            raise RuntimeError("Chrome DevTools websocket handshake failed")

    def call(self, method: str, params: dict[str, Any] | None = None, *, timeout: float | None = None) -> dict[str, Any]:
        self._next_id += 1
        message_id = self._next_id
        self._send_json({"id": message_id, "method": method, "params": params or {}})
        deadline = time.monotonic() + (timeout or 10)
        while time.monotonic() < deadline:
            message = self._recv_json(deadline=deadline)
            if message.get("id") != message_id:
                self._queue_event(message)
                continue
            if "error" in message:
                raise RuntimeError(str(message["error"]))
            result = message.get("result")
            return result if isinstance(result, dict) else {}
        raise TimeoutError(f"Chrome DevTools call timed out: {method}")

    def evaluate(self, expression: str, *, timeout: float | None = None) -> Any:
        result = self.call("Runtime.evaluate", {"expression": expression, "returnByValue": True, "awaitPromise": True}, timeout=timeout)
        if "exceptionDetails" in result:
            raise RuntimeError("Chrome Runtime.evaluate failed")
        remote = result.get("result")
        if isinstance(remote, dict) and "value" in remote:
            return remote["value"]
        if isinstance(remote, dict) and remote.get("type") == "undefined":
            return None
        return None

    def wait_for(self, method: str, *, timeout: float) -> bool:
        if self._pop_event(method) is not None:
            return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                message = self._recv_json(deadline=deadline)
            except TimeoutError:
                break
            if message.get("method") == method:
                return True
            self._queue_event(message)
        return False

    def wait_for_event(self, method: str, *, timeout: float) -> dict[str, Any]:
        queued = self._pop_event(method)
        if queued is not None:
            params = queued.get("params")
            return params if isinstance(params, dict) else {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                message = self._recv_json(deadline=deadline)
            except TimeoutError:
                break
            if message.get("method") == method:
                params = message.get("params")
                return params if isinstance(params, dict) else {}
            self._queue_event(message)
        return {}

    def _queue_event(self, message: dict[str, Any]) -> None:
        if isinstance(message.get("method"), str):
            self._events.append(message)
            self._events = self._events[-50:]

    def _pop_event(self, method: str) -> dict[str, Any] | None:
        for index, message in enumerate(self._events):
            if message.get("method") == method:
                return self._events.pop(index)
        return None

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass

    def _send_json(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        header = bytearray([0x81])
        length = len(data)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.extend([0x80 | 126, (length >> 8) & 0xFF, length & 0xFF])
        else:
            header.append(0x80 | 127)
            header.extend(length.to_bytes(8, "big"))
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
        self.socket.sendall(bytes(header) + mask + masked)

    def _recv_json(self, *, deadline: float) -> dict[str, Any]:
        while True:
            remaining = max(0.1, deadline - time.monotonic())
            self.socket.settimeout(remaining)
            frame = self._recv_frame()
            if frame is None:
                continue
            return json.loads(frame.decode("utf-8"))

    def _recv_frame(self) -> bytes | None:
        first = self._recv_exact(2)
        opcode = first[0] & 0x0F
        masked = bool(first[1] & 0x80)
        length = first[1] & 0x7F
        if length == 126:
            length = int.from_bytes(self._recv_exact(2), "big")
        elif length == 127:
            length = int.from_bytes(self._recv_exact(8), "big")
        mask = self._recv_exact(4) if masked else b""
        payload = self._recv_exact(length) if length else b""
        if masked:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        if opcode == 0x8:
            raise RuntimeError("Chrome DevTools websocket closed")
        if opcode == 0x9:
            self._send_pong(payload)
            return None
        if opcode != 0x1:
            return None
        return payload

    def _send_pong(self, payload: bytes) -> None:
        header = bytearray([0x8A])
        length = len(payload)
        header.append(0x80 | length)
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(bytes(header) + mask + masked)

    def _recv_exact(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.socket.recv(size - len(chunks))
            if not chunk:
                raise RuntimeError("Chrome DevTools websocket disconnected")
            chunks.extend(chunk)
        return bytes(chunks)


def _browser_live_mutation_sandbox_receipt(*, executable: str, exit_code: int | None, allowlist: tuple[str, ...]) -> dict[str, Any]:
    return {
        "sandbox_profile": "live_chromium_cdp_ephemeral_mutation",
        "adapter": "chromium-cdp-ephemeral-mutation",
        "ambient_workspace_read": False,
        "ambient_network": "allowlisted_browser_navigation_only",
        "navigation_network": "main_frame_allowlist_only",
        "network_allowlist": list(allowlist),
        "remote_subresources_allowed": "allowlisted_only",
        "remote_subresources_loaded": "allowlisted_only",
        "cookies_persisted": False,
        "cookie_jar_persisted": False,
        "local_storage_persisted": False,
        "session_storage_persisted": False,
        "javascript_executed": True,
        "page_javascript_allowed": True,
        "original_page_dom_returned": False,
        "dom_renderer_used": True,
        "real_selector_events_dispatched": True,
        "real_page_mutation_allowed": True,
        "downloads_allowed": False,
        "uploads_allowed": False,
        "renderer": Path(executable).name,
        "renderer_exit_code": exit_code,
        "raw_secret_capture_allowed": False,
        "writes_confined_to": ".aegis/browser",
    }


def _browser_live_download_sandbox_receipt(*, executable: str, exit_code: int | None, allowlist: tuple[str, ...]) -> dict[str, Any]:
    return {
        "sandbox_profile": "live_chromium_cdp_ephemeral_download",
        "adapter": "chromium-cdp-ephemeral-download",
        "ambient_workspace_read": False,
        "ambient_network": "allowlisted_browser_navigation_only",
        "navigation_network": "main_frame_allowlist_only",
        "network_allowlist": list(allowlist),
        "remote_subresources_allowed": "allowlisted_only",
        "remote_subresources_loaded": "allowlisted_only",
        "cookies_persisted": False,
        "cookie_jar_persisted": False,
        "local_storage_persisted": False,
        "session_storage_persisted": False,
        "javascript_executed": True,
        "page_javascript_allowed": True,
        "original_page_dom_returned": False,
        "dom_renderer_used": True,
        "real_selector_events_dispatched": True,
        "real_page_mutation_allowed": True,
        "downloads_allowed": True,
        "uploads_allowed": False,
        "file_chooser_allowed": False,
        "max_download_bytes": _MAX_LIVE_BROWSER_DOWNLOAD_BYTES,
        "renderer": Path(executable).name,
        "renderer_exit_code": exit_code,
        "raw_secret_capture_allowed": False,
        "raw_network_body_returned": False,
        "writes_confined_to": ".aegis/browser",
    }


def _browser_live_upload_sandbox_receipt(*, executable: str, exit_code: int | None, allowlist: tuple[str, ...]) -> dict[str, Any]:
    return {
        "sandbox_profile": "live_chromium_cdp_ephemeral_upload",
        "adapter": "chromium-cdp-ephemeral-upload",
        "ambient_workspace_read": False,
        "explicit_workspace_source_reads_only": True,
        "ambient_network": "allowlisted_browser_navigation_only",
        "navigation_network": "main_frame_allowlist_only",
        "network_allowlist": list(allowlist),
        "remote_subresources_allowed": "allowlisted_only",
        "remote_subresources_loaded": "allowlisted_only",
        "cookies_persisted": False,
        "cookie_jar_persisted": False,
        "local_storage_persisted": False,
        "session_storage_persisted": False,
        "javascript_executed": True,
        "page_javascript_allowed": True,
        "original_page_dom_returned": False,
        "dom_renderer_used": True,
        "real_selector_events_dispatched": True,
        "real_page_mutation_allowed": True,
        "downloads_allowed": False,
        "uploads_allowed": True,
        "file_chooser_allowed": True,
        "max_upload_bytes": _MAX_LIVE_BROWSER_UPLOAD_BYTES,
        "renderer": Path(executable).name,
        "renderer_exit_code": exit_code,
        "raw_secret_capture_allowed": False,
        "raw_network_body_returned": False,
        "writes_confined_to": ".aegis/browser",
    }


def _browser_live_mutation_evidence(
    session: dict[str, Any],
    *,
    action: str,
    url: str,
    selector: str | None,
    fields: dict[str, str],
    result: dict[str, Any],
    artifact_hashes: dict[str, str],
    sandbox_receipt: dict[str, Any],
) -> dict[str, Any]:
    return {
        "evidence_schema": "aegis.browser.live_mutation_evidence.v1",
        "captured_at": now_utc(),
        "session_id": str(session.get("id", "")),
        "action": action,
        "selector": _redacted_string(selector, limit=500) if selector is not None else None,
        "field_selectors": sorted(fields),
        "fields_sha256": hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() if fields else "",
        "url_before": _redacted_string(url, limit=2000),
        "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
        "url_sha256": hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest(),
        "capture_surface": "live_browser_selector_mutation",
        "rendering_status": "rendered" if result.get("ok") else "render_failed",
        "mode": "live_chromium_cdp_ephemeral_mutation",
        "content_returned": False,
        "raw_browser_content_included": False,
        "raw_secret_values_included": False,
        "raw_cookie_values_included": False,
        "raw_storage_values_included": False,
        "model_invocation_performed": False,
        "width": result.get("width"),
        "height": result.get("height"),
        "artifact_hashes": dict(artifact_hashes),
        "sandbox_receipt": sandbox_receipt,
        "automation_boundaries": _browser_automation_boundaries(rendered=True, live_mutation=True),
        "action_result": _safe_live_mutation_action_result(result.get("action_result")),
        "error": result.get("error"),
    }


def _browser_live_download_evidence(
    session: dict[str, Any],
    *,
    selector: str,
    url: str,
    result: dict[str, Any],
    artifact_hashes: dict[str, str],
    sandbox_receipt: dict[str, Any],
) -> dict[str, Any]:
    return {
        "evidence_schema": "aegis.browser.live_download_evidence.v1",
        "captured_at": now_utc(),
        "session_id": str(session.get("id", "")),
        "action": "live_download",
        "selector": _redacted_string(selector, limit=500),
        "url_before": _redacted_string(url, limit=2000),
        "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
        "url_sha256": hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest(),
        "capture_surface": "live_browser_private_download",
        "rendering_status": "rendered" if result.get("ok") else "render_failed",
        "mode": "live_chromium_cdp_ephemeral_download",
        "filename": _redacted_string(result.get("filename"), limit=200),
        "mime_type": _redacted_string(result.get("mime_type"), limit=120),
        "bytes": _safe_int(result.get("bytes")),
        "download_domain": _redacted_string(result.get("download_domain"), limit=255),
        "download_url_sha256": _redacted_string(result.get("download_url_sha256"), limit=64),
        "max_bytes": _MAX_LIVE_BROWSER_DOWNLOAD_BYTES,
        "content_returned": False,
        "raw_browser_content_included": False,
        "raw_secret_values_included": False,
        "raw_cookie_values_included": False,
        "raw_storage_values_included": False,
        "raw_network_body_returned": False,
        "model_invocation_performed": False,
        "width": result.get("width"),
        "height": result.get("height"),
        "artifact_hashes": dict(artifact_hashes),
        "sandbox_receipt": sandbox_receipt,
        "automation_boundaries": _browser_automation_boundaries(rendered=True, live_download=True),
        "action_result": _safe_live_download_action_result(result.get("action_result")),
        "error": result.get("error"),
    }


def _browser_live_upload_evidence(
    session: dict[str, Any],
    *,
    selector: str,
    url: str,
    source: dict[str, Any],
    result: dict[str, Any],
    artifact_hashes: dict[str, str],
    sandbox_receipt: dict[str, Any],
) -> dict[str, Any]:
    return {
        "evidence_schema": "aegis.browser.live_upload_evidence.v1",
        "captured_at": now_utc(),
        "session_id": str(session.get("id", "")),
        "action": "live_upload",
        "selector": _redacted_string(selector, limit=500),
        "url_before": _redacted_string(url, limit=2000),
        "url_after": _redacted_string(str(result.get("url_after") or url), limit=2000),
        "url_sha256": hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest(),
        "capture_surface": "live_browser_private_upload",
        "rendering_status": "rendered" if result.get("ok") else "render_failed",
        "mode": "live_chromium_cdp_ephemeral_upload",
        "source_filename": _redacted_string(source.get("filename"), limit=200),
        "source_mime_type": _redacted_string(source.get("mime_type"), limit=120),
        "source_bytes": _safe_int(source.get("bytes")),
        "source_sha256": _redacted_string(source.get("sha256"), limit=64),
        "source_path_sha256": _redacted_string(source.get("path_sha256"), limit=64),
        "max_upload_bytes": _MAX_LIVE_BROWSER_UPLOAD_BYTES,
        "content_returned": False,
        "raw_browser_content_included": False,
        "raw_secret_values_included": False,
        "raw_cookie_values_included": False,
        "raw_storage_values_included": False,
        "raw_network_body_returned": False,
        "model_invocation_performed": False,
        "width": result.get("width"),
        "height": result.get("height"),
        "artifact_hashes": dict(artifact_hashes),
        "sandbox_receipt": sandbox_receipt,
        "automation_boundaries": _browser_automation_boundaries(rendered=True, live_upload=True),
        "action_result": _safe_live_upload_action_result(result.get("action_result")),
        "error": result.get("error"),
    }


def _safe_live_mutation_action_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    allowed_scalar_keys = {"ok", "status", "selector", "field_count", "filled_count", "url_before", "url_after"}
    for key in allowed_scalar_keys:
        if key in value:
            item = value[key]
            safe[key] = _redacted_string(item, limit=500) if isinstance(item, str) else item
    if isinstance(value.get("element"), dict):
        safe["element"] = _safe_live_mutation_element(value["element"])
    if isinstance(value.get("results"), list):
        safe["results"] = [
            {
                "selector": _redacted_string(item.get("selector"), limit=500),
                "status": _redacted_string(item.get("status"), limit=80),
                "element": _safe_live_mutation_element(item.get("element")),
            }
            for item in value["results"][:25]
            if isinstance(item, dict)
        ]
    return safe


def _safe_live_download_action_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for key in ("ok", "status", "selector", "url_before", "url_after"):
        if key in value:
            item = value[key]
            safe[key] = _redacted_string(item, limit=500) if isinstance(item, str) else item
    if isinstance(value.get("element"), dict):
        element = _safe_live_mutation_element(value["element"])
        element["download_attr_present"] = bool(value["element"].get("download_attr_present", False))
        safe["element"] = element
    return safe


def _safe_live_upload_action_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for key in ("ok", "status", "selector", "file_count", "url_before", "url_after"):
        if key in value:
            item = value[key]
            safe[key] = _redacted_string(item, limit=500) if isinstance(item, str) else item
    if isinstance(value.get("element"), dict):
        element = _safe_live_mutation_element(value["element"])
        element["accept"] = _redacted_string(value["element"].get("accept"), limit=120)
        element["multiple"] = bool(value["element"].get("multiple", False))
        safe["element"] = element
    return safe


def _safe_live_mutation_element(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe = {
        "tag": _redacted_string(value.get("tag"), limit=80),
        "id": _redacted_string(value.get("id"), limit=120),
        "name": _redacted_string(value.get("name"), limit=120),
        "type": _redacted_string(value.get("type"), limit=80),
        "role": _redacted_string(value.get("role"), limit=120),
        "href_present": bool(value.get("href_present", False)),
    }
    rect = value.get("rect")
    if isinstance(rect, dict):
        safe["rect"] = {key: _safe_int(rect.get(key)) for key in ("x", "y", "width", "height")}
    return safe


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[dict[str, Any]] = []
        self._table_stack: list[dict[str, Any]] = []
        self._current_row: list[str] | None = None
        self._current_cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._table_stack.append({"attrs": {key: value or "" for key, value in attrs}, "rows": []})
        elif tag == "tr" and self._table_stack:
            self._current_row = []
        elif tag in {"td", "th"} and self._current_row is not None:
            self._current_cell = []

    def handle_data(self, data: str) -> None:
        if self._current_cell is not None:
            self._current_cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self._current_cell is not None and self._current_row is not None:
            value = " ".join(" ".join(self._current_cell).split())
            self._current_row.append(str(redact(value))[:500])
            self._current_cell = None
        elif tag == "tr" and self._current_row is not None and self._table_stack:
            if any(cell for cell in self._current_row):
                self._table_stack[-1]["rows"].append(self._current_row)
            self._current_row = None
            self._current_cell = None
        elif tag == "table" and self._table_stack:
            table = self._table_stack.pop()
            if table["rows"]:
                if self._table_stack:
                    self._table_stack[-1]["rows"].extend(table["rows"])
                else:
                    self.tables.append(table)


def _extract_html_tables(content: str, *, selector: str | None = None) -> dict[str, Any]:
    parser = _TableParser()
    parser.feed(content)
    parser.close()
    tables = parser.tables
    selector_status = "not_provided"
    selector_note = "All HTML tables were returned."
    if selector:
        matcher = _table_selector_matcher(selector)
        if matcher is None:
            return {
                "tables": [table["rows"] for table in tables],
                "selector_status": "unsupported",
                "selector_note": "Only table, #id, .class, table#id, and table.class selectors are supported by the dependency-light parser.",
            }
        matched = [table for table in tables if matcher(table["attrs"])]
        selector_status = "matched" if matched else "no_match"
        selector_note = "Selector filtering used the dependency-light table parser."
        tables = matched
    return {"tables": [table["rows"] for table in tables], "selector_status": selector_status, "selector_note": selector_note}


def _table_selector_matcher(selector: str):
    selector = selector.strip()
    if not selector:
        return None
    if selector == "table":
        return lambda attrs: True
    if selector.startswith("#") and _simple_selector_value(selector[1:]):
        expected = selector[1:]
        return lambda attrs: attrs.get("id") == expected
    if selector.startswith(".") and _simple_selector_value(selector[1:]):
        expected = selector[1:]
        return lambda attrs: expected in attrs.get("class", "").split()
    if selector.startswith("table#") and _simple_selector_value(selector[6:]):
        expected = selector[6:]
        return lambda attrs: attrs.get("id") == expected
    if selector.startswith("table.") and _simple_selector_value(selector[6:]):
        expected = selector[6:]
        return lambda attrs: expected in attrs.get("class", "").split()
    return None


def _simple_selector_value(value: str) -> bool:
    return bool(value) and all(char.isalnum() or char in {"-", "_", ":"} for char in value)
