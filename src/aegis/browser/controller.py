"""Dependency-light governed browser sessions."""

from __future__ import annotations

import html
import json
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse
from uuid import uuid4
import zlib

from aegis.audit.logger import AuditLogger, redact
from aegis.connectors.base import ConnectorRequest
from aegis.connectors.registry import ConnectorRegistry
from aegis.security.taint import now_utc
from aegis.storage.state import ensure_private_dir, ensure_private_file


_MAX_PERSISTED_CONTENT_CHARS = 200_000
_MAX_STATIC_DOM_NODES = 120
_MAX_STATIC_DOM_DEPTH = 12
_MAX_STATIC_DOM_TEXT_CHARS = 160
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
    def __init__(self, connectors: ConnectorRegistry, audit_logger: AuditLogger, artifact_dir: str | Path) -> None:
        self.connectors = connectors
        self.audit_logger = audit_logger
        self.artifact_dir = ensure_private_dir(artifact_dir)
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
        selector_inventory = _selector_inventory(interactive_elements)
        activation = _live_browser_activation_preflight()
        response = {
            "ok": True,
            "session_id": session_id,
            "url": _session_url(session),
            "title": _redacted_string(session.get("title"), limit=200),
            "interactive_elements": interactive_elements,
            "interactive_element_count": len(interactive_elements),
            "selector_inventory": selector_inventory,
            "unsupported_live_actions": _unsupported_live_browser_actions(),
            "readiness": {
                "live_browser_adapter": "blocked_pending_boundaries",
                "approval_required_for_mutation": True,
                "javascript_executed": False,
                "cookie_persistence": False,
                "real_selector_events_dispatched": False,
                "dom_mutation_supported": False,
                "static_dom_form_fill_supported": True,
            },
            "activation": activation,
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
        raise ValueError(f"unsupported browser approval action: {action}")

    def deny_live_automation(self, *, action: str, session_id: str | None = None, selector: str | None = None) -> dict[str, Any]:
        session = self._require_session(session_id) if session_id else None
        activation = _live_browser_activation_preflight()
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
            "unsupported_live_actions": _unsupported_live_browser_actions(),
            "mode": "live_browser_adapter_denied",
        }
        self.audit_logger.append("browser.live_automation_denied", response)
        return response

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


def _selector_inventory(elements: list[dict[str, str]]) -> list[dict[str, Any]]:
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
                "requires_approval": True,
                "dom_mutation_supported": False,
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


def _unsupported_live_browser_actions() -> list[str]:
    return [
        "javascript_execution",
        "cookie_persistence",
        "network_subresource_loading",
        "dom_event_dispatch",
        "real_page_mutation",
        "live_form_submit",
    ]


def _live_browser_activation_preflight() -> dict[str, Any]:
    blockers = [
        {"control": "live_browser_adapter", "detail": "no real browser automation adapter is enabled"},
        {"control": "ephemeral_profile", "detail": "live automation must use a per-run browser profile with no persistent cookies or storage"},
        {"control": "network_allowlist", "detail": "navigation and subresource requests must pass configured provider/domain allowlists"},
        {"control": "script_policy", "detail": "page JavaScript execution policy must be explicit before live DOM automation"},
        {"control": "cookie_and_storage_isolation", "detail": "cookies, local storage, and session storage must be isolated and redacted in receipts"},
        {"control": "approval_gated_mutation", "detail": "real clicks, form fills, downloads, uploads, and page mutations must require matching approval"},
        {"control": "redacted_artifact_receipts", "detail": "screenshots, DOM captures, console logs, and network traces must be hash-receipted and secret-redacted"},
    ]
    return {
        "status": "live_browser_adapter_required",
        "preflight_status": "blocked",
        "configured_controls": [
            "http_connector_navigation_allowlist",
            "virtual_interaction_approval_gate",
            "browser_automation_boundary_receipts",
            "private_artifact_storage",
            "artifact_hash_receipts",
            "secret_redaction",
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
        ],
        "next_steps": [
            "Add a browser automation adapter only after navigation, subresource, script, cookie, and storage boundaries are enforceable.",
            "Keep every real page mutation approval-gated and bind approvals to the exact selector/action payload.",
            "Record redacted hash receipts for screenshots, DOM snapshots, downloads, uploads, console logs, and network traces.",
        ],
    }


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


def _browser_automation_boundaries(*, rendered: bool) -> dict[str, Any]:
    return {
        "boundary_schema": "browser_automation_boundaries_v1",
        "capture_surface": "sanitized_generated_html" if rendered else "http_content_session_state",
        "navigation_network": "disabled_for_generated_file_capture" if rendered else "http_connector_allowlist_only",
        "remote_subresources_loaded": False,
        "page_javascript_allowed": False,
        "original_page_dom_executed": False,
        "cookies_persisted": False,
        "cookie_jar_persisted": False,
        "local_storage_persisted": False,
        "session_storage_persisted": False,
        "real_selector_events_dispatched": False,
        "real_page_mutation_allowed": False,
        "virtual_interactions_only": True,
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
