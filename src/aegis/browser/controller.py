"""Dependency-light governed browser sessions."""

from __future__ import annotations

import html
import json
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from typing import Any
from uuid import uuid4
import zlib

from aegis.audit.logger import AuditLogger, redact
from aegis.connectors.base import ConnectorRequest
from aegis.connectors.registry import ConnectorRegistry
from aegis.security.taint import now_utc
from aegis.storage.state import ensure_private_dir, ensure_private_file


_MAX_PERSISTED_CONTENT_CHARS = 200_000


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
            response = {"ok": False, "session": dict(session), "url": url, "error": result.error}
            self.audit_logger.append("browser.navigate_failed", response)
            return response
        content = str(result.data.get("content", ""))
        title = _title_from_text(content, fallback=url)
        interactive_elements = _extract_interactive_elements(content)
        session.update(
            {
                "current_url": url,
                "title": title,
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
            "url": url,
            "domain": result.data.get("domain"),
            "title": title,
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
            "url": session.get("current_url"),
            "text": str(redact(text[:5000])),
            "content_length": len(content),
            "mode": "http_content_no_js",
            "taint": "WEB_CONTENT",
        }
        self.audit_logger.append("browser.text_extracted", {"session_id": session_id, "url": session.get("current_url"), "content_length": len(content)})
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
            "url": session.get("current_url"),
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
            {"session_id": session_id, "url": session.get("current_url"), "table_count": len(tables), "selector": selector},
        )
        return response

    def screenshot(self, *, session_id: str) -> dict[str, Any]:
        session = self._require_session(session_id)
        evidence = _browser_evidence(session, action="screenshot")
        artifact = self.artifact_dir / f"{session_id}.png"
        sidecar = self.artifact_dir / f"{session_id}.txt"
        evidence_artifact = self.artifact_dir / f"{session_id}.evidence.json"
        width, height = _write_session_snapshot_png(artifact, session=session)
        sidecar.write_text(
            "\n".join(
                [
                    "Aegis governed browser PNG session snapshot",
                    f"url: {session.get('current_url') or ''}",
                    f"title: {session.get('title') or ''}",
                    f"captured_at: {now_utc()}",
                    f"clicks: {', '.join(str(item.get('selector', '')) for item in session.get('clicks', []))}",
                    f"form_state: {_redacted_form_state(session)}",
                ]
            ),
            encoding="utf-8",
        )
        artifact_hashes = {
            "snapshot_png_sha256": _file_sha256(artifact),
            "metadata_txt_sha256": _file_sha256(sidecar),
        }
        sandbox_receipt = _browser_sandbox_receipt()
        evidence_artifact.write_text(
            json.dumps(_browser_snapshot_evidence_document(session, evidence=evidence, artifact_hashes=artifact_hashes, sandbox_receipt=sandbox_receipt), indent=2, sort_keys=True),
            encoding="utf-8",
        )
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
            "url": session.get("current_url"),
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
        result = _capture_chrome_screenshot(
            executable=executable,
            html_path=html_artifact,
            output_path=artifact,
            artifact_dir=self.artifact_dir,
        )
        artifact_hashes = {"render_html_sha256": _file_sha256(html_artifact)}
        if artifact.exists():
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
            "url": session.get("current_url"),
            "evidence": evidence,
            "error": result.get("error"),
        }
        self.audit_logger.append("browser.render_screenshot_captured", response)
        return response

    def click(self, *, session_id: str, selector: str, approved: bool = False) -> dict[str, Any]:
        session = self._require_session(session_id)
        if not approved:
            return {"status": "approval_required", "session_id": session_id, "selector": selector, "reason": "browser click requires approval"}
        url_before = session.get("current_url")
        content_hash_before = _content_hash(session)
        click = {"selector": selector, "clicked_at": now_utc()}
        clicks = list(session.get("clicks", []))
        clicks.append(click)
        session["clicks"] = clicks[-25:]
        session["updated_at"] = now_utc()
        self._persist_sessions()
        evidence = _browser_evidence(session, action="click", url_before=url_before, content_hash_before=content_hash_before)
        response = {
            "ok": True,
            "session_id": session_id,
            "selector": selector,
            "url": session.get("current_url"),
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
        url_before = session.get("current_url")
        content_hash_before = _content_hash(session)
        form_state = dict(session.get("form_state", {}))
        for selector, value in fields.items():
            form_state[str(selector)] = str(redact(str(value)))[:500]
        session["form_state"] = form_state
        session["updated_at"] = now_utc()
        self._persist_sessions()
        evidence = _browser_evidence(session, action="fill", url_before=url_before, content_hash_before=content_hash_before)
        response = {
            "ok": True,
            "session_id": session_id,
            "fields": sorted(form_state),
            "url": session.get("current_url"),
            "effect": "virtual_form_state_updated",
            "mode": "virtual_state_no_dom",
            "dom_mutated": False,
            "form_state": dict(form_state),
            "evidence": evidence,
        }
        self.audit_logger.append("browser.fill_recorded", response)
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
    return {key: value for key, value in session.items() if key != "last_content"}


def _persistable_session(session: dict[str, Any]) -> dict[str, Any]:
    persisted = dict(session)
    if "last_content" in persisted:
        persisted["last_content"] = _bounded_redacted_content(str(persisted["last_content"]))
        persisted["last_content_redacted"] = True
    return persisted


def _normalize_persisted_session(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    session_id = item.get("id")
    if not isinstance(session_id, str) or not session_id:
        return None
    now = now_utc()
    session = {
        "id": session_id,
        "label": str(item.get("label") or "Browser session")[:200],
        "status": str(item.get("status") or "active")[:50],
        "current_url": str(item["current_url"])[:2000] if item.get("current_url") is not None else None,
        "title": str(item.get("title") or item.get("label") or "Browser session")[:200],
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
    return str(redact(content[:_MAX_PERSISTED_CONTENT_CHARS]))


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
            clicks.append({"selector": str(item.get("selector") or "")[:500], "clicked_at": str(item.get("clicked_at") or now_utc())})
    return clicks


def _normalize_form_state(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key)[:500]: str(redact(str(val)))[:500] for key, val in value.items()}


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
            "selector_hint": selector,
        }
        if tag == "a":
            element["href"] = str(redact(attrs.get("href", "")))[:300]
        if tag in {"button", "input", "textarea", "select"}:
            element["form_hint"] = selector
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
    clicks = list(session.get("clicks", []))
    form_state = dict(session.get("form_state", {}))
    if clicks:
        lines.append("Browser interaction state:")
        lines.extend(f"clicked {item.get('selector', '')}" for item in clicks[-10:])
    if form_state:
        if not lines:
            lines.append("Browser interaction state:")
        lines.extend(f"field {selector} = {value}" for selector, value in sorted(form_state.items()))
    return "\n".join(lines)


def _redacted_form_state(session: dict[str, Any]) -> str:
    form_state = dict(session.get("form_state", {}))
    return ", ".join(f"{selector}={value}" for selector, value in sorted(form_state.items()))


def _content_hash(session: dict[str, Any]) -> str:
    content = _bounded_redacted_content(str(session.get("last_content", "")))
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def _write_session_snapshot_png(path: Path, *, session: dict[str, Any]) -> tuple[int, int]:
    width = 320
    height = 180
    seed_text = json.dumps(
        {
            "url": session.get("current_url"),
            "title": session.get("title"),
            "content_hash": _content_hash(session),
            "clicks": [item.get("selector") for item in session.get("clicks", [])[-10:]],
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
    url_after = session.get("current_url")
    content_hash_after = _content_hash(session)
    return {
        "action": action,
        "url_before": url_before if url_before is not None else url_after,
        "url_after": url_after,
        "content_sha256_before": content_hash_before or content_hash_after,
        "content_sha256_after": content_hash_after,
        "content_changed": (content_hash_before or content_hash_after) != content_hash_after,
        "dom_mutated": False,
        "mode": "virtual_state_no_dom" if action in {"click", "fill"} else "local_png_session_snapshot_no_dom_render",
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
        "url": session.get("current_url"),
        "title": session.get("title"),
        "capture_surface": "http_content_session_state",
        "rendering_status": "not_rendered",
        "mode": "local_png_session_snapshot_no_dom_render",
        "sandbox_receipt": dict(sandbox_receipt),
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
        "url": session.get("current_url"),
        "title": session.get("title"),
        "capture_surface": "sanitized_http_content_dom",
        "rendering_status": "rendered" if render_result.get("ok") else "render_failed",
        "mode": "sanitized_dom_render_no_page_js",
        "sandbox_receipt": dict(sandbox_receipt),
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
        "cookies_persisted": False,
        "javascript_executed": False,
        "dom_renderer_used": False,
        "raw_secret_capture_allowed": False,
        "writes_confined_to": ".aegis/browser",
    }


def _browser_render_sandbox_receipt(*, executable: str, exit_code: int | None) -> dict[str, Any]:
    return {
        "sandbox_profile": "sanitized_http_content_chrome_render",
        "ambient_workspace_read": False,
        "ambient_network": "disabled_for_generated_file_capture",
        "cookies_persisted": False,
        "javascript_executed": False,
        "original_page_dom_executed": False,
        "dom_renderer_used": True,
        "renderer": Path(executable).name,
        "renderer_exit_code": exit_code,
        "raw_secret_capture_allowed": False,
        "writes_confined_to": ".aegis/browser",
    }


def _find_chrome_executable() -> str | None:
    for executable in ("google-chrome", "chromium", "chromium-browser"):
        path = shutil.which(executable)
        if path:
            return path
    return None


def _renderable_sanitized_html(session: dict[str, Any]) -> str:
    content = str(session.get("last_content", ""))
    text = " ".join(content.split())[:20_000]
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
  <title>{html.escape(str(session.get("title") or "Aegis render"))}</title>
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
    <h1>{html.escape(str(session.get("title") or "Browser session"))}</h1>
    <div class="muted">{html.escape(str(session.get("current_url") or ""))}</div>
  </header>
  <main>
    <section><h2>Sanitized Text</h2><p>{html.escape(str(redact(text)))}</p></section>
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
