"""Dependency-free local development API server."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import json
import mimetypes
import re
from urllib.parse import parse_qs, urlparse

from aegis.agent.orchestrator import build_orchestrator
from aegis.product.capabilities import build_product_dashboard


def serve(*, data_dir: str | Path, workspace: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    orchestrator = build_orchestrator(data_dir=data_dir, workspace=workspace)
    static_root = Path(__file__).resolve().parents[1] / "web" / "static"

    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisAgent/0.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler name.
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
                self._json({"events": orchestrator.channels.events(limit=int(query.get("limit", ["50"])[0]))})
                return
            if path == "/models":
                self._json({"models": orchestrator.models.list_models()})
                return
            if path == "/model-providers":
                self._json({"providers": orchestrator.models.list_providers()})
                return
            if path == "/tools":
                self._json({"tools": orchestrator.tool_catalog.list()})
                return
            if path == "/backends":
                self._json({"backends": orchestrator.execution_backends.list()})
                return
            if path == "/skill-hub":
                self._json(orchestrator.skill_hub.search(""))
                return
            if path == "/schedules":
                self._json({"schedules": orchestrator.schedules.list_schedules()})
                return
            if path == "/sessions":
                self._json({"sessions": orchestrator.sessions.list_sessions()})
                return
            if path == "/tasks":
                self._json({"tasks": [_task_summary(row) for row in orchestrator.store.list_tasks(limit=int(query.get("limit", ["25"])[0]))]})
                return
            if path == "/approvals":
                status = query.get("status", [None])[0]
                self._json({"approvals": orchestrator.approvals.list(status=status)})
                return
            if path == "/memory":
                search = query.get("q", [""])[0]
                self._json({"memories": orchestrator.memory.retrieve_relevant(search) if search else []})
                return
            if path == "/audit":
                self._json({"events": orchestrator.audit_logger.tail(int(query.get("limit", ["50"])[0]))})
                return
            if path == "/kanban/boards":
                self._json({"boards": orchestrator.kanban.list_boards()})
                return
            match_cards = re.fullmatch(r"/kanban/boards/([^/]+)/cards", path)
            if match_cards:
                self._json({"cards": orchestrator.kanban.list_cards(match_cards.group(1))})
                return
            match = re.fullmatch(r"/tasks/([^/]+)", path)
            if match:
                self._json(orchestrator.status(match.group(1)))
                return
            self._json({"error": "not found"}, status=404)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler name.
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/tasks":
                payload = self._read_json()
                self._json(orchestrator.submit_task(str(payload["request"]), path=payload.get("path")))
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
            if path == "/models/auth/login":
                payload = self._read_json()
                self._json(
                    {
                        "ok": True,
                        "auth": orchestrator.models.login_provider(str(payload["provider"]), str(payload["api_key"])),
                    }
                )
                return
            if path == "/models/auth/logout":
                payload = self._read_json()
                self._json(
                    {
                        "ok": True,
                        "auth": orchestrator.models.logout_provider(str(payload["provider"])),
                    }
                )
                return
            if path == "/schedules":
                payload = self._read_json()
                self._json(
                    orchestrator.schedules.create_schedule(
                        name=str(payload["name"]),
                        natural_language=str(payload.get("natural_language", payload["task_request"])),
                        cron=str(payload["cron"]),
                        task_request=str(payload["task_request"]),
                        channel=str(payload.get("channel", "web")),
                    )
                )
                return
            if path == "/kanban/boards":
                payload = self._read_json()
                self._json(orchestrator.kanban.create_board(str(payload["name"])))
                return
            match_card = re.fullmatch(r"/kanban/boards/([^/]+)/cards", path)
            if match_card:
                payload = self._read_json()
                self._json(
                    orchestrator.kanban.add_card(
                        match_card.group(1),
                        title=str(payload["title"]),
                        description=str(payload.get("description", "")),
                        lane=str(payload.get("lane", "backlog")),
                    )
                )
                return
            match_move = re.fullmatch(r"/kanban/cards/([^/]+)/move", path)
            if match_move:
                payload = self._read_json()
                lane = str(payload["lane"])
                orchestrator.kanban.move_card(match_move.group(1), lane)
                self._json({"ok": True, "card_id": match_move.group(1), "lane": lane})
                return
            match_approval_approve = re.fullmatch(r"/approvals/([^/]+)/approve", path)
            if match_approval_approve:
                self._json(orchestrator.approvals.approve(match_approval_approve.group(1)))
                return
            match_approval_deny = re.fullmatch(r"/approvals/([^/]+)/deny", path)
            if match_approval_deny:
                self._json(orchestrator.approvals.deny(match_approval_deny.group(1)))
                return
            match = re.fullmatch(r"/tasks/([^/]+)/resume", path)
            if match:
                self._json(orchestrator.resume_task(match.group(1)))
                return
            self._json({"error": "not found"}, status=404)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b"{}"
            return json.loads(body.decode("utf-8"))

        def _json(self, payload: dict[str, Any], *, status: int = 200) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

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

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Aegis Agent API listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Aegis Agent API stopped", flush=True)
    finally:
        server.server_close()


def _task_summary(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    decoded["plan"] = json.loads(decoded.pop("plan_json", "[]"))
    decoded["checkpoint"] = json.loads(decoded.pop("checkpoint_json", "{}"))
    receipt_json = decoded.pop("receipt_json", None)
    decoded["receipt"] = json.loads(receipt_json) if receipt_json else None
    return decoded
