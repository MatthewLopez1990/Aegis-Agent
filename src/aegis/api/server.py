"""Dependency-free local development API server."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import json
import mimetypes
import re

from aegis.agent.orchestrator import build_orchestrator


def serve(*, data_dir: str | Path, workspace: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    orchestrator = build_orchestrator(data_dir=data_dir, workspace=workspace)
    static_root = Path(__file__).resolve().parents[1] / "web" / "static"

    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisAgent/0.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler name.
            if self.path == "/":
                self._static(static_root / "index.html")
                return
            if self.path.startswith("/static/"):
                requested = (static_root / self.path.removeprefix("/static/")).resolve()
                if static_root not in (requested, *requested.parents):
                    self._json({"error": "invalid static path"}, status=403)
                    return
                self._static(requested)
                return
            if self.path == "/health":
                self._json(
                    {
                        "ok": True,
                        "audit_chain_ok": orchestrator.audit_logger.verify_chain(),
                        "connectors": orchestrator.connectors.status(),
                        "channels": orchestrator.channels.status(),
                    }
                )
                return
            if self.path == "/connectors":
                self._json({"connectors": orchestrator.connectors.list()})
                return
            if self.path == "/channels":
                self._json({"channels": orchestrator.channels.list_channels()})
                return
            if self.path == "/models":
                self._json({"models": orchestrator.models.list_models()})
                return
            if self.path == "/model-providers":
                self._json({"providers": orchestrator.models.list_providers()})
                return
            if self.path == "/tools":
                self._json({"tools": orchestrator.tool_catalog.list()})
                return
            if self.path == "/backends":
                self._json({"backends": orchestrator.execution_backends.list()})
                return
            if self.path == "/skill-hub":
                self._json(orchestrator.skill_hub.search(""))
                return
            if self.path == "/schedules":
                self._json({"schedules": orchestrator.schedules.list_schedules()})
                return
            if self.path == "/sessions":
                self._json({"sessions": orchestrator.sessions.list_sessions()})
                return
            if self.path == "/audit":
                self._json({"events": orchestrator.audit_logger.tail(50)})
                return
            if self.path == "/kanban/boards":
                self._json({"boards": orchestrator.kanban.list_boards()})
                return
            match = re.fullmatch(r"/tasks/([^/]+)", self.path)
            if match:
                self._json(orchestrator.status(match.group(1)))
                return
            self._json({"error": "not found"}, status=404)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler name.
            if self.path == "/tasks":
                payload = self._read_json()
                self._json(orchestrator.submit_task(str(payload["request"]), path=payload.get("path")))
                return
            if self.path == "/sessions":
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
            if self.path == "/models/auth/login":
                payload = self._read_json()
                self._json(
                    {
                        "ok": True,
                        "auth": orchestrator.models.login_provider(str(payload["provider"]), str(payload["api_key"])),
                    }
                )
                return
            if self.path == "/models/auth/logout":
                payload = self._read_json()
                self._json(
                    {
                        "ok": True,
                        "auth": orchestrator.models.logout_provider(str(payload["provider"])),
                    }
                )
                return
            if self.path == "/schedules":
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
            if self.path == "/kanban/boards":
                payload = self._read_json()
                self._json(orchestrator.kanban.create_board(str(payload["name"])))
                return
            match_card = re.fullmatch(r"/kanban/boards/([^/]+)/cards", self.path)
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
            match = re.fullmatch(r"/tasks/([^/]+)/resume", self.path)
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
