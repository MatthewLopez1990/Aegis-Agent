from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class ApiResumePersistenceTests(unittest.TestCase):
    def test_session_bound_task_resume_survives_server_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            workspace = root / "workspace"
            workspace.mkdir()
            port = _free_port()

            first_server = _start_server(data_dir=data_dir, workspace=workspace, port=port)
            try:
                _wait_for_server(port)
                token = _json_get(port, "/auth")["token"]
                session = _json_post(port, "/sessions", {"title": "Restart resume session", "channel": "web"}, token=token)
                task = _json_post(port, "/tasks", {"request": "send message hello", "session_id": session["id"]}, token=token)

                self.assertEqual(task["status"], "waiting_approval")
                self.assertEqual(task["session"]["id"], session["id"])
            finally:
                _stop_server(first_server)

            second_server = _start_server(data_dir=data_dir, workspace=workspace, port=port)
            try:
                _wait_for_server(port)
                restarted_token = _json_get(port, "/auth")["token"]
                restarted_status = _json_get(port, f"/tasks/{task['id']}", token=restarted_token)
                approval_id = restarted_status["checkpoint"]["approval_id"]
                other_session = _json_post(port, "/sessions", {"title": "Other web session", "channel": "web"}, token=restarted_token)
                _json_post(
                    port,
                    f"/sessions/{other_session['id']}/messages",
                    {"content": "other api session noise", "submit": False},
                    token=restarted_token,
                )

                self.assertEqual(restarted_status["session"]["id"], session["id"])
                self.assertEqual(restarted_status["session"]["title"], "Restart resume session")

                _json_post(port, f"/approvals/{approval_id}/approve", {}, token=restarted_token)
                with self.assertRaises(HTTPError) as mismatch:
                    _json_post(port, f"/tasks/{task['id']}/resume", {"session_id": other_session["id"]}, token=restarted_token)

                self.assertEqual(mismatch.exception.code, 403)
                resumed = _json_post(port, f"/tasks/{task['id']}/resume", {}, token=restarted_token)
                history = _json_get(port, f"/sessions/{session['id']}/messages?limit=20", token=restarted_token)
                limited_history = _json_get(port, f"/sessions/{session['id']}/messages?limit=2", token=restarted_token)
                other_history = _json_get(port, f"/sessions/{other_session['id']}/messages?limit=20", token=restarted_token)

                self.assertEqual(resumed["status"], "completed")
                self.assertEqual(resumed["session"]["id"], session["id"])
                self.assertEqual(resumed["session"]["task_count"], 1)
                self.assertTrue(any(message["metadata"].get("source") == "task_resume_result" for message in history["messages"]))
                self.assertFalse(any(message["metadata"].get("source") == "task_resume_result" for message in other_history["messages"]))
                self.assertEqual(len(limited_history["messages"]), 2)
                self.assertEqual(limited_history["messages"][-1]["metadata"].get("source"), "task_resume_result")
                self.assertEqual(limited_history["messages"][-1]["current_task_status"], "completed")
            finally:
                _stop_server(second_server)


def _start_server(*, data_dir: Path, workspace: Path, port: int) -> subprocess.Popen[bytes]:
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aegis.cli.main",
            "--data-dir",
            str(data_dir),
            "serve",
            "--workspace",
            str(workspace),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _stop_server(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        handle.bind(("127.0.0.1", 0))
        return int(handle.getsockname()[1])


def _wait_for_server(port: int) -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            _json_get(port, "/health")
            return
        except (HTTPError, URLError, ConnectionError):
            time.sleep(0.05)
    raise RuntimeError("server did not start")


def _json_get(port: int, path: str, *, token: str | None = None) -> dict[str, object]:
    headers = {}
    if token is not None:
        headers["X-Aegis-Token"] = token
    request = Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    with urlopen(request, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def _json_post(port: int, path: str, payload: dict[str, object], *, token: str) -> dict[str, object]:
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Aegis-Token": token},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
