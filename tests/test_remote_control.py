from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from aegis.remote_control import RemoteControlPairingRegistry, build_remote_control_directory


class RemoteControlPairingTests(unittest.TestCase):
    def test_pairing_token_is_returned_once_and_public_status_is_redacted(self) -> None:
        registry = RemoteControlPairingRegistry()
        now = datetime(2026, 5, 12, 12, 0, tzinfo=timezone.utc)

        created = registry.create_pairing(label="phone", session_id="session-1", task_id="task-1", allowed_actions=("status", "pause", "shell"), ttl_seconds=30, now=now)

        self.assertEqual(created["status"], "paired")
        self.assertEqual(created["token_header"], "X-Aegis-Remote-Token")
        self.assertEqual(created["expires_in_seconds"], 60)
        self.assertTrue(created["token"].startswith("aegis-rc-"))
        self.assertNotIn("token_sha256", created["pairing"])
        self.assertEqual(created["pairing"]["status"], "active")
        self.assertEqual(created["pairing"]["label"], "phone")
        self.assertEqual(created["pairing"]["task_id"], "task-1")
        self.assertEqual(created["pairing"]["allowed_actions"], ["pause", "status"])
        self.assertEqual(registry.authorize(created["token"], now=now)["id"], created["pairing"]["id"])
        self.assertEqual(registry.authorize_action(created["token"], action="pause", task_id="task-1", now=now)["id"], created["pairing"]["id"])
        self.assertIsNone(registry.authorize_action(created["token"], action="cancel", task_id="task-1", now=now))
        self.assertIsNone(registry.authorize_action(created["token"], action="pause", task_id="other-task", now=now))

        status = registry.status(now=now)
        self.assertEqual(status["active_pairing_count"], 1)
        self.assertEqual(status["relay_preflight"]["status"], "relay_blocked_preflight")
        self.assertFalse(status["relay_preflight"]["outbound_relay_enabled"])
        self.assertFalse(status["relay_preflight"]["pairing_token_relayed"])
        self.assertNotIn(created["token"], str(status))

    def test_scoped_directory_sanitizes_task_metadata(self) -> None:
        registry = RemoteControlPairingRegistry()
        now = datetime(2026, 5, 12, 12, 0, tzinfo=timezone.utc)
        created = registry.create_pairing(label="phone", session_id="session-1", allowed_actions=("status", "events", "pause"), now=now)

        class FakeStore:
            def list_tasks(self, limit: int = 20, *, session_id: str | None = None):
                self.limit = limit
                self.session_id = session_id
                return [
                    {
                        "id": "task-1",
                        "status": "paused",
                        "risk_level": "medium",
                        "session_id": "session-1",
                        "created_at": "2026-05-12T12:00:00+00:00",
                        "updated_at": "2026-05-12T12:01:00+00:00",
                        "user_request": "token=secret should not be exposed",
                        "plan_json": '[{"secret":"hidden"}]',
                        "receipt_json": '{"token":"hidden"}',
                    }
                ]

        store = FakeStore()
        directory = build_remote_control_directory(created["pairing"], store=store, limit=99, now=now)
        rendered = json.dumps(directory, sort_keys=True)

        self.assertEqual(directory["status"], "remote_directory_available")
        self.assertEqual(directory["scope"]["type"], "session")
        self.assertEqual(directory["task_limit"], 25)
        self.assertEqual(store.session_id, "session-1")
        self.assertEqual(directory["tasks"][0]["id"], "task-1")
        self.assertEqual(directory["tasks"][0]["links"]["status"], "/remote-control/tasks/task-1")
        self.assertEqual(directory["tasks"][0]["links"]["events"], "/remote-control/tasks/task-1/events")
        self.assertEqual(directory["tasks"][0]["links"]["pause"], "/remote-control/tasks/task-1/pause")
        self.assertFalse(directory["broad_task_listing"])
        self.assertFalse(directory["raw_secret_values_included"])
        self.assertFalse(directory["user_request_included"])
        self.assertFalse(directory["plan_receipt_included"])
        self.assertNotIn(created["token"], rendered)
        self.assertNotIn("token=secret", rendered)
        self.assertNotIn("hidden", rendered)

    def test_relay_preflight_redacts_url_secrets_and_blocks_transport(self) -> None:
        registry = RemoteControlPairingRegistry()

        result = registry.relay_preflight(relay_url="https://relay.example/aegis?token=secret#frag")

        rendered = json.dumps(result, sort_keys=True)
        self.assertEqual(result["status"], "relay_blocked_preflight")
        self.assertEqual(result["mode"], "preflight_only")
        self.assertEqual(result["relay_target"], "https://relay.example/aegis")
        self.assertTrue(result["relay_url_redacted"])
        self.assertFalse(result["outbound_relay_enabled"])
        self.assertFalse(result["raw_secret_values_included"])
        self.assertFalse(result["pairing_token_relayed"])
        self.assertNotIn("token=secret", rendered)
        self.assertNotIn("#frag", rendered)
        self.assertIsNone(registry.relay_preflight(relay_url="https://user:pass@relay.example/aegis")["relay_target"])

    def test_approved_relay_registration_posts_redacted_pairing_metadata(self) -> None:
        registry = RemoteControlPairingRegistry()
        now = datetime(2026, 5, 12, 12, 0, tzinfo=timezone.utc)
        created = registry.create_pairing(label="phone", task_id="task-1", allowed_actions=("status", "pause"), now=now)
        captured = {"requests": []}

        class FakeResponse:
            def __init__(self, payload: dict[str, object] | None = None) -> None:
                self.payload = payload or {"ok": True, "token": "relay-raw-secret"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def getcode(self) -> int:
                return 202

            def read(self, limit: int) -> bytes:
                return json.dumps(self.payload).encode("utf-8")

        def fake_open(request, timeout: int):
            captured["request"] = request
            captured["requests"].append(request)
            captured["timeout"] = timeout
            body = json.loads(request.data.decode("utf-8"))
            if body.get("type") == "aegis.remote_control.pull":
                return FakeResponse(
                    {
                        "actions": [
                            {"request_id": "a1", "action": "status", "task_id": "task-1", "extra": "ignored"},
                            {"request_id": "a2", "action": "cancel", "task_id": "task-1"},
                            {"request_id": "a3", "action": "pause", "task_id": "other-task"},
                        ]
                    }
                )
            if body.get("type") == "aegis.remote_control.directory":
                return FakeResponse({"ok": True, "published": True})
            return FakeResponse()

        with patch("aegis.remote_control._private_network_error", return_value=None):
            with patch("aegis.remote_control._open_without_redirects", side_effect=fake_open):
                result = registry.relay_pairing(
                    created["pairing"]["id"],
                    relay_url="https://example.com/aegis-relay?token=secret",
                    allowlist=("example.com",),
                    relay_auth_token="relay-raw-secret",
                    approved=True,
                    now=now,
                )

        body = json.loads(captured["request"].data.decode("utf-8"))
        rendered_result = json.dumps(result, sort_keys=True)
        rendered_body = json.dumps(body, sort_keys=True)
        self.assertEqual(result["status"], "relay_registered")
        self.assertEqual(result["relay_target"], "https://example.com/aegis-relay")
        self.assertTrue(result["outbound_relay_enabled"])
        self.assertFalse(result["pairing_token_relayed"])
        self.assertEqual(result["relay_response_status"], 202)
        self.assertEqual(captured["request"].get_header("Authorization"), "Bearer relay-raw-secret")
        self.assertEqual(body["pairing"]["id"], created["pairing"]["id"])
        self.assertFalse(body["pairing_token_included"])
        self.assertNotIn(created["token"], rendered_body)
        self.assertNotIn(created["token"], rendered_result)
        self.assertNotIn("relay-raw-secret", rendered_body)
        self.assertNotIn("relay-raw-secret", rendered_result)
        self.assertNotIn("token=secret", rendered_result)
        self.assertEqual(registry.authorize_relay_action(created["pairing"]["id"], "relay-raw-secret", action="pause", task_id="task-1", now=now)["pairing"]["id"], created["pairing"]["id"])
        self.assertIsNone(registry.authorize_relay_action(created["pairing"]["id"], "wrong-secret", action="pause", task_id="task-1", now=now))
        self.assertIsNone(registry.authorize_relay_action(created["pairing"]["id"], "relay-raw-secret", action="cancel", task_id="task-1", now=now))
        self.assertIsNone(registry.authorize_relay_action(created["pairing"]["id"], "relay-raw-secret", action="pause", task_id="other-task", now=now))
        with patch("aegis.remote_control._private_network_error", return_value=None):
            with patch("aegis.remote_control._open_without_redirects", side_effect=fake_open):
                pulled = registry.pull_relay_actions(
                    created["pairing"]["id"],
                    relay_auth_token="relay-raw-secret",
                    allowlist=("example.com",),
                    approved=True,
                    limit=5,
                    now=now + timedelta(seconds=1),
                )
        pull_body = json.loads(captured["requests"][-1].data.decode("utf-8"))
        rendered_pulled = json.dumps(pulled, sort_keys=True)
        self.assertEqual(pulled["status"], "relay_actions_pulled")
        self.assertEqual(pulled["action_count"], 3)
        self.assertEqual(pulled["executable_action_count"], 1)
        self.assertTrue(pulled["actions"][0]["accepted"])
        self.assertEqual(pulled["actions"][1]["rejection_reason"], "action is outside pairing scope")
        self.assertEqual(pulled["actions"][2]["rejection_reason"], "task_id is outside pairing scope")
        self.assertEqual(pull_body["type"], "aegis.remote_control.pull")
        self.assertFalse(pull_body["pairing_token_included"])
        self.assertNotIn(created["token"], rendered_pulled)
        self.assertNotIn("relay-raw-secret", rendered_pulled)
        directory_payload = {
            "status": "remote_directory_available",
            "mode": "scoped_remote_directory",
            "scope": {"type": "task", "task_id": "task-1"},
            "task_count": 1,
            "tasks": [
                {
                    "id": "task-1",
                    "status": "paused",
                    "metadata_only": True,
                    "allowed_actions": ["status", "pause", "shell"],
                    "links": {"status": "/remote-control/tasks/task-1?token=secret"},
                    "user_request": "hidden prompt",
                }
            ],
            "pairing_token_relayed": False,
            "raw_secret_values_included": False,
            "user_request_included": False,
            "plan_receipt_included": False,
        }
        with patch("aegis.remote_control._private_network_error", return_value=None):
            with patch("aegis.remote_control._open_without_redirects", side_effect=fake_open):
                directory_published = registry.publish_relay_directory(
                    created["pairing"]["id"],
                    directory=directory_payload,
                    relay_auth_token="relay-raw-secret",
                    allowlist=("example.com",),
                    approved=True,
                    now=now + timedelta(seconds=2),
                )
        directory_body = json.loads(captured["requests"][-1].data.decode("utf-8"))
        rendered_directory = json.dumps(directory_published, sort_keys=True)
        rendered_directory_body = json.dumps(directory_body, sort_keys=True)
        self.assertEqual(directory_published["status"], "relay_directory_published")
        self.assertEqual(directory_published["mode"], "approved_relay_directory_snapshot")
        self.assertEqual(directory_published["directory_task_count"], 1)
        self.assertEqual(directory_body["type"], "aegis.remote_control.directory")
        self.assertEqual(directory_body["directory"]["scope"]["type"], "task")
        self.assertEqual(directory_body["directory"]["tasks"][0]["allowed_actions"], ["status", "pause"])
        self.assertEqual(directory_body["directory"]["tasks"][0]["links"]["status"], "/remote-control/tasks/task-1")
        self.assertFalse(directory_body["pairing_token_included"])
        self.assertFalse(directory_body["relay_auth_token_included"])
        self.assertFalse(directory_body["user_request_included"])
        self.assertFalse(directory_published["relay_auth_token_captured"])
        self.assertNotIn(created["token"], rendered_directory)
        self.assertNotIn("hidden prompt", rendered_directory_body)
        self.assertNotIn("token=secret", rendered_directory_body)
        self.assertNotIn("relay-raw-secret", rendered_directory)
        self.assertNotIn(created["token"], rendered_directory_body)
        self.assertNotIn("relay-raw-secret", rendered_directory_body)
        self.assertEqual(registry.public_pairing(created["pairing"]["id"], now=now + timedelta(seconds=3))["relay_last_directory_publish_at"], (now + timedelta(seconds=2)).isoformat())
        with patch("aegis.remote_control._open_without_redirects", side_effect=fake_open):
            revoked = registry.revoke(
                created["pairing"]["id"],
                relay_auth_token="relay-raw-secret",
                notify_relay=True,
                now=now + timedelta(seconds=4),
            )
        revoked_body = json.loads(captured["requests"][-1].data.decode("utf-8"))
        rendered_revoked = json.dumps(revoked, sort_keys=True)
        rendered_revoked_body = json.dumps(revoked_body, sort_keys=True)
        self.assertTrue(revoked["relay_revocation_propagated"])
        self.assertEqual(revoked["relay_target"], "https://example.com/aegis-relay")
        self.assertEqual(revoked["relay_response_status"], 202)
        self.assertEqual(revoked_body["type"], "aegis.remote_control.revocation")
        self.assertEqual(revoked_body["pairing_id"], created["pairing"]["id"])
        self.assertFalse(revoked_body["pairing_token_included"])
        self.assertNotIn(created["token"], rendered_revoked)
        self.assertNotIn(created["token"], rendered_revoked_body)
        self.assertNotIn("relay-raw-secret", rendered_revoked)
        self.assertNotIn("relay-raw-secret", rendered_revoked_body)
        self.assertTrue(registry.status(now=now + timedelta(seconds=3))["pairings"][0]["relay_revocation_propagated"])
        self.assertIsNone(registry.authorize_relay_action(created["pairing"]["id"], "relay-raw-secret", action="pause", task_id="task-1", now=now + timedelta(seconds=3)))

    def test_relay_preflight_rejects_non_https_targets(self) -> None:
        registry = RemoteControlPairingRegistry()

        result = registry.relay_preflight(relay_url="http://relay.example/aegis")

        self.assertIsNone(result["relay_target"])
        self.assertFalse(result["relay_configured"])
        self.assertEqual(result["blockers"][0]["control"], "relay_url_validation")

    def test_pairing_expires_and_can_be_revoked(self) -> None:
        registry = RemoteControlPairingRegistry()
        now = datetime(2026, 5, 12, 12, 0, tzinfo=timezone.utc)
        created = registry.create_pairing(label="tablet", ttl_seconds=60, now=now)
        token = created["token"]
        pairing_id = created["pairing"]["id"]

        self.assertIsNone(registry.authorize(token, now=now + timedelta(seconds=61)))
        expired = registry.status(now=now + timedelta(seconds=61))["pairings"][0]
        self.assertEqual(expired["status"], "expired")

        revoked = registry.revoke(pairing_id, now=now + timedelta(seconds=30))
        self.assertEqual(revoked["pairing"]["status"], "revoked")
        self.assertIsNone(registry.authorize(token, now=now + timedelta(seconds=31)))

    def test_pairing_store_persists_hashes_without_raw_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store_path = Path(temp) / "remote_control_pairings.json"
            now = datetime(2026, 5, 12, 12, 0, tzinfo=timezone.utc)
            registry = RemoteControlPairingRegistry(store_path)

            created = registry.create_pairing(label="phone", task_id="task-1", allowed_actions=("status", "pause"), now=now)
            token = created["token"]
            persisted = store_path.read_text(encoding="utf-8")

            self.assertNotIn(token, persisted)
            self.assertIn("token_sha256", persisted)
            self.assertEqual(stat.S_IMODE(store_path.stat().st_mode), 0o600)

            reloaded = RemoteControlPairingRegistry(store_path)
            self.assertEqual(reloaded.authorize_action(token, action="pause", task_id="task-1", now=now)["id"], created["pairing"]["id"])
            revoked = reloaded.revoke(created["pairing"]["id"], now=now + timedelta(seconds=1))

            self.assertEqual(revoked["pairing"]["status"], "revoked")
            self.assertIsNone(RemoteControlPairingRegistry(store_path).authorize(token, now=now + timedelta(seconds=2)))


if __name__ == "__main__":
    unittest.main()
