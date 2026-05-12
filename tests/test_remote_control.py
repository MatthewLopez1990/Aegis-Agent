from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from aegis.remote_control import RemoteControlPairingRegistry


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


if __name__ == "__main__":
    unittest.main()
