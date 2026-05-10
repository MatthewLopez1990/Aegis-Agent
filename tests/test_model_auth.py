from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.audit.logger import AuditLogger
from aegis.memory.store import LocalStore
from aegis.models.registry import ModelRegistry
from aegis.security.secrets_broker import SecretsBroker


class ModelAuthTests(unittest.TestCase):
    def test_openai_and_openrouter_login_use_brokered_local_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {}, clear=True):
            root = Path(temp)
            secret_path = root / ".aegis" / "secrets.json"
            audit_path = root / ".aegis" / "audit.jsonl"
            broker = SecretsBroker(secret_path)
            registry = ModelRegistry(LocalStore(root / ".aegis" / "aegis.db"), AuditLogger(audit_path), broker)

            self.assertFalse(registry.auth_status("openai")["auth_configured"])
            self.assertFalse(registry.auth_status("openrouter")["auth_configured"])

            openai_status = registry.login_provider("openai", "sk-openai-test")
            openrouter_status = registry.login_provider("openrouter", "sk-openrouter-test")

            self.assertEqual(openai_status["auth_source"], "local")
            self.assertEqual(openrouter_status["auth_source"], "local")
            self.assertTrue(registry.auth_status("openai")["auth_configured"])
            self.assertTrue(registry.auth_status("openrouter")["auth_configured"])
            self.assertTrue(registry.route("openai/gpt-4o").secret_handle_id)
            self.assertTrue(registry.route("openrouter/openai/gpt-4o").secret_handle_id)

            openai_handle = broker.request_handle(
                name="OPENAI_API_KEY",
                requester="model:openai",
                reason="test resolve",
                scopes=("model.invoke",),
            )
            self.assertEqual(broker.resolve_for_authorized_tool(openai_handle, requester="model:openai"), "sk-openai-test")

            self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o600)
            audit_text = audit_path.read_text(encoding="utf-8")
            self.assertNotIn("sk-openai-test", audit_text)
            self.assertNotIn("sk-openrouter-test", audit_text)

            logout_status = registry.logout_provider("openrouter")
            self.assertFalse(logout_status["auth_configured"])


if __name__ == "__main__":
    unittest.main()
