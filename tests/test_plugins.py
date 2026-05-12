from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
import hmac
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from aegis.audit.logger import AuditLogger
from aegis.hooks.manager import HookManager
from aegis.mcp.registry import McpRegistry
from aegis.memory.store import LocalStore
from aegis.plugins.manager import PluginManager
from aegis.security.secrets_broker import SecretsBroker
from aegis.skills.signing import DEFAULT_SKILL_SIGNING_KEY, SIGNATURE_ALGORITHM
from aegis.skills.registry import SkillRegistry
from aegis.skills.runtime import builtin_project_summary_manifest


class PluginManagerTests(unittest.TestCase):
    def test_plugin_install_enable_disable_and_remove_uses_governed_registries(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            plugin_path = _write_plugin_fixture(root)
            manager = _plugin_manager(data_dir, workspace=root)

            installed = manager.install_plugin(plugin_path, unsigned_local=True)
            self.assertEqual(installed["id"], "test.plugin")
            self.assertFalse(installed["enabled"])
            self.assertEqual({resource["kind"] for resource in installed["resources"]}, {"skill", "mcp_server", "hook"})

            enabled = manager.enable_plugin("test.plugin")
            self.assertTrue(enabled["plugin"]["enabled"])
            self.assertTrue(_plugin_manager(data_dir, workspace=root).list_plugins()[0]["enabled"])
            self.assertTrue(SkillRegistry(LocalStore(data_dir / "aegis.db"), AuditLogger(data_dir / "audit.jsonl"), SecretsBroker(data_dir / "secrets.json")).get("test.plugin_skill")[1])

            disabled = manager.disable_plugin("test.plugin")
            self.assertFalse(disabled["plugin"]["enabled"])
            self.assertFalse(SkillRegistry(LocalStore(data_dir / "aegis.db"), AuditLogger(data_dir / "audit.jsonl"), SecretsBroker(data_dir / "secrets.json")).get("test.plugin_skill")[1])

            removed = manager.remove_plugin("test.plugin")
            self.assertTrue(removed["removed"])
            self.assertEqual(manager.list_plugins(), [])
            with self.assertRaises(KeyError):
                SkillRegistry(LocalStore(data_dir / "aegis.db"), AuditLogger(data_dir / "audit.jsonl"), SecretsBroker(data_dir / "secrets.json")).get("test.plugin_skill")
            with self.assertRaises(KeyError):
                McpRegistry(LocalStore(data_dir / "aegis.db"), AuditLogger(data_dir / "audit.jsonl")).get_server("plugin-mcp")
            self.assertFalse(any(hook["id"] == "test.plugin.hook" for hook in manager.hooks.list_hooks()))

    def test_plugin_install_requires_signed_skills_unless_unsigned_local(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            plugin_path = _write_plugin_fixture(root)
            manager = _plugin_manager(data_dir, workspace=root)

            with self.assertRaises(PermissionError):
                manager.install_plugin(plugin_path)

            self.assertEqual(manager.list_plugins(), [])

    def test_plugin_rejects_resource_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            plugin_path = root / "plugin.json"
            plugin_path.write_text(
                json.dumps(
                    {
                        "id": "test.bad_plugin",
                        "name": "Bad Plugin",
                        "version": "0.1.0",
                        "skills": [{"manifest_path": "../outside.json"}],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                _plugin_manager(data_dir, workspace=root).install_plugin(plugin_path, unsigned_local=True)

    def test_plugin_install_rolls_back_partial_resources_on_late_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            plugin_path = _write_plugin_fixture(root)
            plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
            plugin["hooks"][0]["command"] = "python3 -c print('bad')"
            plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
            manager = _plugin_manager(data_dir, workspace=root)

            with self.assertRaises(ValueError):
                manager.install_plugin(plugin_path, unsigned_local=True)

            self.assertEqual(manager.list_plugins(), [])
            with self.assertRaises(KeyError):
                SkillRegistry(LocalStore(data_dir / "aegis.db"), AuditLogger(data_dir / "audit.jsonl"), SecretsBroker(data_dir / "secrets.json")).get("test.plugin_skill")
            with self.assertRaises(KeyError):
                McpRegistry(LocalStore(data_dir / "aegis.db"), AuditLogger(data_dir / "audit.jsonl")).get_server("plugin-mcp")
            self.assertEqual(manager.hooks.list_hooks(), [])

    def test_plugin_marketplace_and_update_plan_are_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            plugin_path = _write_plugin_fixture(root)
            catalog_path = _write_plugin_catalog(root)
            manager = _plugin_manager(data_dir, workspace=root)
            manager.install_plugin(plugin_path, unsigned_local=True)

            marketplace = manager.marketplace(query="test", catalog_path=catalog_path)
            updates = manager.update_plan(catalog_path=catalog_path)
            serialized = json.dumps({"marketplace": marketplace, "updates": updates}, sort_keys=True)

            self.assertEqual(marketplace["status"], "virtual_marketplace_no_code_download")
            self.assertEqual(marketplace["catalog_source"], "local_file")
            self.assertEqual([entry["id"] for entry in marketplace["entries"]], ["test.plugin"])
            self.assertTrue(marketplace["entries"][0]["installed"])
            self.assertTrue(marketplace["entries"][0]["update_available"])
            self.assertFalse(marketplace["entries"][0]["download_supported"])
            self.assertTrue(marketplace["entries"][0]["manifest_fetch_supported"])
            self.assertTrue(marketplace["entries"][0]["marketplace_install_supported"])
            self.assertFalse(marketplace["entries"][0]["dynamic_code_import_supported"])
            self.assertEqual(updates["status"], "updates_available")
            self.assertEqual(updates["updates"][0]["id"], "test.plugin")
            self.assertEqual(updates["updates"][0]["installed_version"], "0.1.0")
            self.assertEqual(updates["updates"][0]["available_version"], "0.2.0")
            self.assertIn("remote_code_auto_install", updates["blocked_operations"])
            self.assertFalse(updates["raw_secret_values_included"])
            self.assertNotIn("token=", serialized)

    def test_plugin_marketplace_fetches_verified_manifest_for_review_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            body = json.dumps({"id": "remote.plugin", "name": "Remote Plugin", "version": "1.2.0"}).encode("utf-8")
            digest = sha256(body).hexdigest()
            bundle_body = b"remote plugin bundle bytes"
            bundle_digest = sha256(bundle_body).hexdigest()
            SecretsBroker(data_dir / "secrets.json").store_secret(name=DEFAULT_SKILL_SIGNING_KEY, value="bundle-signing-key")
            bundle_signature = hmac.new(b"bundle-signing-key", bundle_body, digestmod="sha256").hexdigest()
            catalog_path = root / "marketplace.json"
            catalog_path.write_text(
                json.dumps(
                    {
                        "plugins": [
                            {
                                "id": "remote.plugin",
                                "name": "Remote Plugin",
                                "version": "1.2.0",
                                "description": "Verified manifest fetch fixture.",
                                "manifest_url": "https://example.com/remote.plugin/plugin.json",
                                "manifest_sha256": f"sha256:{digest}",
                                "bundle_url": "https://example.com/remote.plugin/plugin.bundle",
                                "bundle_sha256": f"sha256:{bundle_digest}",
                                "bundle_signature": {
                                    "algorithm": SIGNATURE_ALGORITHM,
                                    "key_id": DEFAULT_SKILL_SIGNING_KEY,
                                    "digest": bundle_digest,
                                    "signature": bundle_signature,
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self, limit: int) -> bytes:
                    return body

            class FakeBundleResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self, limit: int) -> bytes:
                    return bundle_body

            manager = _plugin_manager(data_dir, workspace=root)
            with patch("aegis.plugins.manager._open_without_redirects", return_value=FakeResponse()):
                fetched = manager.fetch_marketplace_manifest("remote.plugin", catalog_path=catalog_path, allowlist=("example.com",))
            with patch("aegis.plugins.manager._open_without_redirects", return_value=FakeBundleResponse()):
                fetched_bundle = manager.fetch_marketplace_bundle("remote.plugin", catalog_path=catalog_path, allowlist=("example.com",))
            with patch("aegis.plugins.manager._open_without_redirects", return_value=FakeResponse()):
                installed = manager.install_marketplace_plugin("remote.plugin", catalog_path=catalog_path, allowlist=("example.com",))

            manifest_path = Path(fetched["manifest_path"])
            bundle_path = Path(fetched_bundle["bundle_path"])
            self.assertEqual(fetched["status"], "manifest_downloaded_for_review")
            self.assertEqual(fetched["manifest_sha256"], digest)
            self.assertFalse(fetched["auto_install_supported"])
            self.assertEqual(manifest_path.read_bytes(), body)
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
            self.assertEqual(fetched_bundle["status"], "bundle_downloaded_for_review")
            self.assertEqual(fetched_bundle["mode"], "sha256_and_signature_verified_bundle_review_only")
            self.assertEqual(fetched_bundle["bundle_sha256"], bundle_digest)
            self.assertEqual(fetched_bundle["signature"]["algorithm"], SIGNATURE_ALGORITHM)
            self.assertTrue(fetched_bundle["signature"]["signature_verified"])
            self.assertFalse(fetched_bundle["auto_install_supported"])
            self.assertFalse(fetched_bundle["dynamic_code_import_supported"])
            self.assertEqual(bundle_path.read_bytes(), bundle_body)
            self.assertEqual(stat.S_IMODE(bundle_path.stat().st_mode), 0o600)
            self.assertNotIn("bundle-signing-key", json.dumps(fetched_bundle, sort_keys=True))
            self.assertIn("plugins install", fetched["install_command"])
            self.assertEqual(installed["status"], "marketplace_plugin_installed")
            self.assertEqual(installed["plugin"]["id"], "remote.plugin")
            self.assertEqual(installed["fetch"]["manifest_sha256"], digest)
            self.assertIn("unattended_remote_bundle_auto_install", installed["blocked_operations"])
            self.assertEqual(manager.list_plugins()[0]["id"], "remote.plugin")
            self.assertNotIn("bundle-signing-key", (data_dir / "audit.jsonl").read_text(encoding="utf-8"))

            invalid_catalog_path = root / "invalid-marketplace.json"
            invalid_catalog_path.write_text(
                json.dumps(
                    {
                        "plugins": [
                            {
                                "id": "bad.plugin",
                                "name": "Bad Plugin",
                                "version": "1.0.0",
                                "manifest_url": "https://example.com/bad.plugin/plugin.json",
                                "manifest_sha256": "sha256:not-a-real-digest",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch("aegis.plugins.manager._open_without_redirects") as open_without_redirects:
                with self.assertRaises(ValueError):
                    manager.fetch_marketplace_manifest("bad.plugin", catalog_path=invalid_catalog_path, allowlist=("example.com",))
            open_without_redirects.assert_not_called()

    def test_plugin_marketplace_installs_verified_signed_bundle_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            bundle_body = json.dumps(
                {
                    "plugin": {
                        "id": "bundle.plugin",
                        "name": "Bundle Plugin",
                        "version": "2.0.0",
                        "description": "Installed from a signed marketplace bundle.",
                    }
                }
            ).encode("utf-8")
            bundle_digest = sha256(bundle_body).hexdigest()
            SecretsBroker(data_dir / "secrets.json").store_secret(name=DEFAULT_SKILL_SIGNING_KEY, value="bundle-signing-key")
            bundle_signature = hmac.new(b"bundle-signing-key", bundle_body, digestmod="sha256").hexdigest()
            catalog_path = root / "bundle-marketplace.json"
            catalog_path.write_text(
                json.dumps(
                    {
                        "plugins": [
                            {
                                "id": "bundle.plugin",
                                "name": "Bundle Plugin",
                                "version": "2.0.0",
                                "bundle_url": "https://example.com/bundle.plugin/plugin.bundle",
                                "bundle_sha256": f"sha256:{bundle_digest}",
                                "bundle_signature": {
                                    "algorithm": SIGNATURE_ALGORITHM,
                                    "key_id": DEFAULT_SKILL_SIGNING_KEY,
                                    "digest": bundle_digest,
                                    "signature": bundle_signature,
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            class FakeBundleResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self, limit: int) -> bytes:
                    return bundle_body

            manager = _plugin_manager(data_dir, workspace=root)
            with patch("aegis.plugins.manager._open_without_redirects", return_value=FakeBundleResponse()):
                installed = manager.install_marketplace_bundle("bundle.plugin", catalog_path=catalog_path, allowlist=("example.com",))

            self.assertEqual(installed["status"], "marketplace_bundle_installed")
            self.assertEqual(installed["mode"], "sha256_and_signature_verified_bundle_install")
            self.assertEqual(installed["fetch"]["bundle_sha256"], bundle_digest)
            self.assertTrue(installed["fetch"]["signature"]["signature_verified"])
            self.assertEqual(installed["plugin"]["id"], "bundle.plugin")
            self.assertEqual(installed["plugin"]["version"], "2.0.0")
            self.assertEqual(manager.list_plugins()[0]["source_path"], installed["manifest_path"])
            self.assertEqual(json.loads(Path(installed["manifest_path"]).read_text(encoding="utf-8"))["id"], "bundle.plugin")
            self.assertEqual(stat.S_IMODE(Path(installed["manifest_path"]).stat().st_mode), 0o600)
            self.assertFalse(installed["auto_install_supported"])
            self.assertTrue(installed["explicit_install_supported"])
            self.assertFalse(installed["dynamic_code_import_supported"])
            self.assertIn("unattended_remote_bundle_auto_install", installed["blocked_operations"])
            self.assertNotIn("bundle-signing-key", json.dumps(installed, sort_keys=True))
            self.assertNotIn("bundle-signing-key", (data_dir / "audit.jsonl").read_text(encoding="utf-8"))

    def test_plugin_marketplace_update_replaces_installed_plugin_with_verified_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            plugin_path = _write_plugin_fixture(root)
            manager = _plugin_manager(data_dir, workspace=root)
            installed = manager.install_plugin(plugin_path, unsigned_local=True)
            body = json.dumps({"id": "test.plugin", "name": "Test Plugin", "version": "0.2.0", "description": "Updated remotely."}).encode("utf-8")
            digest = sha256(body).hexdigest()
            catalog_path = root / "update-marketplace.json"
            catalog_path.write_text(
                json.dumps(
                    {
                        "plugins": [
                            {
                                "id": "test.plugin",
                                "name": "Test Plugin",
                                "version": "0.2.0",
                                "description": "Updated local catalog metadata.",
                                "manifest_url": "https://example.com/plugins/test.plugin/plugin.json",
                                "manifest_sha256": digest,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self, limit: int) -> bytes:
                    return body

            with patch("aegis.plugins.manager._open_without_redirects", return_value=FakeResponse()):
                updated = manager.update_marketplace_plugin("test.plugin", catalog_path=catalog_path, allowlist=("example.com",))

            self.assertEqual(installed["version"], "0.1.0")
            self.assertEqual(updated["status"], "marketplace_plugin_updated")
            self.assertEqual(updated["mode"], "sha256_verified_manifest_update")
            self.assertEqual(updated["previous_version"], "0.1.0")
            self.assertEqual(updated["plugin"]["version"], "0.2.0")
            self.assertEqual(updated["fetch"]["manifest_sha256"], digest)
            self.assertFalse(updated["auto_update_supported"])
            self.assertFalse(updated["provider_writes_performed"])
            self.assertIn("unattended_remote_plugin_auto_update", updated["blocked_operations"])
            self.assertTrue(Path(updated["rollback_manifest_path"]).exists())
            self.assertEqual(manager.list_plugins()[0]["description"], "Updated remotely.")
            with self.assertRaises(KeyError):
                SkillRegistry(LocalStore(data_dir / "aegis.db"), AuditLogger(data_dir / "audit.jsonl"), SecretsBroker(data_dir / "secrets.json")).get("test.plugin_skill")

    def test_plugin_marketplace_update_can_be_prepared_then_explicitly_applied(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            plugin_path = _write_plugin_fixture(root)
            manager = _plugin_manager(data_dir, workspace=root)
            manager.install_plugin(plugin_path, unsigned_local=True)
            body = json.dumps({"id": "test.plugin", "name": "Test Plugin", "version": "0.3.0", "description": "Prepared update."}).encode("utf-8")
            digest = sha256(body).hexdigest()
            catalog_path = root / "prepared-update-marketplace.json"
            catalog_path.write_text(
                json.dumps(
                    {
                        "plugins": [
                            {
                                "id": "test.plugin",
                                "name": "Test Plugin",
                                "version": "0.3.0",
                                "description": "Prepared update metadata.",
                                "manifest_url": "https://example.com/plugins/test.plugin/plugin.json",
                                "manifest_sha256": digest,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self, limit: int) -> bytes:
                    return body

            with patch("aegis.plugins.manager._open_without_redirects", return_value=FakeResponse()):
                prepared = manager.prepare_marketplace_update("test.plugin", catalog_path=catalog_path, allowlist=("example.com",))

            self.assertEqual(prepared["status"], "marketplace_update_prepared")
            self.assertEqual(prepared["mode"], "verified_manifest_update_candidate")
            self.assertEqual(prepared["previous_version"], "0.1.0")
            self.assertEqual(prepared["available_version"], "0.3.0")
            self.assertEqual(prepared["fetch"]["manifest_sha256"], digest)
            self.assertTrue(Path(prepared["candidate_path"]).exists())
            self.assertNotEqual(prepared["fetch"]["manifest_path"], prepared["fetch"]["source_manifest_path"])
            self.assertTrue(str(Path(prepared["fetch"]["manifest_path"]).parent).endswith("update-candidates"))
            self.assertEqual(Path(prepared["fetch"]["manifest_path"]).read_bytes(), body)
            self.assertFalse(prepared["auto_update_supported"])
            self.assertTrue(prepared["approved_apply_supported"])
            with self.assertRaises(PermissionError):
                manager.apply_prepared_marketplace_update(prepared["candidate_id"])

            applied = manager.apply_prepared_marketplace_update(prepared["candidate_id"], approved=True)
            candidate = json.loads(Path(prepared["candidate_path"]).read_text(encoding="utf-8"))

            self.assertEqual(applied["status"], "marketplace_prepared_update_applied")
            self.assertEqual(applied["mode"], "approved_verified_manifest_update_candidate")
            self.assertEqual(applied["candidate_id"], prepared["candidate_id"])
            self.assertEqual(applied["previous_version"], "0.1.0")
            self.assertEqual(applied["plugin"]["version"], "0.3.0")
            self.assertEqual(applied["manifest_sha256"], digest)
            self.assertFalse(applied["auto_update_supported"])
            self.assertTrue(applied["approved_candidate_apply_supported"])
            self.assertFalse(applied["provider_writes_performed"])
            self.assertEqual(candidate["status"], "applied")
            self.assertEqual(candidate["applied_plugin_version"], "0.3.0")
            self.assertEqual(manager.list_plugins()[0]["description"], "Prepared update.")
            with self.assertRaises(ValueError):
                manager.apply_prepared_marketplace_update(prepared["candidate_id"], approved=True)

    @unittest.skipUnless(os.name == "posix", "POSIX mode assertions only apply on POSIX")
    def test_plugin_store_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            _plugin_manager(data_dir, workspace=root).install_plugin(_write_plugin_fixture(root), unsigned_local=True)

            self.assertEqual(stat.S_IMODE((data_dir / "plugins.json").stat().st_mode), 0o600)


def _plugin_manager(data_dir: Path, *, workspace: Path) -> PluginManager:
    store = LocalStore(data_dir / "aegis.db")
    audit = AuditLogger(data_dir / "audit.jsonl")
    skills = SkillRegistry(store, audit, SecretsBroker(data_dir / "secrets.json"))
    mcp = McpRegistry(store, audit)
    hooks = HookManager(data_dir / "hooks.json", audit, allowed_executables=("python3",), workspace=workspace)
    return PluginManager(data_dir / "plugins.json", audit, skills=skills, mcp=mcp, hooks=hooks, secrets_broker=SecretsBroker(data_dir / "secrets.json"))


def _write_plugin_fixture(root: Path) -> Path:
    skill = builtin_project_summary_manifest()
    skill["id"] = "test.plugin_skill"
    skill["name"] = "Plugin Skill"
    skill_path = root / "skill.json"
    skill_path.write_text(json.dumps(skill), encoding="utf-8")
    plugin = {
        "id": "test.plugin",
        "name": "Test Plugin",
        "version": "0.1.0",
        "description": "Local plugin lifecycle fixture.",
        "skills": [{"manifest_path": "skill.json", "enabled": True}],
        "mcp_servers": [{"name": "plugin-mcp", "command": "python3 fake_mcp.py", "allowed_tools": ["echo"], "enabled": True}],
        "hooks": [{"id": "test.plugin.hook", "event": "manual", "command": ["python3", "-c", "print('plugin')"], "enabled": True, "approval_required": False}],
    }
    plugin_path = root / "plugin.json"
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
    return plugin_path


def _write_plugin_catalog(root: Path) -> Path:
    catalog_path = root / "marketplace.json"
    catalog_path.write_text(
        json.dumps(
            {
                "plugins": [
                    {
                        "id": "test.plugin",
                        "name": "Test Plugin",
                        "version": "0.2.0",
                        "description": "Updated local catalog metadata.",
                        "platforms": ["Hermes Agent"],
                        "tags": ["test", "plugin"],
                        "resource_kinds": ["skill", "mcp_server", "hook"],
                        "manifest_url": "https://example.com/plugins/test.plugin/plugin.json",
                        "manifest_sha256": "sha256:abc123",
                    },
                    {
                        "id": "other.plugin",
                        "name": "Other Plugin",
                        "version": "1.0.0",
                        "description": "Different plugin.",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    return catalog_path


if __name__ == "__main__":
    unittest.main()
