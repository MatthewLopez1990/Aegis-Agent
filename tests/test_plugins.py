from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from aegis.audit.logger import AuditLogger
from aegis.hooks.manager import HookManager
from aegis.mcp.registry import McpRegistry
from aegis.memory.store import LocalStore
from aegis.plugins.manager import PluginManager
from aegis.security.secrets_broker import SecretsBroker
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
    return PluginManager(data_dir / "plugins.json", audit, skills=skills, mcp=mcp, hooks=hooks)


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


if __name__ == "__main__":
    unittest.main()
