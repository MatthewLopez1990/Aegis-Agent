"""Local plugin install lifecycle.

Plugins are install manifests that bind existing governed extension types together.
They do not download code or bypass skill/MCP/hook controls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4
import json
import re

from aegis.audit.logger import AuditLogger, redact
from aegis.hooks.manager import HookManager
from aegis.mcp.registry import McpRegistry
from aegis.security.taint import now_utc
from aegis.skills.manifest import SkillManifest
from aegis.skills.registry import SkillRegistry
from aegis.storage.state import ensure_private_file


_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")


class PluginManager:
    """Installs local plugin manifests through existing governed registries."""

    def __init__(
        self,
        path: str | Path,
        audit_logger: AuditLogger,
        *,
        skills: SkillRegistry,
        mcp: McpRegistry,
        hooks: HookManager,
    ) -> None:
        self.path = Path(path)
        self.audit_logger = audit_logger
        self.skills = skills
        self.mcp = mcp
        self.hooks = hooks

    def list_plugins(self) -> list[dict[str, Any]]:
        return sorted(self._read_store()["plugins"].values(), key=lambda plugin: str(plugin["id"]))

    def install_plugin(
        self,
        manifest_path: str | Path,
        *,
        enable: bool = False,
        unsigned_local: bool = False,
    ) -> dict[str, Any]:
        path = Path(manifest_path).expanduser().resolve()
        raw = _read_plugin_manifest(path)
        plugin_id = str(raw.get("id") or "").strip()
        if not _PLUGIN_ID_RE.fullmatch(plugin_id):
            raise ValueError("plugin id must be 1-120 characters of letters, digits, dot, underscore, or dash")
        store = self._read_store()
        if plugin_id in store["plugins"]:
            raise KeyError(plugin_id)
        installed_resources: list[dict[str, Any]] = []
        root = path.parent
        try:
            for skill_spec in _list_value(raw, "skills"):
                skill_manifest = SkillManifest.from_dict(_load_skill_manifest(skill_spec, root=root))
                self._ensure_skill_absent(skill_manifest.id)
                default_enabled = bool(skill_spec.get("enabled", False))
                registered = self.skills.register(
                    skill_manifest,
                    enable=bool(enable and default_enabled),
                    require_signature=not unsigned_local,
                )
                _, skill_enabled = self.skills.get(registered.id)
                installed_resources.append(
                    {
                        "kind": "skill",
                        "id": registered.id,
                        "default_enabled": default_enabled,
                        "enabled": bool(skill_enabled),
                    }
                )
            for server_spec in _list_value(raw, "mcp_servers"):
                name = str(_required(server_spec, "name"))
                self._ensure_mcp_name_absent(name)
                tools = server_spec.get("allowed_tools", server_spec.get("tools", []))
                if not isinstance(tools, list):
                    raise ValueError("mcp server allowed_tools must be a JSON array")
                default_enabled = bool(server_spec.get("enabled", False))
                server = self.mcp.register_server(
                    name=name,
                    command=str(_required(server_spec, "command")),
                    allowed_tools=tuple(str(tool) for tool in tools),
                    enabled=bool(enable and default_enabled),
                    approval_required=bool(server_spec.get("approval_required", True)),
                    metadata={"source": "plugin", "plugin_id": plugin_id},
                )
                installed_resources.append(
                    {
                        "kind": "mcp_server",
                        "id": server["id"],
                        "name": server["name"],
                        "default_enabled": default_enabled,
                        "enabled": bool(server["enabled"]),
                    }
                )
            for hook_spec in _list_value(raw, "hooks"):
                command = hook_spec.get("command")
                if not isinstance(command, list):
                    raise ValueError("hook command must be a JSON array")
                default_enabled = bool(hook_spec.get("enabled", False))
                hook = self.hooks.register_hook(
                    event=str(_required(hook_spec, "event")),
                    command=[str(part) for part in command],
                    hook_id=str(hook_spec.get("id") or f"{plugin_id}.{uuid4().hex[:8]}"),
                    enabled=bool(enable and default_enabled),
                    approval_required=bool(hook_spec.get("approval_required", True)),
                    timeout_seconds=int(hook_spec.get("timeout_seconds", 10)),
                    max_output_bytes=int(hook_spec.get("max_output_bytes", 4096)),
                )
                installed_resources.append(
                    {
                        "kind": "hook",
                        "id": hook["id"],
                        "event": hook["event"],
                        "default_enabled": default_enabled,
                        "enabled": bool(hook["enabled"]),
                    }
                )
        except Exception:
            self._rollback_install_resources(installed_resources)
            raise
        installed = {
            "id": plugin_id,
            "name": str(raw.get("name") or plugin_id),
            "version": str(raw.get("version") or "0.0.0"),
            "description": str(raw.get("description") or ""),
            "source_path": str(path),
            "enabled": bool(enable and all((not resource.get("default_enabled")) or resource.get("enabled") for resource in installed_resources)),
            "installed_at": now_utc(),
            "updated_at": now_utc(),
            "unsigned_local": bool(unsigned_local),
            "resources": installed_resources,
        }
        store["plugins"][plugin_id] = installed
        self._write_store(store)
        self.audit_logger.append("plugin.installed", _plugin_audit_payload(installed))
        return _public_plugin(installed)

    def enable_plugin(self, plugin_id: str) -> dict[str, Any]:
        return self._set_plugin_enabled(plugin_id, True)

    def disable_plugin(self, plugin_id: str) -> dict[str, Any]:
        return self._set_plugin_enabled(plugin_id, False)

    def remove_plugin(self, plugin_id: str) -> dict[str, Any]:
        store = self._read_store()
        plugin = store["plugins"].pop(plugin_id, None)
        if plugin is None:
            raise KeyError(plugin_id)
        removed: list[dict[str, Any]] = []
        for resource in plugin.get("resources", []):
            try:
                if resource.get("kind") == "skill":
                    removed.append({"kind": "skill", **self.skills.remove(str(resource["id"]))})
                elif resource.get("kind") == "mcp_server":
                    removed_server = self.mcp.remove_server(str(resource["id"]))
                    removed.append({"kind": "mcp_server", "id": removed_server["id"], "name": removed_server["name"]})
                elif resource.get("kind") == "hook":
                    removed_hook = self.hooks.remove_hook(str(resource["id"]))
                    removed.append({"kind": "hook", "id": removed_hook["id"], "event": removed_hook["event"]})
            except KeyError:
                removed.append({"kind": str(resource.get("kind") or "unknown"), "id": str(resource.get("id") or ""), "status": "already_missing"})
        self._write_store(store)
        payload = {"plugin_id": plugin_id, "removed_resources": removed}
        self.audit_logger.append("plugin.removed", redact(payload))
        return {"plugin": _public_plugin(plugin), "removed": True, "removed_resources": removed}

    def _set_plugin_enabled(self, plugin_id: str, enabled: bool) -> dict[str, Any]:
        store = self._read_store()
        plugin = store["plugins"].get(plugin_id)
        if plugin is None:
            raise KeyError(plugin_id)
        results: list[dict[str, Any]] = []
        for resource in plugin.get("resources", []):
            should_enable = enabled and bool(resource.get("default_enabled", False))
            try:
                if resource.get("kind") == "skill":
                    if should_enable:
                        self.skills.enable(str(resource["id"]))
                    else:
                        self.skills.disable(str(resource["id"]))
                    resource["enabled"] = should_enable
                    results.append({"kind": "skill", "id": resource["id"], "enabled": should_enable})
                elif resource.get("kind") == "mcp_server":
                    self.mcp.set_enabled(str(resource["id"]), should_enable)
                    resource["enabled"] = should_enable
                    results.append({"kind": "mcp_server", "id": resource["id"], "enabled": should_enable})
                elif resource.get("kind") == "hook":
                    self.hooks.set_enabled(str(resource["id"]), should_enable)
                    resource["enabled"] = should_enable
                    results.append({"kind": "hook", "id": resource["id"], "enabled": should_enable})
            except (KeyError, PermissionError, ValueError) as exc:
                results.append({"kind": str(resource.get("kind") or "unknown"), "id": str(resource.get("id") or ""), "enabled": False, "blocked": str(exc)})
        plugin["enabled"] = bool(enabled and not any("blocked" in result for result in results))
        plugin["updated_at"] = now_utc()
        self._write_store(store)
        self.audit_logger.append("plugin.enabled" if enabled else "plugin.disabled", {"plugin_id": plugin_id, "enabled": plugin["enabled"], "resources": results})
        return {"plugin": _public_plugin(plugin), "resources": results}

    def _ensure_skill_absent(self, skill_id: str) -> None:
        try:
            self.skills.get(skill_id)
        except KeyError:
            return
        raise KeyError(f"skill already registered: {skill_id}")

    def _ensure_mcp_name_absent(self, name: str) -> None:
        try:
            self.mcp.get_server(name)
        except KeyError:
            return
        raise KeyError(f"MCP server already registered: {name}")

    def _rollback_install_resources(self, resources: list[dict[str, Any]]) -> None:
        if not resources:
            return
        rolled_back: list[dict[str, Any]] = []
        for resource in reversed(resources):
            kind = str(resource.get("kind") or "unknown")
            resource_id = str(resource.get("id") or "")
            try:
                if kind == "skill":
                    self.skills.remove(resource_id)
                elif kind == "mcp_server":
                    self.mcp.remove_server(resource_id)
                elif kind == "hook":
                    self.hooks.remove_hook(resource_id)
                rolled_back.append({"kind": kind, "id": resource_id, "status": "removed"})
            except Exception as exc:  # pragma: no cover - best-effort cleanup should not hide the install error.
                rolled_back.append({"kind": kind, "id": resource_id, "status": "cleanup_failed", "reason": str(exc)})
        self.audit_logger.append("plugin.install_rolled_back", redact({"resources": rolled_back}))

    def _read_store(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "plugins": {}}
        with self.path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        plugins = raw.get("plugins", {}) if isinstance(raw, dict) else {}
        if not isinstance(plugins, dict):
            plugins = {}
        return {"version": 1, "plugins": {str(key): _public_plugin(value) for key, value in plugins.items() if isinstance(value, dict)}}

    def _write_store(self, store: dict[str, Any]) -> None:
        ensure_private_file(self.path)
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump({"version": 1, "plugins": store.get("plugins", {})}, handle, indent=2, sort_keys=True)
            handle.write("\n")
        ensure_private_file(self.path)


def _read_plugin_manifest(path: Path) -> dict[str, Any]:
    if not path.name.endswith(".json"):
        raise ValueError("plugin manifest must be a JSON file")
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("plugin manifest must be a JSON object")
    return raw


def _load_skill_manifest(spec: dict[str, Any], *, root: Path) -> dict[str, Any]:
    if "manifest" in spec and isinstance(spec["manifest"], dict):
        return dict(spec["manifest"])
    manifest = spec.get("manifest_path")
    if not isinstance(manifest, str) or not manifest:
        raise ValueError("skill plugin entries require manifest_path or inline manifest")
    path = _safe_plugin_child(root, manifest)
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("skill manifest must be a JSON object")
    return raw


def _safe_plugin_child(root: Path, relative_path: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise ValueError("plugin resource paths must be relative to the plugin manifest")
    resolved = (root / candidate).resolve()
    if root not in (resolved, *resolved.parents):
        raise ValueError("plugin resource path escapes the plugin directory")
    return resolved


def _list_value(raw: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = raw.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"plugin {key} must be a JSON array")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"plugin {key} entries must be JSON objects")
        result.append(item)
    return result


def _required(raw: dict[str, Any], key: str) -> Any:
    if key not in raw:
        raise ValueError(f"missing required field: {key}")
    return raw[key]


def _public_plugin(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(raw.get("id") or ""),
        "name": str(raw.get("name") or raw.get("id") or ""),
        "version": str(raw.get("version") or ""),
        "description": str(raw.get("description") or ""),
        "source_path": str(raw.get("source_path") or ""),
        "enabled": bool(raw.get("enabled", False)),
        "installed_at": str(raw.get("installed_at") or ""),
        "updated_at": str(raw.get("updated_at") or ""),
        "unsigned_local": bool(raw.get("unsigned_local", False)),
        "resources": [dict(resource) for resource in raw.get("resources", []) if isinstance(resource, dict)],
    }


def _plugin_audit_payload(plugin: dict[str, Any]) -> dict[str, Any]:
    return {
        "plugin_id": plugin["id"],
        "name": plugin["name"],
        "version": plugin["version"],
        "enabled": plugin["enabled"],
        "unsigned_local": plugin["unsigned_local"],
        "resource_count": len(plugin["resources"]),
        "resources": [{"kind": resource.get("kind"), "id": resource.get("id")} for resource in plugin["resources"]],
    }
