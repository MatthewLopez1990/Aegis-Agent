"""Local plugin install lifecycle.

Plugins are install manifests that bind existing governed extension types together.
They do not download code or bypass skill/MCP/hook controls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request
from uuid import uuid4
import hashlib
import hmac
import json
import re

from aegis.audit.logger import AuditLogger, redact
from aegis.connectors.http import _open_without_redirects, _private_network_error, _validate_url
from aegis.hooks.manager import HookManager
from aegis.mcp.registry import McpRegistry
from aegis.security.taint import now_utc
from aegis.skills.manifest import SkillManifest
from aegis.skills.registry import SkillRegistry
from aegis.skills.signing import DEFAULT_SKILL_SIGNING_KEY, SIGNATURE_ALGORITHM
from aegis.security.secrets_broker import SecretsBroker
from aegis.storage.state import ensure_private_dir, ensure_private_file


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
        secrets_broker: SecretsBroker | None = None,
    ) -> None:
        self.path = Path(path)
        self.audit_logger = audit_logger
        self.skills = skills
        self.mcp = mcp
        self.hooks = hooks
        self.secrets_broker = secrets_broker or SecretsBroker()

    def list_plugins(self) -> list[dict[str, Any]]:
        return sorted(self._read_store()["plugins"].values(), key=lambda plugin: str(plugin["id"]))

    def marketplace(self, *, query: str = "", catalog_path: str | Path | None = None) -> dict[str, Any]:
        catalog = _read_plugin_catalog(catalog_path)
        installed = {plugin["id"]: plugin for plugin in self.list_plugins()}
        needle = query.strip().lower()
        entries: list[dict[str, Any]] = []
        for entry in catalog:
            public = _public_marketplace_entry(entry, installed=installed.get(str(entry.get("id") or "")))
            haystack = " ".join(
                [
                    public["id"],
                    public["name"],
                    public["description"],
                    " ".join(public["tags"]),
                    " ".join(public["platforms"]),
                ]
            ).lower()
            if needle and needle not in haystack:
                continue
            entries.append(public)
        return {
            "status": "virtual_marketplace_no_code_download",
            "mode": "metadata_only_update_planning",
            "catalog_source": "local_file" if catalog_path else "built_in",
            "query": query,
            "entries": sorted(entries, key=lambda entry: entry["id"]),
            "raw_secret_values_included": False,
            "blocked_operations": [
                "remote_code_auto_install",
                "dynamic_plugin_import",
                "marketplace_token_capture",
                "unsigned_auto_update",
            ],
        }

    def update_plan(self, *, catalog_path: str | Path | None = None) -> dict[str, Any]:
        catalog = {str(entry.get("id") or ""): _public_marketplace_entry(entry) for entry in _read_plugin_catalog(catalog_path)}
        installed = self.list_plugins()
        updates: list[dict[str, Any]] = []
        current: list[dict[str, Any]] = []
        missing_from_catalog: list[dict[str, Any]] = []
        for plugin in installed:
            entry = catalog.get(plugin["id"])
            if entry is None:
                missing_from_catalog.append(
                    {
                        "id": plugin["id"],
                        "name": plugin["name"],
                        "installed_version": plugin["version"],
                        "status": "not_in_catalog",
                    }
                )
                continue
            row = {
                "id": plugin["id"],
                "name": plugin["name"] or entry["name"],
                "installed_version": plugin["version"],
                "available_version": entry["version"],
                "status": "update_available" if _version_newer(entry["version"], plugin["version"]) else "current",
                "install_mode": entry["install_mode"],
                "manifest_url": entry["manifest_url"],
                "manifest_sha256": entry["manifest_sha256"],
                "requires_review": entry["requires_review"],
                "next_actions": [
                    "review marketplace metadata",
                    "run plugins fetch-manifest <plugin_id> to verify the remote manifest",
                    "run plugins install-marketplace <plugin_id> for an explicit governed install",
                    "install through plugins install <plugin.json> using the existing governed lifecycle",
                ],
            }
            if row["status"] == "update_available":
                updates.append(row)
            else:
                current.append(row)
        return {
            "status": "updates_available" if updates else "no_updates",
            "mode": "metadata_only_update_planning",
            "catalog_source": "local_file" if catalog_path else "built_in",
            "updates": sorted(updates, key=lambda entry: entry["id"]),
            "current": sorted(current, key=lambda entry: entry["id"]),
            "missing_from_catalog": sorted(missing_from_catalog, key=lambda entry: entry["id"]),
            "raw_secret_values_included": False,
            "blocked_operations": [
                "remote_code_auto_install",
                "dynamic_plugin_import",
                "marketplace_token_capture",
                "unsigned_auto_update",
            ],
        }

    def fetch_marketplace_manifest(
        self,
        plugin_id: str,
        *,
        catalog_path: str | Path | None = None,
        allowlist: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        raw_catalog = {str(entry.get("id") or ""): entry for entry in _read_plugin_catalog(catalog_path)}
        raw_entry = raw_catalog.get(plugin_id)
        if raw_entry is None:
            raise KeyError(plugin_id)
        entry = _public_marketplace_entry(raw_entry)
        manifest_url = str(entry.get("manifest_url") or "")
        expected_sha256 = _normalize_sha256(str(entry.get("manifest_sha256") or ""))
        if not expected_sha256:
            raise ValueError("marketplace manifest download requires manifest_sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("marketplace manifest_sha256 must be a 64-character hex digest")
        parsed = urlparse(manifest_url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed)
        if validation_error:
            raise ValueError(validation_error)
        if parsed.scheme != "https":
            raise ValueError("marketplace manifest download requires https")
        if not _allowed_domain(domain, allowlist):
            raise ValueError(f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            raise ValueError(private_error)
        body = _download_marketplace_bytes(manifest_url, max_bytes=262_144, label="marketplace manifest")
        digest = hashlib.sha256(body).hexdigest()
        if digest != expected_sha256:
            raise ValueError("marketplace manifest SHA-256 does not match catalog metadata")
        decoded = json.loads(body.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("marketplace manifest must be a JSON object")
        if str(decoded.get("id") or "") != plugin_id:
            raise ValueError("marketplace manifest id does not match catalog entry")
        output_dir = ensure_private_dir(self.path.parent / "plugin-marketplace")
        output_path = ensure_private_file(output_dir / f"{plugin_id}.plugin.json")
        with output_path.open("wb") as handle:
            handle.write(body)
        ensure_private_file(output_path)
        result = {
            "status": "manifest_downloaded_for_review",
            "mode": "verified_manifest_only_no_dynamic_import",
            "id": plugin_id,
            "name": entry["name"],
            "version": entry["version"],
            "manifest_url": manifest_url,
            "manifest_sha256": digest,
            "manifest_path": str(output_path),
            "install_command": f"plugins install {output_path}",
            "auto_install_supported": False,
            "raw_secret_values_included": False,
            "blocked_operations": [
                "dynamic_plugin_import",
                "marketplace_token_capture",
                "unsigned_auto_update",
            ],
        }
        self.audit_logger.append("plugin.marketplace_manifest_downloaded", redact(result))
        return result

    def fetch_marketplace_bundle(
        self,
        plugin_id: str,
        *,
        catalog_path: str | Path | None = None,
        allowlist: tuple[str, ...] = (),
        key_name: str = DEFAULT_SKILL_SIGNING_KEY,
    ) -> dict[str, Any]:
        raw_catalog = {str(entry.get("id") or ""): entry for entry in _read_plugin_catalog(catalog_path)}
        raw_entry = raw_catalog.get(plugin_id)
        if raw_entry is None:
            raise KeyError(plugin_id)
        entry = _public_marketplace_entry(raw_entry)
        bundle_url = str(entry.get("bundle_url") or "")
        expected_sha256 = _normalize_sha256(str(entry.get("bundle_sha256") or ""))
        if not bundle_url:
            raise ValueError("marketplace bundle download requires bundle_url")
        if not expected_sha256:
            raise ValueError("marketplace bundle download requires bundle_sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("marketplace bundle_sha256 must be a 64-character hex digest")
        parsed = urlparse(bundle_url)
        domain = parsed.hostname or ""
        validation_error = _validate_url(parsed)
        if validation_error:
            raise ValueError(validation_error)
        if parsed.scheme != "https":
            raise ValueError("marketplace bundle download requires https")
        if not _allowed_domain(domain, allowlist):
            raise ValueError(f"domain {domain!r} is not allowlisted")
        private_error = _private_network_error(domain)
        if private_error:
            raise ValueError(private_error)
        body = _download_marketplace_bytes(bundle_url, max_bytes=1_048_576, label="marketplace bundle")
        digest = hashlib.sha256(body).hexdigest()
        if digest != expected_sha256:
            raise ValueError("marketplace bundle SHA-256 does not match catalog metadata")
        signature = _verify_bundle_signature(
            body,
            raw_entry.get("bundle_signature"),
            self.secrets_broker,
            key_name=key_name,
            expected_digest=digest,
        )
        output_dir = ensure_private_dir(self.path.parent / "plugin-marketplace")
        output_path = ensure_private_file(output_dir / f"{plugin_id}.bundle")
        with output_path.open("wb") as handle:
            handle.write(body)
        ensure_private_file(output_path)
        result = {
            "status": "bundle_downloaded_for_review",
            "mode": "sha256_and_signature_verified_bundle_review_only",
            "id": plugin_id,
            "name": entry["name"],
            "version": entry["version"],
            "bundle_url": bundle_url,
            "bundle_sha256": digest,
            "bundle_path": str(output_path),
            "signature": signature,
            "auto_install_supported": False,
            "dynamic_code_import_supported": False,
            "raw_secret_values_included": False,
            "blocked_operations": [
                "remote_bundle_auto_install",
                "dynamic_plugin_import",
                "marketplace_token_capture",
                "unsigned_auto_update",
            ],
        }
        self.audit_logger.append("plugin.marketplace_bundle_downloaded", redact(result))
        return result

    def install_marketplace_plugin(
        self,
        plugin_id: str,
        *,
        catalog_path: str | Path | None = None,
        allowlist: tuple[str, ...] = (),
        enable: bool = False,
    ) -> dict[str, Any]:
        fetched = self.fetch_marketplace_manifest(plugin_id, catalog_path=catalog_path, allowlist=allowlist)
        plugin = self.install_plugin(fetched["manifest_path"], enable=enable, unsigned_local=False)
        result = {
            "status": "marketplace_plugin_installed",
            "mode": "sha256_verified_manifest_install",
            "fetch": {
                "id": fetched["id"],
                "manifest_url": fetched["manifest_url"],
                "manifest_sha256": fetched["manifest_sha256"],
                "manifest_path": fetched["manifest_path"],
            },
            "plugin": plugin,
            "enabled": bool(plugin.get("enabled", False)),
            "raw_secret_values_included": False,
            "blocked_operations": [
                "remote_bundle_auto_install",
                "dynamic_plugin_import",
                "marketplace_token_capture",
                "unsigned_auto_update",
            ],
        }
        self.audit_logger.append("plugin.marketplace_installed", redact(result))
        return result

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


def _read_plugin_catalog(catalog_path: str | Path | None = None) -> list[dict[str, Any]]:
    if catalog_path:
        path = Path(catalog_path).expanduser().resolve()
        if path.suffix.lower() != ".json":
            raise ValueError("plugin marketplace catalog must be a JSON file")
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    else:
        raw = {"plugins": _BUILT_IN_MARKETPLACE}
    entries = raw.get("plugins") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("plugin marketplace catalog must contain a plugins array")
    result: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("plugin marketplace entries must be JSON objects")
        plugin_id = str(entry.get("id") or "").strip()
        if not _PLUGIN_ID_RE.fullmatch(plugin_id):
            raise ValueError("marketplace plugin id must be 1-120 characters of letters, digits, dot, underscore, or dash")
        result.append(entry)
    return result


def _allowed_domain(domain: str, allowlist: tuple[str, ...]) -> bool:
    return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowlist)


def _normalize_sha256(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("sha256:"):
        return text.removeprefix("sha256:")
    return text


def _download_marketplace_bytes(url: str, *, max_bytes: int, label: str) -> bytes:
    request = Request(url, headers={"User-Agent": "Aegis-Agent/0.1"})
    try:
        response_context = _open_without_redirects(request, timeout=10)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError(f"HTTP redirects are not followed for {label}s") from exc
        raise ValueError(f"{label} download failed with status {exc.code}") from exc
    except URLError as exc:
        raise ValueError(f"{label} download failed: {exc.reason}") from exc
    with response_context as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} byte limit")
    return body


def _verify_bundle_signature(
    body: bytes,
    signature: Any,
    broker: SecretsBroker,
    *,
    key_name: str,
    expected_digest: str,
) -> dict[str, Any]:
    if isinstance(signature, dict):
        if signature.get("algorithm") != SIGNATURE_ALGORITHM:
            raise ValueError("marketplace bundle signature uses unsupported algorithm")
        actual_key_name = str(signature.get("key_id") or key_name)
        if actual_key_name != key_name:
            raise ValueError("marketplace bundle signature key_id does not match requested key")
        signature_digest = str(signature.get("digest") or "")
        if signature_digest and signature_digest != expected_digest:
            raise ValueError("marketplace bundle signature digest does not match bundle")
        signature_hex = str(signature.get("signature") or "")
    else:
        actual_key_name = key_name
        signature_hex = str(signature or "")
    if not re.fullmatch(r"[0-9a-f]{64}", signature_hex):
        raise ValueError("marketplace bundle signature must be a 64-character hex HMAC")
    try:
        key = broker.resolve_stored_secret(actual_key_name)
    except KeyError as exc:
        raise ValueError("marketplace bundle signing key is not configured") from exc
    expected_signature = hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature_hex, expected_signature):
        raise ValueError("marketplace bundle signature mismatch")
    return {
        "ok": True,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": actual_key_name,
        "digest": expected_digest,
        "signature_verified": True,
        "raw_secret_values_included": False,
    }


def _public_marketplace_entry(raw: dict[str, Any], *, installed: dict[str, Any] | None = None) -> dict[str, Any]:
    resource_kinds = _string_list(raw.get("resource_kinds", raw.get("resources", [])))
    manifest_url = str(raw.get("manifest_url") or "")
    manifest_sha256 = str(raw.get("manifest_sha256") or "")
    bundle_url = str(raw.get("bundle_url") or "")
    bundle_sha256 = str(raw.get("bundle_sha256") or "")
    verified_manifest_available = bool(manifest_url and _normalize_sha256(manifest_sha256))
    verified_bundle_available = bool(bundle_url and _normalize_sha256(bundle_sha256) and raw.get("bundle_signature"))
    entry = {
        "id": str(raw.get("id") or ""),
        "name": str(raw.get("name") or raw.get("id") or ""),
        "version": str(raw.get("version") or "0.0.0"),
        "description": str(raw.get("description") or ""),
        "platforms": _string_list(raw.get("platforms", [])),
        "tags": _string_list(raw.get("tags", [])),
        "resource_kinds": resource_kinds,
        "install_mode": str(raw.get("install_mode") or "manual_manifest_review"),
        "manifest_url": manifest_url,
        "manifest_sha256": manifest_sha256,
        "bundle_url": bundle_url,
        "bundle_sha256": bundle_sha256,
        "bundle_signature": raw.get("bundle_signature"),
        "bundle_signature_required": bool(bundle_url),
        "requires_review": bool(raw.get("requires_review", True)),
        "download_supported": False,
        "manifest_fetch_supported": verified_manifest_available,
        "bundle_fetch_supported": verified_bundle_available,
        "marketplace_install_supported": verified_manifest_available,
        "dynamic_code_import_supported": False,
        "token_capture_supported": False,
        "installed": installed is not None,
        "installed_version": str(installed.get("version") or "") if installed else "",
        "update_available": bool(installed and _version_newer(str(raw.get("version") or "0.0.0"), str(installed.get("version") or "0.0.0"))),
        "next_actions": [
            "review marketplace metadata",
            "run plugins fetch-manifest <plugin_id> to verify the remote manifest",
            "run plugins install-marketplace <plugin_id> for an explicit governed install",
            "install through the existing governed plugin lifecycle",
        ],
    }
    return redact(entry)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, dict):
            kind = item.get("kind")
            if kind:
                result.append(str(kind))
            continue
        text = str(item).strip()
        if text:
            result.append(text)
    return sorted(set(result))


def _version_newer(candidate: str, installed: str) -> bool:
    return _version_key(candidate) > _version_key(installed)


def _version_key(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value)
    if not parts:
        return (0,)
    return tuple(int(part) for part in parts[:4])


_BUILT_IN_MARKETPLACE = [
    {
        "id": "aegis.github-workflow",
        "name": "GitHub Workflow Pack",
        "version": "0.1.0",
        "description": "Governed issue, PR, and CI workflow helpers routed through existing connector and approval controls.",
        "platforms": ["Hermes Agent", "Claude Code parity"],
        "tags": ["github", "workflow", "automation"],
        "resource_kinds": ["skill", "hook"],
        "install_mode": "manual_manifest_review",
        "manifest_url": "https://example.com/aegis/plugins/github-workflow/plugin.json",
        "manifest_sha256": "",
        "requires_review": True,
    },
    {
        "id": "aegis.remote-operator",
        "name": "Remote Operator Pack",
        "version": "0.1.0",
        "description": "Remote-control task triage and notification helpers for the local pairing-token control plane.",
        "platforms": ["Hermes Agent", "OpenClaw"],
        "tags": ["remote-control", "mobile", "operator"],
        "resource_kinds": ["skill", "hook"],
        "install_mode": "manual_manifest_review",
        "manifest_url": "https://example.com/aegis/plugins/remote-operator/plugin.json",
        "manifest_sha256": "",
        "requires_review": True,
    },
    {
        "id": "aegis.research-pipeline",
        "name": "Research Pipeline Pack",
        "version": "0.1.0",
        "description": "Research trajectory and evaluation workflow helpers that preserve audit and prompt-boundary controls.",
        "platforms": ["Hermes Agent"],
        "tags": ["research", "evaluation", "workflow"],
        "resource_kinds": ["skill", "mcp_server"],
        "install_mode": "manual_manifest_review",
        "manifest_url": "https://example.com/aegis/plugins/research-pipeline/plugin.json",
        "manifest_sha256": "",
        "requires_review": True,
    },
]
