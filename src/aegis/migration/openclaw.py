"""Dry-run import helpers for OpenClaw/Hermes style local data."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from aegis.memory.manager import SECRET_LIKE
from aegis.memory.models import MemoryType
from aegis.security.context_firewall import redact_secret_values
from aegis.security.taint import Sensitivity

_MAX_IMPORT_FILE_BYTES = 128_000
_MAX_CANDIDATES = 100
_MAX_INVENTORY_ITEMS = 100
_SUPPORTED_MEMORY_SUFFIXES = {".md", ".markdown", ".txt", ".json", ".jsonl"}
_SUPPORTED_METADATA_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".mdc",
    ".py",
    ".sh",
}
_SECRET_PATH_MARKERS = ("secret", "token", "credential", "apikey", "api_key", "password", ".env", "oauth")
_CONTEXT_FILENAMES = {
    "SOUL.md",
    "MEMORY.md",
    "USER.md",
    "AGENTS.md",
    "CLAUDE.md",
    ".hermes.md",
    "HERMES.md",
    ".cursorrules",
    "TOOLS.md",
}


def inspect_openclaw_home(path: str | Path) -> dict[str, Any]:
    root = Path(path).expanduser()
    candidates = {
        "SOUL.md": root / "SOUL.md",
        "MEMORY.md": root / "MEMORY.md",
        "USER.md": root / "USER.md",
        "AGENTS.md": root / "AGENTS.md",
        "skills": root / "skills",
        "config": root / "openclaw.yaml",
    }
    inventory = _inventory_home(
        root,
        config_files=[
            root / "openclaw.yaml",
            root / "openclaw.yml",
            root / "config.yaml",
            root / "config.yml",
            root / "config.json",
            root / "settings.json",
        ],
        memory_dirs=[root / "memory", root / "memories"],
        session_dirs=[root / "sessions", root / "conversations"],
        skill_dirs=[root / "skills"],
        plugin_dirs=[root / "plugins"],
        schedule_dirs=[root / "schedules", root / "jobs"],
        process_dirs=[root / "processes", root / "bashes"],
    )
    return {
        "root": str(root),
        "exists": root.exists(),
        "found": {name: target.exists() for name, target in candidates.items()},
        "mode": "dry_run_only",
        "inventory_mode": "metadata_only_inventory",
        "inventory": inventory["inventory"],
        "inventory_counts": inventory["counts"],
        "blocked_inventory": inventory["blocked"],
        "raw_content_included": False,
        "secrets_import": "blocked_by_default_use_secrets_broker",
    }


def preview_openclaw_memory_import(path: str | Path, *, owner: str = "local-user", scope: str = "workspace") -> dict[str, Any]:
    root = Path(path).expanduser()
    files = [
        root / "MEMORY.md",
        root / "USER.md",
        root / "SOUL.md",
        root / "AGENTS.md",
    ]
    files.extend(_iter_supported_files(root / "memory"))
    files.extend(_iter_supported_files(root / "sessions"))
    return _preview_memory_import(root, platform="openclaw", files=files, owner=owner, scope=scope)


def inspect_hermes_home(path: str | Path) -> dict[str, Any]:
    root = Path(path).expanduser()
    candidates = {
        "SOUL.md": root / "SOUL.md",
        "memory": root / "memory",
        "skills": root / "skills",
        "config": root / "config.yaml",
        "sessions": root / "sessions",
    }
    inventory = _inventory_home(
        root,
        config_files=[
            root / "config.yaml",
            root / "config.yml",
            root / "config.json",
            root / "settings.json",
            root / "hermes.yaml",
            root / "hermes.yml",
        ],
        memory_dirs=[root / "memory", root / "memories"],
        session_dirs=[root / "sessions", root / "conversations", root / "chats"],
        skill_dirs=[root / "skills", root / "procedures"],
        plugin_dirs=[root / "plugins", root / "extensions"],
        schedule_dirs=[root / "cron", root / "jobs", root / "schedules"],
        process_dirs=[root / "processes", root / "terminals", root / "shells"],
    )
    return {
        "root": str(root),
        "exists": root.exists(),
        "found": {name: target.exists() for name, target in candidates.items()},
        "mode": "dry_run_only",
        "inventory_mode": "metadata_only_inventory",
        "inventory": inventory["inventory"],
        "inventory_counts": inventory["counts"],
        "blocked_inventory": inventory["blocked"],
        "raw_content_included": False,
        "secrets_import": "blocked_by_default_use_secrets_broker",
    }


def preview_hermes_memory_import(path: str | Path, *, owner: str = "local-user", scope: str = "workspace") -> dict[str, Any]:
    root = Path(path).expanduser()
    files = [root / "SOUL.md"]
    files.extend(_iter_supported_files(root / "memory"))
    files.extend(_iter_supported_files(root / "sessions"))
    files.extend(_iter_supported_files(root / "skills"))
    return _preview_memory_import(root, platform="hermes", files=files, owner=owner, scope=scope)


def _preview_memory_import(root: Path, *, platform: str, files: list[Path], owner: str, scope: str) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    root_path = root.expanduser()
    root_resolved = root_path.resolve(strict=False)
    seen: set[Path] = set()
    for file_path in files:
        if len(candidates) >= _MAX_CANDIDATES:
            break
        display_path = file_path.expanduser()
        if not display_path.exists() or not display_path.is_file() or display_path.suffix.lower() not in _SUPPORTED_MEMORY_SUFFIXES:
            continue
        try:
            resolved = display_path.resolve(strict=True)
        except OSError as exc:
            blocked.append(_blocked_file(display_path, root=root_path, reason=f"resolve_failed:{exc.__class__.__name__}"))
            continue
        if resolved in seen:
            continue
        if root_resolved not in (resolved, *resolved.parents):
            blocked.append(_blocked_file(display_path, root=root_path, reason="outside_import_root"))
            seen.add(resolved)
            continue
        seen.add(resolved)
        try:
            if resolved.stat().st_size > _MAX_IMPORT_FILE_BYTES:
                blocked.append(_blocked_file(display_path, root=root_path, reason="file_too_large"))
                continue
            raw = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            blocked.append(_blocked_file(display_path, root=root_path, reason=f"read_failed:{exc.__class__.__name__}"))
            continue
        for index, content in enumerate(_extract_candidate_texts(raw, suffix=resolved.suffix.lower()), start=1):
            if len(candidates) >= _MAX_CANDIDATES:
                break
            candidate = _candidate_from_text(
                content,
                platform=platform,
                root=root_path,
                path=display_path,
                index=index,
                owner=owner,
                scope=scope,
            )
            if candidate["blocked"]:
                blocked.append(candidate)
            else:
                candidates.append(candidate)
    return {
        "root": str(root_path),
        "exists": root_path.exists(),
        "mode": "dry_run_memory_preview",
        "platform": platform,
        "candidate_count": len(candidates),
        "blocked_count": len(blocked),
        "candidates": candidates,
        "blocked": blocked,
        "limits": {"max_file_bytes": _MAX_IMPORT_FILE_BYTES, "max_candidates": _MAX_CANDIDATES},
        "persistence": "not_persisted_requires_explicit_memory_create_or_review_flow",
        "secrets_import": "blocked_by_default_use_secrets_broker",
    }


def _iter_supported_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    return sorted(item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in _SUPPORTED_MEMORY_SUFFIXES)


def _inventory_home(
    root: Path,
    *,
    config_files: list[Path],
    memory_dirs: list[Path],
    session_dirs: list[Path],
    skill_dirs: list[Path],
    plugin_dirs: list[Path],
    schedule_dirs: list[Path],
    process_dirs: list[Path],
) -> dict[str, Any]:
    blocked: list[dict[str, Any]] = []
    inventory = {
        "context_files": _metadata_entries(_iter_context_files(root), root=root, kind="context_file", blocked=blocked),
        "config_files": _metadata_entries(config_files, root=root, kind="config_file", blocked=blocked),
        "memory_files": _metadata_entries(_iter_inventory_files(memory_dirs), root=root, kind="memory_file", blocked=blocked),
        "session_files": _metadata_entries(_iter_inventory_files(session_dirs), root=root, kind="session_file", blocked=blocked),
        "skill_files": _metadata_entries(_iter_inventory_files(skill_dirs), root=root, kind="skill_file", blocked=blocked),
        "plugin_files": _metadata_entries(_iter_inventory_files(plugin_dirs), root=root, kind="plugin_file", blocked=blocked),
        "schedule_files": _metadata_entries(_iter_inventory_files(schedule_dirs), root=root, kind="schedule_file", blocked=blocked),
        "process_files": _metadata_entries(_iter_inventory_files(process_dirs), root=root, kind="process_file", blocked=blocked),
    }
    return {
        "inventory": inventory,
        "counts": {name: len(entries) for name, entries in inventory.items()},
        "blocked": blocked[:_MAX_INVENTORY_ITEMS],
    }


def _iter_inventory_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if not path.exists():
            continue
        if path.is_file():
            if path.suffix.lower() in _SUPPORTED_METADATA_SUFFIXES:
                files.append(path)
            continue
        if path.is_dir():
            for item in sorted(path.rglob("*")):
                if len(files) >= _MAX_INVENTORY_ITEMS:
                    return files
                if item.is_file() and item.suffix.lower() in _SUPPORTED_METADATA_SUFFIXES:
                    files.append(item)
    return files[:_MAX_INVENTORY_ITEMS]


def _iter_context_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    files: list[Path] = [root / name for name in sorted(_CONTEXT_FILENAMES) if (root / name).exists()]
    cursor_rules = root / ".cursor" / "rules"
    if cursor_rules.exists():
        files.extend(sorted(cursor_rules.glob("*.mdc")))
    for item in sorted(root.rglob("*")):
        if len(files) >= _MAX_INVENTORY_ITEMS:
            break
        if item.is_file() and (item.name in _CONTEXT_FILENAMES or item.match("*/.cursor/rules/*.mdc")) and item not in files:
            files.append(item)
    return files[:_MAX_INVENTORY_ITEMS]


def _metadata_entries(paths: list[Path], *, root: Path, kind: str, blocked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    root_resolved = root.resolve(strict=False)
    seen: set[Path] = set()
    for path in paths:
        if len(entries) >= _MAX_INVENTORY_ITEMS:
            break
        if not path.exists():
            continue
        try:
            resolved = path.expanduser().resolve(strict=True)
        except OSError as exc:
            blocked.append(_blocked_file(path, root=root, reason=f"resolve_failed:{exc.__class__.__name__}"))
            continue
        if root_resolved not in (resolved, *resolved.parents):
            blocked.append(_blocked_file(path, root=root, reason="outside_import_root"))
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            file_stat = resolved.stat()
        except OSError as exc:
            blocked.append(_blocked_file(path, root=root, reason=f"stat_failed:{exc.__class__.__name__}"))
            continue
        relative_path = _relative(resolved, root_resolved)
        secret_like_path = _secret_like_path(relative_path)
        entries.append(
            {
                "path": relative_path,
                "kind": kind,
                "suffix": resolved.suffix.lower(),
                "size_bytes": int(file_stat.st_size),
                "path_sha256": hashlib.sha256(relative_path.encode("utf-8", errors="replace")).hexdigest(),
                "secret_like_path": secret_like_path,
                "secrets_import": "blocked_by_default_use_secrets_broker" if secret_like_path else "not_detected_from_path",
                "raw_content_included": False,
                "content_hash_included": False,
                "import_action": "metadata_only_review",
            }
        )
    return entries


def _secret_like_path(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in _SECRET_PATH_MARKERS)


def _extract_candidate_texts(raw: str, *, suffix: str) -> list[str]:
    if suffix == ".json":
        try:
            return _texts_from_json(json.loads(raw))
        except json.JSONDecodeError:
            pass
    if suffix == ".jsonl":
        rows: list[str] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                rows.extend(_texts_from_json(json.loads(line)))
            except json.JSONDecodeError:
                rows.append(line)
        return _clean_texts(rows)
    return _clean_texts(_split_markdownish(raw))


def _texts_from_json(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        rows: list[str] = []
        for item in value:
            rows.extend(_texts_from_json(item))
        return rows
    if isinstance(value, dict):
        for key in ("content", "memory", "text", "summary", "message", "value"):
            if isinstance(value.get(key), str):
                return [value[key]]
        parts = [str(value[key]) for key in sorted(value) if isinstance(value.get(key), (str, int, float, bool))]
        return ["; ".join(parts)] if parts else []
    return []


def _split_markdownish(raw: str) -> list[str]:
    blocks: list[str] = []
    paragraph: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("```"):
            if paragraph:
                blocks.append(" ".join(paragraph))
                paragraph = []
            continue
        is_list_item = re.match(r"^([-*+]|\d+[.)])\s+", stripped) is not None
        stripped = re.sub(r"^#{1,6}\s+", "", stripped)
        stripped = re.sub(r"^[-*+]\s+", "", stripped)
        stripped = re.sub(r"^\d+[.)]\s+", "", stripped)
        if is_list_item:
            if paragraph:
                blocks.append(" ".join(paragraph))
                paragraph = []
            blocks.append(stripped)
        else:
            paragraph.append(stripped)
    if paragraph:
        blocks.append(" ".join(paragraph))
    return blocks


def _clean_texts(values: list[str]) -> list[str]:
    cleaned = []
    for value in values:
        text = re.sub(r"\s+", " ", str(value)).strip()
        if len(text) < 8:
            continue
        cleaned.append(text[:2000])
    return cleaned


def _candidate_from_text(
    text: str,
    *,
    platform: str,
    root: Path,
    path: Path,
    index: int,
    owner: str,
    scope: str,
) -> dict[str, Any]:
    redacted = redact_secret_values(text)
    secret_like = SECRET_LIKE.search(text) is not None or redacted != text
    relative_path = _relative(path, root)
    memory_type = _classify_memory_type(relative_path, text)
    candidate_id = hashlib.sha256(f"{platform}:{relative_path}:{index}:{redacted}".encode("utf-8", errors="replace")).hexdigest()[:16]
    base = {
        "id": f"import-{candidate_id}",
        "type": memory_type.value,
        "source": f"migration:{platform}",
        "provenance": {
            "platform": platform,
            "path": relative_path,
            "entry_index": index,
            "dry_run": True,
            "untrusted_import": True,
        },
        "confidence": 0.55,
        "sensitivity": Sensitivity.INTERNAL.value,
        "owner": owner,
        "scope": scope,
        "tags": sorted({"migration", platform, memory_type.value.removesuffix("_memory")}),
        "redaction_status": "secret_like_blocked" if secret_like else "not_redacted",
        "import_action": "review_required",
        "blocked": secret_like,
    }
    if secret_like:
        return {**base, "content": "[BLOCKED_SECRET_LIKE_CONTENT]", "summary": "Secret-like imported memory candidate blocked for manual review.", "reason": "secret_like_content"}
    return {**base, "content": redacted, "summary": _summary(redacted)}


def _classify_memory_type(relative_path: str, text: str) -> MemoryType:
    lowered = f"{relative_path} {text}".lower()
    if "session" in lowered or "conversation" in lowered:
        return MemoryType.EPISODIC
    if "preference" in lowered or "prefer " in lowered or "user.md" in lowered or "profile" in lowered:
        return MemoryType.PREFERENCE
    if "skill" in lowered:
        return MemoryType.SKILL
    if "repair" in lowered or "workflow" in lowered or "procedure" in lowered or "runbook" in lowered:
        return MemoryType.PROCEDURAL
    if "policy" in lowered or "agent" in lowered or "soul" in lowered:
        return MemoryType.POLICY
    return MemoryType.PROJECT


def _summary(text: str) -> str:
    return text[:157] + "..." if len(text) > 160 else text


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _blocked_file(path: Path, *, root: Path, reason: str) -> dict[str, Any]:
    return {
        "path": _relative(path, root),
        "reason": reason,
        "blocked": True,
        "import_action": "blocked",
    }
