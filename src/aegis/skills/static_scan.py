"""Dependency-light static checks for skill manifests and local source trees."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from aegis.skills.manifest import SkillManifest


BLOCKED_COMMAND_PATTERNS = (
    re.compile(r"(^|\s)(rm|sudo|su|curl|wget|nc|ncat|ssh)\b"),
    re.compile(r"(^|\s)(bash|sh)\s+-c\b"),
)
BLOCKED_SOURCE_PATTERNS = {
    "dynamic_eval": re.compile(r"\b(eval|exec)\s*\("),
    "shell_spawn": re.compile(r"\b(os\.system|subprocess\.(Popen|run|call|check_call|check_output))\s*\("),
    "raw_socket": re.compile(r"\bsocket\.socket\s*\("),
}
SOURCE_SUFFIXES = {".py", ".sh", ".js", ".ts"}
MAX_SOURCE_FILES = 100
MAX_SOURCE_BYTES = 64_000


def scan_skill_manifest(manifest: SkillManifest) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for command in manifest.commands:
        for pattern in BLOCKED_COMMAND_PATTERNS:
            if pattern.search(str(command)):
                findings.append({"severity": "high", "kind": "blocked_command", "detail": str(command)})

    network_hosts = manifest.network.get("allowlist", manifest.network.get("hosts", []))
    if isinstance(network_hosts, str):
        network_hosts = [network_hosts]
    if any(str(host).strip() in {"*", "0.0.0.0/0"} for host in network_hosts if host is not None):
        findings.append({"severity": "high", "kind": "wildcard_network", "detail": "network allowlist cannot be wildcard"})

    source_path = Path(manifest.source).expanduser()
    if source_path.exists():
        findings.extend(_scan_source_path(source_path))

    blocked = [finding for finding in findings if finding["severity"] in {"high", "critical"}]
    return {
        "ok": not blocked,
        "checked": ["manifest.commands", "manifest.network", "source"],
        "findings": findings,
        "blocked_findings": blocked,
    }


def _scan_source_path(source_path: Path) -> list[dict[str, Any]]:
    files: list[Path]
    if source_path.is_file():
        files = [source_path]
    else:
        files = [path for path in source_path.rglob("*") if path.is_file() and path.suffix in SOURCE_SUFFIXES][:MAX_SOURCE_FILES]
    findings: list[dict[str, Any]] = []
    root = source_path if source_path.is_dir() else source_path.parent
    for path in files:
        try:
            content = path.read_text(encoding="utf-8")[:MAX_SOURCE_BYTES]
        except UnicodeDecodeError:
            findings.append({"severity": "medium", "kind": "unreadable_source", "path": _relative_path(root, path)})
            continue
        for kind, pattern in BLOCKED_SOURCE_PATTERNS.items():
            if pattern.search(content):
                findings.append({"severity": "high", "kind": kind, "path": _relative_path(root, path)})
    return findings


def _relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
