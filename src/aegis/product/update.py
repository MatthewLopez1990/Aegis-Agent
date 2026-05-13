"""Governed platform update checks and explicit update application."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any
from urllib import request

from aegis import __version__


DEFAULT_MANIFEST_URL = "https://raw.githubusercontent.com/MatthewLopez1990/Aegis-Agent/main/pyproject.toml"
DEFAULT_ARCHIVE_URL = "https://github.com/MatthewLopez1990/Aegis-Agent/archive/refs/heads/main.tar.gz"
DEFAULT_REPOSITORY = "https://github.com/MatthewLopez1990/Aegis-Agent"
MAX_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True)
class UpdateSource:
    manifest_url: str = DEFAULT_MANIFEST_URL
    archive_url: str = DEFAULT_ARCHIVE_URL
    repository: str = DEFAULT_REPOSITORY


def check_platform_update(
    *,
    source: UpdateSource | None = None,
    current_version: str = __version__,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Return a metadata-only update report from the configured public manifest."""

    source = source or UpdateSource()
    manifest_bytes = _fetch_bytes(source.manifest_url, timeout=timeout)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError("remote update manifest is too large")

    manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    project = manifest.get("project", {})
    package_name = str(project.get("name") or "")
    latest_version = str(project.get("version") or "")
    if package_name != "aegis-agent":
        raise ValueError("remote update manifest is not for aegis-agent")
    if not latest_version:
        raise ValueError("remote update manifest does not include a version")

    version_status = "update_available" if _version_newer(latest_version, current_version) else "current"
    update_command = f"{sys.executable} -m pip install --upgrade {source.archive_url}"
    return {
        "ok": True,
        "status": version_status,
        "mode": "metadata_only_update_check",
        "package": package_name,
        "current_version": current_version,
        "latest_version": latest_version,
        "update_available": version_status == "update_available",
        "source": {
            "repository": source.repository,
            "manifest_url": source.manifest_url,
            "archive_url": source.archive_url,
        },
        "apply_supported": True,
        "apply_requires_approval": True,
        "apply_command": "aegis update --apply --approved",
        "manual_update_command": update_command,
        "notes": [
            "Update checks download metadata only until --apply --approved is used.",
            "Approved updates use git pull for a source checkout or pip install for packaged installs.",
        ],
    }


def apply_platform_update(
    *,
    source: UpdateSource | None = None,
    current_version: str = __version__,
    method: str = "auto",
    approved: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Apply a platform update only after explicit approval."""

    check = check_platform_update(source=source, current_version=current_version, timeout=timeout)
    if not approved:
        return {
            **check,
            "status": "approval_required",
            "mode": "approved_update_required",
            "apply_attempted": False,
            "approval_hint": "Run aegis update --apply --approved to update the local platform.",
        }

    source = source or UpdateSource()
    command, selected_method = _build_update_command(source=source, method=method)
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=300)
    ok = completed.returncode == 0
    return {
        **check,
        "ok": ok,
        "status": "updated" if ok else "update_failed",
        "mode": "approved_platform_update",
        "apply_attempted": True,
        "apply_method": selected_method,
        "returncode": completed.returncode,
        "command": _redacted_command(command),
        "stdout_tail": _tail(completed.stdout),
        "stderr_tail": _tail(completed.stderr),
    }


def _build_update_command(*, source: UpdateSource, method: str) -> tuple[list[str], str]:
    if method not in {"auto", "git", "pip"}:
        raise ValueError("update method must be auto, git, or pip")

    source_root = _source_checkout_root()
    if method in {"auto", "git"} and source_root is not None:
        return ["git", "-C", str(source_root), "pull", "--ff-only"], "git"
    if method == "git":
        raise ValueError("git update requested, but this install is not running from a git checkout")
    return [sys.executable, "-m", "pip", "install", "--upgrade", source.archive_url], "pip"


def _source_checkout_root() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        if (parent / ".git").is_dir() and (parent / "pyproject.toml").is_file():
            return parent
    return None


def _fetch_bytes(url: str, *, timeout: float) -> bytes:
    req = request.Request(url, headers={"User-Agent": "aegis-agent-update-check"})
    with request.urlopen(req, timeout=timeout) as response:  # noqa: S310 - URL is operator/config controlled public metadata.
        return response.read(MAX_MANIFEST_BYTES + 1)


def _version_newer(candidate: str, current: str) -> bool:
    return _version_key(candidate) > _version_key(current)


def _version_key(version: str) -> tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", version)]
    return tuple(parts or [0])


def _redacted_command(command: list[str]) -> list[str]:
    return ["<python>" if part == sys.executable else part for part in command]


def _tail(value: str, *, max_chars: int = 4000) -> str:
    if len(value) <= max_chars:
        return value
    return value[-max_chars:]


def update_audit_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": result.get("status"),
        "mode": result.get("mode"),
        "current_version": result.get("current_version"),
        "latest_version": result.get("latest_version"),
        "apply_attempted": result.get("apply_attempted", False),
        "apply_method": result.get("apply_method"),
        "source": result.get("source"),
        "command": result.get("command"),
        "returncode": result.get("returncode"),
        "raw_output_included": False,
        "payload_sha256": hashlib.sha256(json.dumps(result, sort_keys=True, default=str).encode("utf-8")).hexdigest(),
    }
