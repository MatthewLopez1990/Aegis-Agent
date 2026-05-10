"""Dry-run import helpers for OpenClaw/Hermes style local data."""

from __future__ import annotations

from pathlib import Path
from typing import Any


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
    return {
        "root": str(root),
        "exists": root.exists(),
        "found": {name: target.exists() for name, target in candidates.items()},
        "mode": "dry_run_only",
        "secrets_import": "blocked_by_default_use_secrets_broker",
    }


def inspect_hermes_home(path: str | Path) -> dict[str, Any]:
    root = Path(path).expanduser()
    candidates = {
        "SOUL.md": root / "SOUL.md",
        "memory": root / "memory",
        "skills": root / "skills",
        "config": root / "config.yaml",
        "sessions": root / "sessions",
    }
    return {
        "root": str(root),
        "exists": root.exists(),
        "found": {name: target.exists() for name, target in candidates.items()},
        "mode": "dry_run_only",
        "secrets_import": "blocked_by_default_use_secrets_broker",
    }
