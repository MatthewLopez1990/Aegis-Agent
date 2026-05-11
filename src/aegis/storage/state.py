"""Filesystem helpers for private local runtime state."""

from __future__ import annotations

import os
from pathlib import Path


def ensure_private_dir(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    _chmod(directory, 0o700)
    return directory


def ensure_private_file(path: str | Path) -> Path:
    file_path = Path(path)
    ensure_private_dir(file_path.parent)
    if file_path.exists():
        _chmod(file_path, 0o600)
    return file_path


def _chmod(path: Path, mode: int) -> None:
    if os.name != "posix":
        return
    try:
        os.chmod(path, mode)
    except PermissionError:
        return
