"""SOUL-style personality and project context files with safe loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.security.context_firewall import ContextFirewall
from aegis.security.taint import ContextItem, TrustClass


PERSONALITY_NAMES = (
    "default",
    "concise",
    "researcher",
    "engineer",
    "security_reviewer",
    "planner",
    "teacher",
    "operator",
    "support",
    "code_reviewer",
    "incident_commander",
    "writer",
    "analyst",
    "creative",
)

CONTEXT_FILE_TRUST: tuple[tuple[str, TrustClass], ...] = (
    ("SOUL.md", TrustClass.USER_DIRECTIVE),
    ("AGENTS.md", TrustClass.DEVELOPER_TRUSTED),
    ("CLAUDE.md", TrustClass.DEVELOPER_TRUSTED),
    ("TOOLS.md", TrustClass.USER_DIRECTIVE),
)


class ContextFileLoader:
    def __init__(self, workspace: str | Path, *, max_files: int = 12, max_bytes_per_file: int = 32_000) -> None:
        self.workspace = Path(workspace).expanduser().resolve()
        self.firewall = ContextFirewall()
        self.max_files = max_files
        self.max_bytes_per_file = max_bytes_per_file

    def load(self, target_path: str | Path | None = None) -> list[ContextItem]:
        return list(self.firewall.process(self._raw_items(target_path)).items)

    def model_context(self, target_path: str | Path | None = None) -> tuple[str, ...]:
        return self.firewall.process(self._raw_items(target_path)).model_context

    def manifest(self, target_path: str | Path | None = None) -> dict[str, Any]:
        paths = self._candidate_paths(target_path)
        return {
            "workspace": str(self.workspace),
            "target_path": str(self._resolve_target_dir(target_path)) if target_path is not None else str(self.workspace),
            "max_files": self.max_files,
            "max_bytes_per_file": self.max_bytes_per_file,
            "sources": [str(path) for path in paths],
            "raw_content_included": False,
        }

    def _raw_items(self, target_path: str | Path | None = None) -> list[ContextItem]:
        items: list[ContextItem] = []
        trust_by_name = dict(CONTEXT_FILE_TRUST)
        for path in self._candidate_paths(target_path):
            content = self._read_bounded(path)
            items.append(self.firewall.label_content(content, source=str(path), trust_class=trust_by_name[path.name]))
        return items

    def _candidate_paths(self, target_path: str | Path | None = None) -> list[Path]:
        paths: list[Path] = []
        seen: set[Path] = set()
        for directory in self._context_dirs(target_path):
            for filename, _trust in CONTEXT_FILE_TRUST:
                if filename == "SOUL.md" and directory != self.workspace:
                    continue
                path = directory / filename
                if len(paths) >= self.max_files:
                    return paths
                if path in seen or not path.exists() or not path.is_file():
                    continue
                try:
                    resolved = path.resolve()
                    resolved.relative_to(self.workspace)
                except (OSError, ValueError):
                    continue
                paths.append(path)
                seen.add(path)
        return paths

    def _context_dirs(self, target_path: str | Path | None = None) -> list[Path]:
        target_dir = self._resolve_target_dir(target_path)
        try:
            relative = target_dir.relative_to(self.workspace)
        except ValueError:
            return [self.workspace]
        dirs = [self.workspace]
        current = self.workspace
        for part in relative.parts:
            current = current / part
            dirs.append(current)
        return dirs

    def _resolve_target_dir(self, target_path: str | Path | None) -> Path:
        if target_path is None:
            return self.workspace
        raw = Path(target_path).expanduser()
        candidate = raw.resolve() if raw.is_absolute() else (self.workspace / raw).resolve()
        try:
            candidate.relative_to(self.workspace)
        except ValueError:
            return self.workspace
        if candidate.exists() and candidate.is_file():
            return candidate.parent
        if candidate.suffix and not candidate.exists():
            return candidate.parent
        return candidate

    def _read_bounded(self, path: Path) -> str:
        data = path.read_bytes()[: self.max_bytes_per_file + 1]
        truncated = len(data) > self.max_bytes_per_file
        if truncated:
            data = data[: self.max_bytes_per_file]
        content = data.decode("utf-8", errors="replace")
        if truncated:
            content += f"\n[TRUNCATED_CONTEXT_FILE max_bytes={self.max_bytes_per_file}]"
        return content

    def profile(self, personality: str = "default") -> dict[str, Any]:
        if personality not in PERSONALITY_NAMES:
            raise ValueError(f"unknown personality {personality!r}")
        return {"name": personality, "source": "built-in", "editable_file": str(self.workspace / "SOUL.md")}
