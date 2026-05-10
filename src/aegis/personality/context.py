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


class ContextFileLoader:
    def __init__(self, workspace: str | Path) -> None:
        self.workspace = Path(workspace).expanduser().resolve()
        self.firewall = ContextFirewall()

    def load(self) -> list[ContextItem]:
        items: list[ContextItem] = []
        for filename, trust in (("SOUL.md", TrustClass.USER_DIRECTIVE), ("AGENTS.md", TrustClass.DEVELOPER_TRUSTED), ("TOOLS.md", TrustClass.USER_DIRECTIVE)):
            path = self.workspace / filename
            if path.exists() and path.is_file():
                items.append(self.firewall.label_content(path.read_text(encoding="utf-8", errors="replace"), source=str(path), trust_class=trust))
        return list(self.firewall.process(items).items)

    def profile(self, personality: str = "default") -> dict[str, Any]:
        if personality not in PERSONALITY_NAMES:
            raise ValueError(f"unknown personality {personality!r}")
        return {"name": personality, "source": "built-in", "editable_file": str(self.workspace / "SOUL.md")}
