"""Virtual skill hub catalog for safe discovery and installation planning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SkillHubEntry:
    id: str
    name: str
    category: str
    risk: str
    install_mode: str = "manifest_review_required"


class SkillHubCatalog:
    """Catalog facade that can represent large external registries without auto-installing code."""

    advertised_capacity = 5700

    def __init__(self) -> None:
        self.entries = (
            SkillHubEntry("hub.web-search", "Web Search", "web", "medium"),
            SkillHubEntry("hub.email-assistant", "Email Assistant", "productivity", "high"),
            SkillHubEntry("hub.calendar-planner", "Calendar Planner", "productivity", "high"),
            SkillHubEntry("hub.code-review", "Code Review", "engineering", "medium"),
            SkillHubEntry("hub.browser-research", "Browser Research", "web", "high"),
            SkillHubEntry("hub.service-desk", "Service Desk", "business", "high"),
            SkillHubEntry("hub.data-analysis", "Data Analysis", "data", "medium"),
            SkillHubEntry("hub.smart-home", "Smart Home", "iot", "high"),
        )

    def search(self, query: str = "") -> dict[str, Any]:
        normalized = query.lower().strip()
        entries = [entry for entry in self.entries if not normalized or normalized in entry.name.lower() or normalized in entry.category.lower()]
        return {
            "advertised_capacity": self.advertised_capacity,
            "mode": "virtual_catalog_no_code_download",
            "entries": [entry.__dict__ for entry in entries],
            "install_policy": "downloaded skills must pass manifest validation, static checks, sandbox tests, and approval",
        }
