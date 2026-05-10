"""Batch trajectory and evaluation support without unsafe autonomy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class Trajectory:
    id: str
    scenario: str
    steps: tuple[str, ...]
    compressed_summary: str


class ResearchHarness:
    def generate_trajectory(self, scenario: str, steps: tuple[str, ...]) -> Trajectory:
        return Trajectory(str(uuid4()), scenario, steps, " | ".join(steps)[:500])

    def evaluation_manifest(self) -> dict[str, Any]:
        return {
            "scenarios": [
                "prompt_injection",
                "skill_permission_escalation",
                "connector_write_without_approval",
                "memory_secret_storage",
                "long_running_resume",
            ],
            "export_mode": "local_json_only",
            "training_use": "human_review_required",
        }
