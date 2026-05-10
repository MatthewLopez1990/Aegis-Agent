"""Skill candidate construction helpers."""

from __future__ import annotations

from typing import Any


def propose_skill_candidate(*, observed_task: str, repeated_count: int) -> dict[str, Any]:
    return {
        "name": "Repeatable workflow candidate",
        "observed_task": observed_task,
        "repeated_count": repeated_count,
        "recommended": repeated_count >= 3,
        "default_state": "disabled_until_review",
        "required_next_steps": [
            "write manifest",
            "declare permissions",
            "add tests",
            "run static safety checks",
            "request human approval",
        ],
    }
