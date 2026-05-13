"""Skill candidate construction helpers."""

from __future__ import annotations

from typing import Any


def create_skill_template(skill_id: str, *, name: str, description: str, source: str = "cli-generated") -> dict[str, Any]:
    return {
        "id": skill_id,
        "name": name,
        "description": description,
        "version": "0.1.0",
        "author": "local-user",
        "source": source,
        "permissions": {},
        "connectors": [],
        "secrets": [],
        "network": {},
        "filesystem": {},
        "commands": [],
        "input_schema": {"type": "object"},
        "output_schema": {"type": "object"},
        "risk_level": "medium",
        "approval_required": True,
        "sandbox_profile": "no_tools",
        "tests": [],
        "evals": [],
        "rollback": "Disable or delete the skill.",
        "changelog": ["Created disabled template."],
    }


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
