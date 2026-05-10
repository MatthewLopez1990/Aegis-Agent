"""Governed self-improvement proposals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class ImprovementProposal:
    id: str
    kind: str
    summary: str
    evidence: tuple[str, ...]
    approval_required: bool = True
    default_state: str = "disabled_until_review"


class LearningLoop:
    def propose_from_failure(self, *, task_id: str, failure_summary: str) -> ImprovementProposal:
        return ImprovementProposal(
            id=str(uuid4()),
            kind="skill_or_memory_update",
            summary=f"Review failed task {task_id}: {failure_summary}",
            evidence=(task_id,),
        )

    def periodic_nudge(self, *, stale_count: int, low_confidence_count: int) -> dict[str, Any]:
        return {
            "should_review": stale_count > 0 or low_confidence_count > 0,
            "stale_count": stale_count,
            "low_confidence_count": low_confidence_count,
            "default_action": "ask_user_before_memory_or_skill_changes",
        }
