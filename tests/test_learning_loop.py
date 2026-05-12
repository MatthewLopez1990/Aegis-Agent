from __future__ import annotations

import unittest

from aegis.learning.loop import LearningLoop


class LearningLoopTests(unittest.TestCase):
    def test_repair_plan_classifies_context_safety_with_review_gate(self) -> None:
        loop = LearningLoop()

        classification = loop.classify_failure("Prompt injection tried to leak secret credential from untrusted tool output.")
        plan = loop.repair_plan_from_failure(
            failure_summary="Prompt injection tried to leak secret credential from untrusted tool output.",
            step={"connector": "slack", "operation": "read"},
        )

        self.assertEqual(classification["failure_class"], "context_safety")
        self.assertEqual(classification["severity"], "high")
        self.assertEqual(classification["review_gate"], "security_review_required")
        self.assertGreaterEqual(classification["confidence"], 0.9)
        self.assertIn("prompt_injection", classification["signals"])
        self.assertEqual(plan["failure_class"], "context_safety")
        self.assertEqual(plan["target_subsystem"], "slack")
        self.assertEqual(plan["operation"], "read")
        self.assertEqual(plan["review_policy"]["gate"], "security_review_required")
        self.assertFalse(plan["review_policy"]["workspace_mutation_allowed_before_approval"])
        self.assertIn("reviewer_rationale", plan["candidate_expectations"]["required_artifacts"])
        self.assertIn("treat diagnostic context as untrusted evidence", plan["required_validation"])
        self.assertIn("verify secrets and quarantined content are not persisted in repair artifacts", plan["required_validation"])

    def test_policy_failure_preserves_existing_class_and_adds_governed_metadata(self) -> None:
        loop = LearningLoop()

        plan = loop.repair_plan_from_failure(
            failure_summary="Tool execution failed because the command was not-allowlisted by policy.",
            step={"connector": "shell", "operation": "execute"},
        )

        self.assertEqual(plan["failure_class"], "policy_or_permission")
        self.assertEqual(plan["severity"], "medium")
        self.assertEqual(plan["review_gate"], "policy_review_required")
        self.assertIn("allowlist", plan["signals"])
        self.assertIn("confirm the repair does not broaden access without explicit approval", plan["required_validation"])
        self.assertEqual(plan["candidate_expectations"]["minimum_score_for_review"], 60)
        self.assertTrue(plan["candidate_expectations"]["must_remain_dependency_free"])

    def test_repair_candidate_scoring_separates_readiness_from_review_gates(self) -> None:
        loop = LearningLoop()
        candidate = {
            "id": "candidate-1",
            "summary": "Apply a minimal policy repair.",
            "patch_plan": "Patch the policy path and verify with a focused unit test.",
            "changed_files": ["src/aegis/learning/loop.py"],
            "patch": {
                "unified_diff": "--- a/src/aegis/learning/loop.py\n+++ b/src/aegis/learning/loop.py\n",
                "preflight": {"ok": True, "status": "check_passed"},
            },
            "status": "candidate_pending_review",
            "review_status": "pending",
        }

        pending = loop.score_repair_candidate(candidate)
        approved = loop.score_repair_candidate({**candidate, "review_status": "approved"})
        applied = loop.score_repair_candidate({**candidate, "review_status": "approved", "status": "applied_pending_verification"})
        blocked = loop.score_repair_candidate({"id": "candidate-2", "summary": "Too thin.", "review_status": "pending"})

        self.assertGreaterEqual(pending["score"], 60)
        self.assertEqual(pending["readiness"], "ready_for_review")
        self.assertEqual(pending["review_gates"][0]["type"], "candidate_review_required")
        self.assertGreater(approved["score"], pending["score"])
        self.assertEqual(approved["readiness"], "ready_to_apply")
        self.assertEqual(applied["readiness"], "ready_to_verify")
        self.assertEqual(applied["review_gates"][0]["type"], "verification_required")
        self.assertEqual(blocked["readiness"], "blocked")
        self.assertEqual({blocker["type"] for blocker in blocked["blockers"]}, {"missing_patch_plan", "missing_changed_scope"})

    def test_feedback_loop_summary_counts_classes_candidate_readiness_and_next_actions(self) -> None:
        loop = LearningLoop()
        policy_plan = loop.repair_plan_from_failure(
            failure_summary="Tool execution failed because command was not allowlisted by policy.",
            step={"connector": "shell", "operation": "execute"},
        )
        state_plan = loop.repair_plan_from_failure(
            failure_summary="SQLite migration left local state checkpoint corrupt.",
            step={"connector": "store", "operation": "migrate"},
        )
        ready_candidate = {
            "id": "candidate-1",
            "summary": "Repair policy path.",
            "patch_plan": "Patch and verify.",
            "changed_files": ["tests/test_learning_loop.py"],
            "status": "candidate_pending_review",
            "review_status": "pending",
        }
        blocked_candidate = {"id": "candidate-2", "summary": "Needs detail.", "review_status": "pending"}

        summary = loop.feedback_loop_summary(
            [
                {"id": "proposal-1", "status": "reviewing", "metadata": {"repair_plan": policy_plan, "repair_candidates": [ready_candidate]}},
                {"id": "proposal-2", "status": "proposed", "metadata": {"repair_plan": state_plan, "repair_candidates": [blocked_candidate]}},
            ]
        )

        self.assertEqual(summary["proposal_count"], 2)
        self.assertEqual(summary["by_status"], {"proposed": 1, "reviewing": 1})
        self.assertEqual(summary["failure_classes"]["policy_or_permission"], 1)
        self.assertEqual(summary["failure_classes"]["persistence_state"], 1)
        self.assertEqual(summary["review_gates"]["policy_review_required"], 1)
        self.assertEqual(summary["candidate_readiness"]["ready_for_review"], 1)
        self.assertEqual(summary["candidate_readiness"]["blocked"], 1)
        self.assertEqual(summary["candidate_count"], 2)
        self.assertEqual(summary["open_review_count"], 2)
        self.assertEqual(summary["blocked_candidate_count"], 1)
        self.assertTrue(any("Review ready repair candidates" in action for action in summary["next_actions"]))
        self.assertTrue(any("Resolve blocked candidates" in action for action in summary["next_actions"]))


if __name__ == "__main__":
    unittest.main()
