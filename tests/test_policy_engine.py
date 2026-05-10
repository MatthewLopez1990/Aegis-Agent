from __future__ import annotations

import unittest

from aegis.security.policy_engine import PolicyDecisionType, PolicyEngine, PolicyRequest
from aegis.security.taint import RiskLevel, Sensitivity


class PolicyEngineTests(unittest.TestCase):
    def test_allows_low_risk_read(self) -> None:
        decision = PolicyEngine().evaluate(
            PolicyRequest(user_role="user", workspace=".", task_type="read", risk_level=RiskLevel.LOW, connector="filesystem", operation="read", requested_scopes=("read",))
        )
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)

    def test_requires_approval_for_high_risk_action(self) -> None:
        decision = PolicyEngine().evaluate(
            PolicyRequest(user_role="user", workspace=".", task_type="delete", risk_level=RiskLevel.HIGH, connector="filesystem", operation="delete", requested_scopes=("write",))
        )
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRE_APPROVAL)

    def test_approved_high_risk_action_can_proceed(self) -> None:
        decision = PolicyEngine().evaluate(
            PolicyRequest(
                user_role="user",
                workspace=".",
                task_type="send",
                risk_level=RiskLevel.HIGH,
                connector="mock_messaging",
                operation="send_message",
                requested_scopes=("write",),
                approval_state="approved",
            )
        )
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)

    def test_denies_raw_secret_exposure(self) -> None:
        decision = PolicyEngine().evaluate(
            PolicyRequest(user_role="user", workspace=".", task_type="secret", risk_level=RiskLevel.CRITICAL, operation="read_secret", data_sensitivity=Sensitivity.SECRET)
        )
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)

    def test_requires_approval_for_unapproved_network_domain(self) -> None:
        decision = PolicyEngine(network_allowlist=("example.com",)).evaluate(
            PolicyRequest(
                user_role="user",
                workspace=".",
                task_type="http",
                risk_level=RiskLevel.MEDIUM,
                connector="http",
                operation="read",
                requested_scopes=("read",),
                target_domain="evil.test",
            )
        )
        self.assertEqual(decision.decision, PolicyDecisionType.REQUIRE_APPROVAL)


if __name__ == "__main__":
    unittest.main()
