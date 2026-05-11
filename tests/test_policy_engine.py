from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from aegis.security.policy_engine import PolicyDecisionType, PolicyEngine, PolicyRequest
from aegis.config.loader import load_config
from aegis.research.harness import ResearchHarness
from aegis.security.policy_profile import PolicyProfile, activate_due_policy_rollouts, apply_policy_bundle, diff_policy_bundle, import_policy_bundle, import_policy_bundle_text, export_policy_bundle, list_policy_bundles, list_policy_promotions, list_policy_rollouts, parse_policy_profile, promote_policy_bundle, rollback_policy_bundle, schedule_policy_bundle
from aegis.security.taint import RiskLevel, Sensitivity


class PolicyEngineTests(unittest.TestCase):
    def test_allows_low_risk_read(self) -> None:
        decision = PolicyEngine().evaluate(
            PolicyRequest(user_role="user", workspace=".", task_type="read", risk_level=RiskLevel.LOW, connector="filesystem", operation="read", requested_scopes=("read",))
        )
        self.assertEqual(decision.decision, PolicyDecisionType.ALLOW)

    def test_read_requires_read_scope(self) -> None:
        decision = PolicyEngine().evaluate(
            PolicyRequest(user_role="user", workspace=".", task_type="read", risk_level=RiskLevel.LOW, connector="filesystem", operation="read", requested_scopes=())
        )
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)
        self.assertIn("read scope", decision.reasons[0])

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

    def test_admin_approval_policy_requires_admin_approved_state(self) -> None:
        profile = parse_policy_profile({"defaults": {"message_send": "require_admin_approval"}})
        pending = PolicyEngine(profile=profile).evaluate(
            PolicyRequest(
                user_role="user",
                workspace=".",
                task_type="send",
                risk_level=RiskLevel.HIGH,
                connector="mock_messaging",
                operation="send_message",
                requested_scopes=("write",),
            )
        )
        normal_approval = PolicyEngine(profile=profile).evaluate(
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
        admin_approval = PolicyEngine(profile=profile).evaluate(
            PolicyRequest(
                user_role="user",
                workspace=".",
                task_type="send",
                risk_level=RiskLevel.HIGH,
                connector="mock_messaging",
                operation="send_message",
                requested_scopes=("write",),
                approval_state="admin_approved",
            )
        )

        self.assertEqual(pending.decision, PolicyDecisionType.REQUIRE_ADMIN_APPROVAL)
        self.assertEqual(normal_approval.decision, PolicyDecisionType.REQUIRE_ADMIN_APPROVAL)
        self.assertEqual(admin_approval.decision, PolicyDecisionType.ALLOW)

    def test_denies_raw_secret_exposure(self) -> None:
        decision = PolicyEngine().evaluate(
            PolicyRequest(user_role="user", workspace=".", task_type="secret", risk_level=RiskLevel.CRITICAL, operation="read_secret", data_sensitivity=Sensitivity.SECRET)
        )
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)

    def test_secret_data_stays_denied_even_after_approval(self) -> None:
        cases = (
            {"operation": "invoke_model", "connector": "model", "scopes": ("model.invoke",)},
            {"operation": "send_message", "connector": "mock_messaging", "scopes": ("write",)},
            {"operation": "execute", "connector": "shell", "scopes": ("execute",)},
        )
        for case in cases:
            with self.subTest(operation=case["operation"]):
                decision = PolicyEngine().evaluate(
                    PolicyRequest(
                        user_role="user",
                        workspace=".",
                        task_type="approved secret action",
                        risk_level=RiskLevel.HIGH,
                        connector=case["connector"],
                        operation=case["operation"],
                        requested_scopes=case["scopes"],
                        approval_state="approved",
                        data_sensitivity=Sensitivity.SECRET,
                    )
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

    def test_policy_profile_can_deny_message_sends_even_after_approval(self) -> None:
        profile = parse_policy_profile({"defaults": {"message_send": "deny"}})
        decision = PolicyEngine(profile=profile).evaluate(
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
        self.assertEqual(decision.decision, PolicyDecisionType.DENY)

    def test_policy_profile_rejects_attempt_to_allow_raw_secret_exposure(self) -> None:
        with self.assertRaises(ValueError):
            parse_policy_profile({"defaults": {"raw_secret_exposure": "allow"}})

    def test_policy_profile_supplies_allowlists(self) -> None:
        profile = parse_policy_profile(
            {
                "defaults": {"read_only": True},
                "network": {"allowlist": ["example.com", "api.openai.com"]},
                "shell": {"allowlist": ["pwd"]},
            },
            base=PolicyProfile.secure_default(network_allowlist=("localhost",), shell_allowlist=("ls",)),
        )

        self.assertEqual(profile.network_allowlist, ("example.com", "api.openai.com"))
        self.assertEqual(profile.shell_allowlist, ("pwd",))

    def test_policy_bundles_export_secure_profiles(self) -> None:
        bundles = list_policy_bundles()
        strict = export_policy_bundle("strict-local")
        profile = parse_policy_profile({"defaults": {"message_send": "allow"}}, base=parse_policy_profile({"defaults": {"message_send": "require_admin_approval"}}))

        self.assertTrue(any(bundle["name"] == "strict-local" for bundle in bundles))
        self.assertEqual(strict["profile"]["message_send"], "require_admin_approval")
        self.assertEqual(strict["profile"]["raw_secret_exposure"], "deny")
        self.assertIn("[defaults]", strict["toml"])
        self.assertEqual(profile.message_send, "allow")
        with self.assertRaises(KeyError):
            export_policy_bundle("missing")

    def test_policy_bundle_import_and_apply_updates_config_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / ".aegis"
            data_dir.mkdir()
            bundle_path = root / "developer-policy.toml"
            bundle_path.write_text(
                "\n".join(
                    [
                        "[defaults]",
                        'message_send = "deny"',
                        'shell_execution = "require_admin_approval"',
                        "",
                        "[network]",
                        'allowlist = ["localhost"]',
                        "",
                        "[shell]",
                        'allowlist = ["pwd"]',
                    ]
                ),
                encoding="utf-8",
            )

            imported = import_policy_bundle(bundle_path)
            diff = diff_policy_bundle(bundle_path, current=PolicyProfile.secure_default())
            pending = apply_policy_bundle(bundle_path, data_dir=data_dir, approved=False)
            applied = apply_policy_bundle(bundle_path, data_dir=data_dir, approved=True, name="developer-policy")
            loaded = load_config(data_dir)
            rolled_back = rollback_policy_bundle(data_dir=data_dir, approved=True)
            reloaded = load_config(data_dir)

            self.assertEqual(imported["profile"]["message_send"], "deny")
            self.assertTrue(any(change["field"] == "message_send" for change in diff["changes"]))
            self.assertEqual(pending["status"], "approval_required")
            self.assertTrue(applied["ok"])
            self.assertEqual(applied["config_policy_path"], "policies/developer-policy.toml")
            self.assertIsNone(applied["previous_policy_path"])
            self.assertEqual(loaded.policy_profile.message_send, "deny")
            self.assertEqual(loaded.allowed_shell_commands, ("pwd",))
            self.assertEqual(rolled_back["status"], "rolled_back")
            self.assertEqual(reloaded.policy_profile.message_send, "require_approval")
            self.assertNotIn('path = "policies/developer-policy.toml"', (data_dir / "config.toml").read_text(encoding="utf-8"))

    def test_policy_rollouts_schedule_and_promote_without_active_config_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / ".aegis"
            data_dir.mkdir()

            pending_schedule = schedule_policy_bundle("strict-local", data_dir=data_dir, activate_at="2026-05-11T12:00:00Z", approved=False)
            scheduled = schedule_policy_bundle("strict-local", data_dir=data_dir, activate_at="2026-05-11T12:00:00Z", environment="staging", approved=True)
            rollouts = list_policy_rollouts(data_dir=data_dir)
            pending_promotion = promote_policy_bundle("strict-local", data_dir=data_dir, from_environment="staging", to_environment="production", approved=False)
            promoted = promote_policy_bundle("strict-local", data_dir=data_dir, from_environment="staging", to_environment="production", approved=True)
            harness = ResearchHarness(data_dir=data_dir)
            baseline = harness.record_evaluation_run(
                trajectory=harness.generate_trajectory("policy release", ("seed", "run gates")),
                status="reviewed_passed",
                reviewer="release",
            )
            regressed = harness.record_evaluation_run(
                trajectory=harness.generate_trajectory("policy release", ("seed", "missing gate")),
                status="reviewed_failed",
                reviewer="release",
            )
            blocked = promote_policy_bundle(
                "strict-local",
                data_dir=data_dir,
                from_environment="staging",
                to_environment="production",
                approved=True,
                require_clean_evaluation=True,
                baseline_report_id=baseline["id"],
                candidate_report_id=regressed["id"],
            )
            clean = promote_policy_bundle(
                "strict-local",
                data_dir=data_dir,
                from_environment="staging",
                to_environment="production",
                approved=True,
                require_clean_evaluation=True,
                baseline_report_id=regressed["id"],
                candidate_report_id=baseline["id"],
            )
            live_gap_blocked = promote_policy_bundle(
                "strict-local",
                data_dir=data_dir,
                from_environment="staging",
                to_environment="production",
                approved=True,
                require_live_parity=True,
                live_gap_backlog=[
                    {
                        "area": "provider_and_channel_live_connectors",
                        "status": "live_connector_work_required",
                        "sample_tools": ["web_search"],
                        "required_controls": ["human_approval"],
                        "verification_gates": ["receipt_redaction"],
                    }
                ],
            )
            live_gap_missing_reason = promote_policy_bundle(
                "strict-local",
                data_dir=data_dir,
                from_environment="staging",
                to_environment="production",
                approved=True,
                require_live_parity=True,
                live_gap_backlog=[
                    {
                        "area": "provider_and_channel_live_connectors",
                        "status": "live_connector_work_required",
                        "sample_tools": ["web_search"],
                    }
                ],
                deferred_live_gap_areas=["provider_and_channel_live_connectors"],
            )
            live_gap_deferred = promote_policy_bundle(
                "strict-local",
                data_dir=data_dir,
                from_environment="staging",
                to_environment="production",
                approved=True,
                require_live_parity=True,
                live_gap_backlog=[
                    {
                        "area": "provider_and_channel_live_connectors",
                        "status": "live_connector_work_required",
                        "sample_tools": ["web_search"],
                    }
                ],
                deferred_live_gap_areas=["provider_and_channel_live_connectors"],
                live_gap_deferral_reason="Production policy promotion is for local-only runtime.",
            )

            self.assertEqual(pending_schedule["status"], "approval_required")
            self.assertEqual(scheduled["status"], "scheduled")
            self.assertEqual(scheduled["environment"], "staging")
            self.assertFalse(scheduled["restart_required"])
            self.assertTrue(Path(scheduled["rollout_path"]).exists())
            self.assertEqual(rollouts["rollouts"][0]["status"], "scheduled")
            self.assertFalse(rollouts["rollouts"][0]["writes_active_config"])
            self.assertEqual(pending_promotion["status"], "approval_required")
            self.assertEqual(promoted["status"], "promoted")
            self.assertEqual(promoted["from_environment"], "staging")
            self.assertEqual(promoted["to_environment"], "production")
            self.assertTrue(Path(promoted["policy_path"]).exists())
            self.assertEqual(blocked["status"], "blocked_by_evaluation_regression")
            self.assertTrue(blocked["evaluation_delta"]["regression"])
            self.assertEqual(clean["status"], "promoted")
            self.assertTrue(clean["evaluation_gate"]["improvement"])
            self.assertEqual(live_gap_blocked["status"], "blocked_by_live_parity_gap")
            self.assertEqual(live_gap_blocked["live_gap_backlog"][0]["area"], "provider_and_channel_live_connectors")
            self.assertEqual(live_gap_missing_reason["status"], "blocked_by_live_parity_deferral_missing_reason")
            self.assertEqual(live_gap_deferred["status"], "promoted")
            self.assertEqual(live_gap_deferred["deferred_live_gaps"][0]["area"], "provider_and_channel_live_connectors")
            promotion_receipts = list_policy_promotions(data_dir=data_dir)
            deferred_receipt = promotion_receipts["promotions"][-1]
            self.assertEqual(deferred_receipt["deferred_live_gaps"][0]["area"], "provider_and_channel_live_connectors")
            self.assertEqual(deferred_receipt["live_gap_deferral_reason"], "Production policy promotion is for local-only runtime.")
            self.assertFalse((data_dir / "config.toml").exists())

    def test_due_policy_rollout_activation_updates_config_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / ".aegis"
            data_dir.mkdir()

            future = schedule_policy_bundle(
                "approval-first",
                data_dir=data_dir,
                activate_at="2999-05-11T12:00:00Z",
                environment="local",
                approved=True,
            )
            due = schedule_policy_bundle(
                "strict-local",
                data_dir=data_dir,
                activate_at="2000-05-11T12:00:00Z",
                environment="local",
                approved=True,
            )
            activated = activate_due_policy_rollouts(data_dir=data_dir, now="2026-05-11T12:00:00Z")
            loaded = load_config(data_dir)
            rollouts = list_policy_rollouts(data_dir=data_dir)
            due_receipt = [rollout for rollout in rollouts["rollouts"] if rollout["id"] == due["id"]][0]
            future_receipt = [rollout for rollout in rollouts["rollouts"] if rollout["id"] == future["id"]][0]

            self.assertEqual(activated["activated"], 1)
            self.assertEqual(activated["results"][0]["id"], due["id"])
            self.assertTrue(activated["restart_required"])
            self.assertEqual(loaded.policy_profile.message_send, "require_admin_approval")
            self.assertEqual(due_receipt["status"], "activated")
            self.assertTrue(due_receipt["writes_active_config"])
            self.assertEqual(future_receipt["status"], "scheduled")

    def test_policy_bundle_import_rejects_immutable_secret_relaxation(self) -> None:
        with self.assertRaises(ValueError):
            import_policy_bundle_text('[defaults]\nraw_secret_exposure = "allow"\n')


if __name__ == "__main__":
    unittest.main()
