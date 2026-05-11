from __future__ import annotations

import tempfile
import unittest
import json
import os
import subprocess
import sys
import io
from contextlib import redirect_stdout
from pathlib import Path
from urllib.error import HTTPError

from aegis.agent.orchestrator import build_orchestrator
from aegis.cli.main import build_parser, dispatch
from aegis.config.loader import load_config
from aegis.connectors.base import ConnectorRequest, ConnectorResult
from aegis.connectors.mock_messaging import MockMessagingConnector
from aegis.memory.manager import MemorySafetyError
from aegis.memory.models import MemoryType
from aegis.research.harness import ResearchHarness
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.context_firewall import ContextFirewall
from aegis.security.policy_engine import PolicyDecisionType, PolicyEngine, PolicyRequest
from aegis.security.policy_profile import (
    activate_due_policy_rollouts,
    apply_policy_bundle,
    diff_policy_bundle_text,
    list_policy_rollouts,
    parse_policy_profile,
    rollback_policy_bundle,
    schedule_policy_bundle,
)
from aegis.security.taint import RiskLevel, SanitizationStatus, Sensitivity, TrustClass
from aegis.skills.runtime import SkillPermissionError, SkillRuntime
from aegis.tui.main import AegisTui
from tests.test_api import _free_port, _json_get, _json_post, _wait_for_server
from unittest.mock import patch


class EvaluationScenarioTests(unittest.TestCase):
    def test_security_scenario_manifest_covers_required_categories(self) -> None:
        manifest = ResearchHarness().evaluation_manifest()
        scenario_ids = {scenario["id"] for scenario in manifest["scenarios"]}

        self.assertEqual(
            set(manifest["categories"]),
            {"artifact_integrity", "backend_activation", "connector_abuse", "live_connector_receipts", "memory_poisoning", "prompt_injection", "skill_escalation"},
        )
        self.assertEqual(len(scenario_ids), len(manifest["scenarios"]))
        self.assertIn("prompt_injection.file_content", scenario_ids)
        self.assertIn("memory_poisoning.secret_storage", scenario_ids)
        self.assertIn("connector_abuse.write_without_scope", scenario_ids)
        self.assertIn("skill_escalation.undeclared_permission", scenario_ids)
        self.assertIn("artifact_integrity.browser_media_receipts", scenario_ids)
        self.assertIn("backend_activation.remote_execution_disabled", scenario_ids)
        self.assertIn("live_connector_receipts.redacted_write_summary", scenario_ids)
        self.assertIn("policy_regression_gates", manifest)
        self.assertIn("policy_regression_variants", manifest)
        self.assertEqual(
            set(manifest["policy_variant_types"]),
            {"admin_only_profile", "bundle_rollout_canary", "cli_api_parity", "malformed_receipt_canary", "policy_diff_fuzz", "rollback_canary", "tui_web_parity"},
        )
        self.assertEqual(manifest["export_mode"], "local_json_only")
        self.assertEqual(manifest["training_use"], "human_review_required")

    def test_security_scenarios_execute_against_real_gates(self) -> None:
        scenarios = {scenario.id: scenario for scenario in ResearchHarness().security_scenarios()}

        prompt_result = ContextFirewall().process(
            [
                ContextFirewall().label_content(
                    scenarios["prompt_injection.file_content"].adversarial_input,
                    source="eval-file",
                    trust_class=TrustClass.DOCUMENT_CONTENT,
                )
            ]
        )
        self.assertEqual(prompt_result.items[0].taint.sanitization_status, SanitizationStatus.QUARANTINED)
        self.assertFalse(ContextFirewall().external_content_can_trigger_tools(prompt_result.items[0]))

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)
            with self.assertRaises(MemorySafetyError):
                orchestrator.memory.create_memory(
                    memory_type=MemoryType.PROJECT,
                    content=scenarios["memory_poisoning.secret_storage"].adversarial_input,
                    source="eval",
                    provenance={"scenario": "memory_poisoning.secret_storage"},
                    confidence=0.9,
                    confirmed=True,
                )
            self.assertEqual(orchestrator.memory.retrieve_relevant("api_key"), [])

            policy_decision = PolicyEngine().evaluate(
                PolicyRequest(
                    user_role="eval",
                    workspace=str(root),
                    task_type="connector abuse",
                    risk_level=RiskLevel.HIGH,
                    connector="mock_servicenow",
                    operation="close_ticket",
                    requested_scopes=("read",),
                )
            )
            self.assertFalse(policy_decision.allowed)
            self.assertIn("write scope", " ".join(policy_decision.reasons))
            with self.assertRaisesRegex(PermissionError, "write"):
                orchestrator.connectors.get("mock_servicenow").write(
                    ConnectorRequest(
                        operation="close_ticket",
                        params={"id": "INC000001"},
                        scopes=("read",),
                    )
                )

            runtime = SkillRuntime(orchestrator.skills, orchestrator.connectors, orchestrator.audit_logger)
            with self.assertRaises(SkillPermissionError):
                runtime.invoke(
                    "aegis.project_summary",
                    {"path": "."},
                    requested_permissions={"filesystem": {"write": True}},
                )
            audit_text = (root / ".aegis" / "audit.jsonl").read_text(encoding="utf-8")
            self.assertIn("skill.sandbox_denied", audit_text)
            self.assertIn("permission_denied", audit_text)
            self.assertIn('"operation": "request_permission"', audit_text)

            media = orchestrator.tools.execute("image_generate", {"prompt": scenarios["artifact_integrity.browser_media_receipts"].adversarial_input}, approved=True)
            media_metadata = Path(media["metadata_path"]).read_text(encoding="utf-8")
            self.assertRegex(media["artifact_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(json.loads(media_metadata)["artifact_receipt"]["artifact_sha256"], media["artifact_sha256"])
            self.assertEqual(json.loads(media_metadata)["sandbox_receipt"]["sandbox_profile"], "local_artifact_worker_subprocess_no_provider")
            self.assertEqual(json.loads(media_metadata)["sandbox_receipt"]["worker_process"], "subprocess")
            self.assertTrue(json.loads(media_metadata)["sandbox_receipt"]["os_resource_limits"])
            self.assertFalse(json.loads(media_metadata)["sandbox_receipt"]["raw_prompt_or_text_persisted"])
            self.assertNotIn(scenarios["artifact_integrity.browser_media_receipts"].adversarial_input, media_metadata)

            with patch.object(
                orchestrator.connectors.get("http"),
                "read",
                return_value=ConnectorResult(
                    "http",
                    "read",
                    True,
                    {
                        "url": "https://example.com",
                        "domain": "example.com",
                        "content": "<html><title>Receipt Test token=abc123</title><button id='submit'>Submit</button><table><tr><td>ok token=abc123</td></tr></table></html>",
                    },
                ),
            ):
                browser_nav = orchestrator.tools.execute("browser", {"action": "navigate", "url": "https://example.com?token=abc123"}, approved=True)
            browser_shot = orchestrator.tools.execute("browser_screenshot", {"session_id": browser_nav["session"]["id"]})
            browser_evidence = json.loads(Path(browser_shot["evidence_path"]).read_text(encoding="utf-8"))
            browser_metadata = Path(browser_shot["metadata_path"]).read_text(encoding="utf-8")
            browser_session_store = (root / ".aegis" / "browser" / "sessions.json").read_text(encoding="utf-8")
            rendered_browser_payload = json.dumps({"navigation": browser_nav, "shot": browser_shot, "evidence": browser_evidence}, sort_keys=True)
            self.assertRegex(browser_shot["artifact_hashes"]["snapshot_png_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(browser_evidence["artifact_hashes"]["snapshot_png_sha256"], browser_shot["artifact_hashes"]["snapshot_png_sha256"])
            self.assertEqual(browser_evidence["rendering_status"], "not_rendered")
            self.assertEqual(browser_evidence["sandbox_receipt"]["sandbox_profile"], "http_content_session_state_no_js")
            self.assertFalse(browser_evidence["sandbox_receipt"]["javascript_executed"])
            self.assertFalse(browser_evidence["sandbox_receipt"]["page_javascript_allowed"])
            self.assertFalse(browser_evidence["automation_boundaries"]["remote_subresources_loaded"])
            self.assertFalse(browser_evidence["automation_boundaries"]["real_page_mutation_allowed"])
            self.assertNotIn("abc123", rendered_browser_payload)
            self.assertNotIn("abc123", browser_metadata)
            self.assertNotIn("abc123", browser_session_store)

            backend_selection = orchestrator.tools.execute("terminal_backend", {"backend": "ssh"}, approved=True)
            self.assertFalse(backend_selection["ok"])
            self.assertEqual(backend_selection["activation"]["status"], scenarios["backend_activation.remote_execution_disabled"].expected_gate)
            self.assertIn("brokered_backend_auth", backend_selection["activation"]["required_controls"])
            self.assertIn("scope_escape_rejection", backend_selection["activation"]["verification_gates"])
            backend_tool = orchestrator.tools.execute("ssh_exec", {"host": "example.internal", "command": "uptime"}, approved=True)
            self.assertFalse(backend_tool["ok"])
            self.assertEqual(backend_tool["activation_status"], "backend_adapter_required")
            self.assertIn("brokered_backend_auth", backend_tool["required_controls"])
            self.assertIn("disabled_backend_denial", backend_tool["verification_gates"])

            broker = SecretsBroker()
            broker.store_secret(name="MESSAGING_TOKEN", value="msg_eval_secret")
            live_connector = MockMessagingConnector(allowlist=("example.com",), live_writes=True, secrets_broker=broker)

            class FakeResponse:
                status = 202

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

                def read(self, limit: int) -> bytes:
                    return b'{"ok":true,"token":"response-secret"}'

            with patch("aegis.connectors.mock_messaging._open_without_redirects", return_value=FakeResponse()):
                live_write = live_connector.write(
                    ConnectorRequest(
                        operation="send_message",
                        params={
                            "provider_url": "https://example.com/hooks/messages",
                            "channel": "security",
                            "text": scenarios["live_connector_receipts.redacted_write_summary"].adversarial_input,
                        },
                        scopes=("write",),
                        approved=True,
                    )
                )
            rendered_live_write = json.dumps(live_write.data, sort_keys=True)
            self.assertTrue(live_write.ok)
            self.assertEqual(live_write.data["accepted"]["receipt_schema"], "redacted_param_summary_v1")
            self.assertFalse(live_write.data["accepted"]["raw_secret_values_included"])
            self.assertFalse(live_write.data["accepted"]["raw_response_body_included"])
            self.assertNotIn("msg_eval_secret", rendered_live_write)
            self.assertNotIn("response-secret", rendered_live_write)
            self.assertNotIn("token-shaped content", rendered_live_write)

    def test_evaluation_run_reports_are_persisted_locally_with_trends(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / ".aegis"
            harness = ResearchHarness(data_dir=data_dir)
            trajectory = harness.generate_trajectory("policy regression", ("seed", "run", "review"))

            report = harness.record_evaluation_run(
                trajectory=trajectory,
                status="passed",
                reviewer="eval-test",
                notes="Policy canaries passed.",
            )
            trends = harness.evaluation_trends()
            report_path = Path(report["report_path"])
            stored = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]

            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(report_path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(stored[0]["id"], report["id"])
            self.assertEqual(stored[0]["trajectory"]["id"], trajectory.id)
            self.assertEqual(stored[0]["manifest_summary"]["policy_variant_count"], len(harness.policy_regression_variants()))
            self.assertEqual(trends["reports"], 1)
            self.assertEqual(trends["by_status"], {"passed": 1})
            self.assertEqual(trends["by_scenario"], {"policy regression": 1})
            self.assertEqual(trends["latest_report_id"], report["id"])

    def test_evaluation_suite_reports_feed_reviewer_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / ".aegis"
            harness = ResearchHarness(data_dir=data_dir)

            suite = harness.run_evaluation_suite(
                suite="security",
                scenario_ids=("prompt_injection.file_content", "memory_poisoning.secret_storage"),
                reviewer="security-reviewer",
            )
            queue = harness.evaluation_review_queue(reviewer="security-reviewer")

            self.assertEqual(suite["report_count"], 2)
            self.assertEqual(suite["reviewer"], "security-reviewer")
            self.assertEqual(queue["total"], 2)
            self.assertEqual([item["reviewer"] for item in queue["items"]], ["security-reviewer", "security-reviewer"])
            self.assertEqual(queue["statuses"], ["scheduled"])

            reviewed = harness.review_evaluation_report(
                suite["report_ids"][0],
                status="reviewed_passed",
                reviewer="security-reviewer",
                notes="Canary evidence reviewed.",
            )
            reviewed_queue = harness.evaluation_review_queue(reviewer="security-reviewer")
            trends = harness.evaluation_trends()
            delta = harness.evaluation_regression_delta(
                baseline_report_id=suite["report_ids"][1],
                candidate_report_id=suite["report_ids"][0],
            )

            self.assertEqual(reviewed["status"], "reviewed_passed")
            self.assertEqual(reviewed["reviewed_by"], "security-reviewer")
            self.assertEqual(reviewed["review_dispositions"][0]["previous_status"], "scheduled")
            self.assertEqual(reviewed_queue["total"], 1)
            self.assertEqual(trends["by_status"], {"reviewed_passed": 1, "scheduled": 1})
            self.assertTrue(delta["improvement"])
            self.assertFalse(delta["regression"])

            regressed = harness.review_evaluation_report(
                suite["report_ids"][1],
                status="reviewed_failed",
                reviewer="security-reviewer",
                notes="Regression reproduced.",
            )
            regression_delta = harness.evaluation_regression_delta(
                baseline_report_id=suite["report_ids"][0],
                candidate_report_id=regressed["id"],
            )
            readiness = harness.release_readiness_summary(
                baseline_report_id=suite["report_ids"][0],
                candidate_report_id=regressed["id"],
                reviewer="security-reviewer",
            )
            self.assertTrue(regression_delta["regression"])
            self.assertEqual(regression_delta["status_change"]["to"], "reviewed_failed")
            self.assertFalse(readiness["ready"])
            self.assertEqual(readiness["status"], "blocked")
            self.assertIn("evaluation_regression", {blocker["type"] for blocker in readiness["blockers"]})
            self.assertIn("unresolved_failed_or_followup_reports", {blocker["type"] for blocker in readiness["blockers"]})

            clean_harness = ResearchHarness(data_dir=Path(temp) / ".clean-aegis")
            clean_baseline = clean_harness.record_evaluation_run(
                trajectory=clean_harness.generate_trajectory("release", ("seed", "passed")),
                status="reviewed_passed",
                reviewer="security-reviewer",
            )
            clean_candidate = clean_harness.record_evaluation_run(
                trajectory=clean_harness.generate_trajectory("release", ("seed", "passed", "extra evidence")),
                status="reviewed_passed",
                reviewer="security-reviewer",
            )
            clean = clean_harness.release_readiness_summary(
                baseline_report_id=clean_baseline["id"],
                candidate_report_id=clean_candidate["id"],
                reviewer="security-reviewer",
            )
            self.assertTrue(clean["ready"])
            self.assertEqual(clean["status"], "ready")

            parity_blocked = clean_harness.release_readiness_summary(
                baseline_report_id=clean_baseline["id"],
                candidate_report_id=clean_candidate["id"],
                reviewer="security-reviewer",
                live_gap_backlog=[
                    {
                        "area": "provider_and_channel_live_connectors",
                        "status": "live_connector_work_required",
                        "detail": "live connectors remain staged",
                        "sample_tools": ["web_search"],
                        "required_controls": ["human_approval"],
                        "verification_gates": ["receipt_redaction"],
                        "evaluation_scenarios": ["live_connector_receipts.redacted_write_summary"],
                    }
                ],
            )
            self.assertFalse(parity_blocked["ready"])
            self.assertIn("open_live_parity_gap", {blocker["type"] for blocker in parity_blocked["blockers"]})
            self.assertIn("missing_live_gap_evaluation_evidence", {blocker["type"] for blocker in parity_blocked["blockers"]})
            self.assertIn("live_connector_receipts.redacted_write_summary", parity_blocked["next_actions"][-2])
            self.assertIn("provider_and_channel_live_connectors", parity_blocked["next_actions"][-1])
            covered_report = clean_harness.record_evaluation_run(
                trajectory=clean_harness.generate_trajectory("live_connector_receipts.redacted_write_summary", ("seed", "receipt_schema=redacted_param_summary_v1")),
                status="reviewed_passed",
                reviewer="security-reviewer",
            )
            parity_with_coverage = clean_harness.release_readiness_summary(
                baseline_report_id=clean_baseline["id"],
                candidate_report_id=covered_report["id"],
                reviewer="security-reviewer",
                live_gap_backlog=[
                    {
                        "area": "provider_and_channel_live_connectors",
                        "status": "live_connector_work_required",
                        "detail": "live connectors remain staged",
                        "sample_tools": ["web_search"],
                        "required_controls": ["human_approval"],
                        "verification_gates": ["receipt_redaction"],
                        "evaluation_scenarios": ["live_connector_receipts.redacted_write_summary"],
                    }
                ],
            )
            self.assertNotIn("missing_live_gap_evaluation_evidence", {blocker["type"] for blocker in parity_with_coverage["blockers"]})
            parity_deferred = clean_harness.release_readiness_summary(
                baseline_report_id=clean_baseline["id"],
                candidate_report_id=clean_candidate["id"],
                reviewer="security-reviewer",
                live_gap_backlog=[
                    {
                        "area": "provider_and_channel_live_connectors",
                        "status": "live_connector_work_required",
                        "detail": "live connectors remain staged",
                        "sample_tools": ["web_search"],
                        "required_controls": ["human_approval"],
                        "verification_gates": ["receipt_redaction"],
                    }
                ],
                deferred_live_gap_areas=["provider_and_channel_live_connectors"],
                live_gap_deferral_reason="Release is limited to local/offline runtime surfaces.",
            )
            self.assertTrue(parity_deferred["ready"])
            self.assertEqual(parity_deferred["deferred_live_gaps"][0]["area"], "provider_and_channel_live_connectors")

    def test_trajectory_tool_can_persist_evaluation_report_and_return_trends(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator = build_orchestrator(data_dir=root / ".aegis", workspace=root)

            result = orchestrator.tools.execute(
                "trajectory_generate",
                {
                    "scenario": "prompt injection",
                    "steps": ["seed", "run", "review"],
                    "persist_report": True,
                    "status": "passed",
                    "reviewer": "tool-test",
                    "notes": "Local eval report.",
                },
                approved=True,
            )
            compressed = orchestrator.tools.execute(
                "trajectory_compress",
                {"trajectory_id": result["trajectory_id"], "steps": result["steps"], "include_trends": True},
            )

            report = result["evaluation_report"]
            self.assertEqual(report["status"], "passed")
            self.assertTrue(Path(report["report_path"]).exists())
            self.assertEqual(result["evaluation_trends"]["by_status"], {"passed": 1})
            self.assertEqual(compressed["evaluation_trends"]["reports"], 1)

    def test_policy_regression_gates_cover_and_execute_high_risk_policy_classes(self) -> None:
        harness = ResearchHarness()
        gates = {gate.policy_key: gate for gate in harness.policy_regression_gates()}

        self.assertEqual(
            set(gates),
            {
                "raw_secret_exposure",
                "secret_data",
                "skill_without_valid_manifest",
                "unapproved_network_egress",
                "destructive_action",
                "message_send",
                "connector_write_without_scope",
                "unknown_shell_command",
                "shell_execution",
                "high_risk_action",
                "high_risk_memory_without_confirmation",
            },
        )
        self.assertEqual(set(harness.evaluation_manifest()["policy_keys"]), set(gates))

        requests = {
            "raw_secret_exposure": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="secret",
                risk_level=RiskLevel.CRITICAL,
                operation="read_secret",
            ),
            "secret_data": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="model",
                risk_level=RiskLevel.HIGH,
                operation="invoke_model",
                data_sensitivity=Sensitivity.SECRET,
                approval_state="approved",
            ),
            "skill_without_valid_manifest": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="skill",
                risk_level=RiskLevel.MEDIUM,
                operation="read",
                requested_scopes=("read",),
                skill_manifest={"validated": False},
            ),
            "unapproved_network_egress": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="http",
                risk_level=RiskLevel.MEDIUM,
                connector="http",
                operation="read",
                requested_scopes=("read",),
                target_domain="blocked.example",
            ),
            "destructive_action": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="delete",
                risk_level=RiskLevel.MEDIUM,
                connector="filesystem",
                operation="delete",
                requested_scopes=("write",),
            ),
            "message_send": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="send",
                risk_level=RiskLevel.MEDIUM,
                connector="mock_messaging",
                operation="send_message",
                requested_scopes=("write",),
            ),
            "connector_write_without_scope": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="ticket",
                risk_level=RiskLevel.MEDIUM,
                connector="mock_servicenow",
                operation="close_ticket",
                requested_scopes=("read",),
            ),
            "unknown_shell_command": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="shell",
                risk_level=RiskLevel.MEDIUM,
                connector="shell",
                operation="execute",
                requested_scopes=(),
            ),
            "shell_execution": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="shell",
                risk_level=RiskLevel.MEDIUM,
                connector="shell",
                operation="execute",
                requested_scopes=("execute",),
            ),
            "high_risk_action": PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="high-risk",
                risk_level=RiskLevel.HIGH,
                operation="review",
                requested_scopes=("read",),
            ),
        }
        engine = PolicyEngine()
        for policy_key, request in requests.items():
            with self.subTest(policy_key=policy_key):
                decision = engine.evaluate(request)
                self.assertEqual(decision.decision.value, gates[policy_key].expected_gate)
                self.assertNotEqual(decision.decision, PolicyDecisionType.ALLOW)

        with tempfile.TemporaryDirectory() as temp:
            orchestrator = build_orchestrator(data_dir=Path(temp) / ".aegis", workspace=Path(temp))
            with self.assertRaisesRegex(MemorySafetyError, "confirmation"):
                orchestrator.memory.create_memory(
                    memory_type=MemoryType.PROJECT,
                    content="Only deploy from the signed release branch.",
                    source="eval",
                    provenance={"scenario": "policy.high_risk_memory_without_confirmation"},
                    sensitivity=Sensitivity.CONFIDENTIAL,
                    confidence=0.95,
                    confirmed=False,
                )

    def test_policy_regression_variants_execute_admin_profiles_and_rollout_canaries(self) -> None:
        harness = ResearchHarness()
        variants = {variant.id: variant for variant in harness.policy_regression_variants()}

        self.assertEqual(
            set(variants),
            {
                "policy_variant.admin_profile.message_send",
                "policy_variant.admin_profile.shell_execution",
                "policy_variant.rollout.schedule_requires_approval",
                "policy_variant.rollout.due_activation",
                "policy_variant.rollout.future_receipt_skipped",
                "policy_variant.rollout.environment_mismatch_skipped",
                "policy_variant.rollout.invalid_json_skipped",
                "policy_variant.rollout.missing_toml_skipped",
                "policy_variant.rollback.restores_previous_policy",
                "policy_variant.rollback.stale_receipt_blocked",
                "policy_variant.diff.noop_bundle",
                "policy_variant.diff.multi_field_bundle",
                "policy_variant.diff.immutable_secret_relaxation_rejected",
                "policy_variant.diff.unknown_default_rejected",
                "policy_variant.parity.cli_api_policy_surfaces",
                "policy_variant.parity.tui_web_policy_workflows",
            },
        )

        admin_message_profile = parse_policy_profile({"defaults": {"message_send": "require_admin_approval"}})
        message_normal_approval = PolicyEngine(profile=admin_message_profile).evaluate(
            PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="send",
                risk_level=RiskLevel.HIGH,
                connector="mock_messaging",
                operation="send_message",
                requested_scopes=("write",),
                approval_state="approved",
            )
        )
        message_admin_approval = PolicyEngine(profile=admin_message_profile).evaluate(
            PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="send",
                risk_level=RiskLevel.HIGH,
                connector="mock_messaging",
                operation="send_message",
                requested_scopes=("write",),
                approval_state="admin_approved",
            )
        )
        self.assertEqual(message_normal_approval.decision, PolicyDecisionType.REQUIRE_ADMIN_APPROVAL)
        self.assertEqual(message_admin_approval.decision, PolicyDecisionType.ALLOW)

        admin_shell_profile = parse_policy_profile({"defaults": {"shell_execution": "require_admin_approval"}})
        shell_normal_approval = PolicyEngine(profile=admin_shell_profile).evaluate(
            PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="shell",
                risk_level=RiskLevel.HIGH,
                connector="shell",
                operation="execute",
                requested_scopes=("execute",),
                approval_state="approved",
            )
        )
        shell_admin_approval = PolicyEngine(profile=admin_shell_profile).evaluate(
            PolicyRequest(
                user_role="eval",
                workspace=".",
                task_type="shell",
                risk_level=RiskLevel.HIGH,
                connector="shell",
                operation="execute",
                requested_scopes=("execute",),
                approval_state="admin_approved",
            )
        )
        self.assertEqual(shell_normal_approval.decision, PolicyDecisionType.REQUIRE_ADMIN_APPROVAL)
        self.assertEqual(shell_admin_approval.decision, PolicyDecisionType.ALLOW)

        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / ".aegis"
            data_dir.mkdir()
            unapproved = schedule_policy_bundle("strict-local", data_dir=data_dir, activate_at="2000-05-11T12:00:00Z", approved=False)
            staging = schedule_policy_bundle(
                "strict-local",
                data_dir=data_dir,
                activate_at="2000-05-11T12:00:00Z",
                environment="staging",
                approved=True,
            )
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
            rollout_dir = data_dir / "policies" / "rollouts"
            invalid_receipt_path = rollout_dir / "invalid-json.json"
            invalid_receipt_path.write_text("{not valid json", encoding="utf-8")
            missing_toml_path = rollout_dir / "missing-toml.json"
            missing_toml_path.write_text(
                json.dumps(
                    {
                        "id": "missing-toml",
                        "status": "scheduled",
                        "environment": "local",
                        "activate_at": "2000-05-11T12:00:00Z",
                        "name": "missing-toml",
                    }
                ),
                encoding="utf-8",
            )
            activated = activate_due_policy_rollouts(data_dir=data_dir, now="2026-05-11T12:00:00Z", environment="local")
            loaded = load_config(data_dir)
            rollouts = list_policy_rollouts(data_dir=data_dir)["rollouts"]
            by_id = {rollout["id"]: rollout for rollout in rollouts}

            self.assertEqual(unapproved["status"], "approval_required")
            self.assertEqual(activated["activated"], 1)
            self.assertTrue(activated["restart_required"])
            self.assertEqual(loaded.policy_profile.message_send, "require_admin_approval")
            self.assertEqual(by_id[due["id"]]["status"], "activated")
            self.assertTrue(by_id[due["id"]]["writes_active_config"])
            self.assertEqual(by_id[future["id"]]["status"], "scheduled")
            self.assertEqual(by_id[staging["id"]]["status"], "scheduled")
            self.assertEqual(by_id["invalid-json"]["status"], "invalid_receipt")
            skipped_reasons = {skipped["id"]: skipped["reason"] for skipped in activated["skipped"]}
            self.assertEqual(skipped_reasons[staging["id"]], "different environment")
            self.assertEqual(skipped_reasons["invalid-json"], "invalid rollout receipt JSON")
            self.assertEqual(skipped_reasons["missing-toml"], "missing policy TOML")

        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / ".aegis"
            data_dir.mkdir()
            first = apply_policy_bundle("approval-first", data_dir=data_dir, approved=True, name="approval-first")
            second = apply_policy_bundle("strict-local", data_dir=data_dir, approved=True, name="strict-local")
            loaded_second = load_config(data_dir)
            rolled_back = rollback_policy_bundle(data_dir=data_dir, approved=True)
            loaded_rollback = load_config(data_dir)

            self.assertEqual(first["config_policy_path"], "policies/approval-first.toml")
            self.assertEqual(second["previous_policy_path"], "policies/approval-first.toml")
            self.assertEqual(loaded_second.policy_profile.message_send, "require_admin_approval")
            self.assertEqual(rolled_back["status"], "rolled_back")
            self.assertEqual(rolled_back["previous_policy_path"], "policies/approval-first.toml")
            self.assertEqual(loaded_rollback.policy_profile.message_send, "require_approval")

        with tempfile.TemporaryDirectory() as temp:
            data_dir = Path(temp) / ".aegis"
            data_dir.mkdir()
            apply_policy_bundle("approval-first", data_dir=data_dir, approved=True, name="approval-first")
            apply_policy_bundle("strict-local", data_dir=data_dir, approved=True, name="strict-local")
            manual_policy = data_dir / "policies" / "manual-override.toml"
            manual_policy.write_text('[defaults]\nmessage_send = "deny"\n', encoding="utf-8")
            config_path = data_dir / "config.toml"
            config_path.write_text('[policy]\npath = "policies/manual-override.toml"\n', encoding="utf-8")
            stale = rollback_policy_bundle(data_dir=data_dir, approved=True)
            loaded_stale = load_config(data_dir)

            self.assertEqual(stale["status"], "stale_rollback")
            self.assertEqual(stale["current_policy_path"], "policies/manual-override.toml")
            self.assertEqual(stale["applied_policy_path"], "policies/strict-local.toml")
            self.assertEqual(loaded_stale.policy_profile.message_send, "deny")

        base = parse_policy_profile(
            {
                "defaults": {"message_send": "require_approval", "shell_execution": "require_approval"},
                "network": {"allowlist": ["localhost"]},
            }
        )
        noop_diff = diff_policy_bundle_text(
            '[defaults]\nmessage_send = "require_approval"\nshell_execution = "require_approval"\n\n[network]\nallowlist = ["localhost"]\n',
            current=base,
        )
        multi_diff = diff_policy_bundle_text(
            '[defaults]\nmessage_send = "deny"\nshell_execution = "require_admin_approval"\nunapproved_network_egress = "require_admin_approval"\n\n[network]\nallowlist = ["localhost", "api.example.test"]\n',
            current=base,
        )

        self.assertFalse(noop_diff["changed"])
        self.assertEqual(noop_diff["changes"], [])
        self.assertTrue(multi_diff["changed"])
        self.assertGreaterEqual(
            {change["field"] for change in multi_diff["changes"]},
            {"message_send", "shell_execution", "unapproved_network_egress", "network_allowlist"},
        )
        with self.assertRaisesRegex(ValueError, "must remain deny"):
            diff_policy_bundle_text('[defaults]\nraw_secret_exposure = "allow"\n', current=base)
        with self.assertRaisesRegex(ValueError, "unknown policy defaults"):
            diff_policy_bundle_text('[defaults]\nmade_up_policy = "deny"\n', current=base)

    def test_policy_regression_variant_cli_api_policy_surface_parity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cli_data_dir = root / "cli" / ".aegis"
            api_data_dir = root / "api" / ".aegis"
            workspace = root / "workspace"
            workspace.mkdir()
            parser = build_parser()

            cli_pending_schedule = dispatch(
                parser.parse_args(
                    [
                        "--data-dir",
                        str(cli_data_dir),
                        "policy",
                        "schedule-bundle",
                        "strict-local",
                        "--activate-at",
                        "2000-05-11T12:00:00Z",
                    ]
                )
            )
            cli_scheduled = dispatch(
                parser.parse_args(
                    [
                        "--data-dir",
                        str(cli_data_dir),
                        "policy",
                        "schedule-bundle",
                        "strict-local",
                        "--activate-at",
                        "2000-05-11T12:00:00Z",
                        "--approved",
                    ]
                )
            )
            cli_activation = dispatch(
                parser.parse_args(["--data-dir", str(cli_data_dir), "policy", "activate-due", "--now", "2026-05-11T12:00:00Z"])
            )
            with self.assertRaisesRegex(ValueError, "unknown policy defaults"):
                bad_policy = root / "bad-policy.toml"
                bad_policy.write_text('[defaults]\nmade_up_policy = "deny"\n', encoding="utf-8")
                dispatch(parser.parse_args(["--data-dir", str(cli_data_dir), "policy", "diff-bundle", str(bad_policy)]))

            port = _free_port()
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "aegis.cli.main",
                    "--data-dir",
                    str(api_data_dir),
                    "serve",
                    "--workspace",
                    str(workspace),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=Path(__file__).resolve().parents[1],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                _wait_for_server(port)
                token = _json_get(port, "/auth")["token"]
                api_pending_schedule = _json_post(
                    port,
                    "/policy/schedule-bundle",
                    {"source": "strict-local", "activate_at": "2000-05-11T12:00:00Z"},
                    token=str(token),
                )
                api_scheduled = _json_post(
                    port,
                    "/policy/schedule-bundle",
                    {"source": "strict-local", "activate_at": "2000-05-11T12:00:00Z", "approved": True},
                    token=str(token),
                )
                api_activation = _json_post(port, "/policy/activate-due", {"now": "2026-05-11T12:00:00Z"}, token=str(token))
                with self.assertRaises(HTTPError) as api_bad_policy:
                    _json_post(
                        port,
                        "/policy/diff-bundle",
                        {"name": "bad-policy", "toml": '[defaults]\nmade_up_policy = "deny"\n'},
                        token=str(token),
                    )

                self.assertEqual(cli_pending_schedule["status"], api_pending_schedule["status"])
                self.assertEqual(cli_scheduled["status"], api_scheduled["status"])
                self.assertEqual(cli_scheduled["environment"], api_scheduled["environment"])
                self.assertEqual(cli_activation["activated"], api_activation["activated"])
                self.assertEqual(cli_activation["restart_required"], api_activation["restart_required"])
                self.assertEqual(api_bad_policy.exception.code, 400)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def test_policy_regression_variant_tui_web_policy_workflow_parity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tui = AegisTui(data_dir=root / ".aegis", workspace=root)
            output = io.StringIO()

            completions = set(tui.complete_security("schedule", "security schedule", len("security "), len("security schedule")))
            self.assertIn("schedule-bundle", completions)
            self.assertIn("activate-due", set(tui.complete_security("activate", "security activate", len("security "), len("security activate"))))
            self.assertIn("rollouts", set(tui.complete_security("roll", "security roll", len("security "), len("security roll"))))

            with redirect_stdout(output):
                tui.onecmd("security schedule-bundle strict-local --activate-at 2000-05-11T12:00:00Z --approved")
                tui.onecmd("security rollouts")
                tui.onecmd("security activate-due --now 2026-05-11T12:00:00Z")

            rendered = output.getvalue()
            self.assertIn('"status": "scheduled"', rendered)
            self.assertIn('"rollouts": [', rendered)
            self.assertIn('"activated": 1', rendered)

        static_root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (static_root / "index.html").read_text(encoding="utf-8")
        script = (static_root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="policy-schedule-form"', markup)
        self.assertIn('id="policy-rollouts"', markup)
        self.assertIn('id="policy-activate-due"', markup)
        self.assertIn('api("/policy/schedule-bundle"', script)
        self.assertIn('api("/policy/rollouts")', script)
        self.assertIn('api("/policy/activate-due"', script)


if __name__ == "__main__":
    unittest.main()
