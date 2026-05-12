"""Aegis Agent command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys
from typing import Any

from aegis.api.server import serve
from aegis.agent.orchestrator import build_orchestrator
from aegis.approvals.actions import approval_action_hints
from aegis.audit.logger import AuditLogger
from aegis.channels.base import ChannelResponse
from aegis.channels.registry import ChannelRegistry
from aegis.config.loader import load_config, write_default_config
from aegis.connectors.registry import build_default_registry
from aegis.execution.backends import ExecutionBackendRegistry
from aegis.hooks.manager import HOOK_EVENTS, HookManager
from aegis.kanban.manager import KanbanManager
from aegis.memory.manager import MemoryManager
from aegis.memory.models import MemoryType
from aegis.memory.store import LocalStore
from aegis.mcp.registry import McpRegistry
from aegis.migration.openclaw import inspect_hermes_home, inspect_openclaw_home, preview_hermes_memory_import, preview_openclaw_memory_import
from aegis.models.registry import ModelRegistry
from aegis.personality.context import ContextFileLoader, PERSONALITY_NAMES
from aegis.plugins.manager import PluginManager
from aegis.product.capabilities import build_product_dashboard
from aegis.remote_control import RemoteControlPairingRegistry
from aegis.research.harness import ResearchHarness
from aegis.scheduler.manager import ScheduleManager
from aegis.security.policy_profile import activate_due_policy_rollouts, apply_policy_bundle, diff_policy_bundle, export_policy_bundle, import_policy_bundle, list_policy_bundles, list_policy_promotions, list_policy_rollouts, promote_policy_bundle, rollback_policy_bundle, schedule_policy_bundle
from aegis.security.secrets_broker import SecretsBroker
from aegis.security.taint import Sensitivity, TrustClass
from aegis.sessions.manager import SessionManager
from aegis.skills.manifest import SkillManifest
from aegis.skills.hub import SkillHubCatalog
from aegis.skills.registry import SkillRegistry
from aegis.skills.signing import DEFAULT_SKILL_SIGNING_KEY, ensure_signing_key, sign_manifest, verify_manifest_signature
from aegis.tools.catalog import ToolCatalog
from aegis.tui.main import SHIELD_FRAMES, run_tui


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = dispatch(args)
    except Exception as exc:  # noqa: BLE001 - CLI should show concise actionable errors.
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 1
    if result is not None:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis Agent local-first runtime")
    parser.add_argument("--data-dir", default=".aegis", help="Aegis data directory")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("init", help="Create default local configuration")
    subcommands.add_parser("health", help="Show local runtime health")
    subcommands.add_parser("dashboard", help="Show product capability and security posture")
    subcommands.add_parser("capabilities", help="Show capability groups, readiness buckets, and live gaps")
    enterprise = subcommands.add_parser("enterprise-readiness", help="Show concise enterprise readiness flags")
    enterprise.add_argument("--memory", action="store_true", help="Only report governed memory readiness")
    enterprise.add_argument("--self-improvement", action="store_true", help="Only report self-improvement readiness")
    enterprise.add_argument("--tui", action="store_true", help="Only report TUI readiness")
    enterprise.add_argument("--limit", type=int, default=20, help="Maximum readiness blockers to include")
    server = subcommands.add_parser("serve", help="Run the local development API server")
    server.add_argument("--workspace", default=".")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    tui = subcommands.add_parser("tui", help="Run the interactive terminal UI")
    tui.add_argument("--workspace", default=".")
    tui.add_argument("--session-id", help="Join an existing session")
    tui.add_argument("--model", help="Model alias or identifier for a new TUI session")
    tui.add_argument("--personality", choices=PERSONALITY_NAMES, help="Personality for a new TUI session")

    task = subcommands.add_parser("task", help="Submit and inspect tasks")
    task_sub = task.add_subparsers(dest="task_command", required=True)
    task_list = task_sub.add_parser("list", help="List recent tasks")
    task_list.add_argument("--limit", type=int, default=20)
    task_list.add_argument("--session-id", help="Only list tasks linked to this conversation session")
    task_submit = task_sub.add_parser("submit", help="Submit a task")
    task_submit.add_argument("request", help="User request")
    task_submit.add_argument("--workspace", default=".", help="Workspace root for scoped connectors")
    task_submit.add_argument("--path", help="Optional path for filesystem tasks")
    task_submit.add_argument("--session-id", help="Attach the task to an existing conversation session")
    task_status = task_sub.add_parser("status", help="Show task status")
    task_status.add_argument("task_id")
    task_status.add_argument("--workspace", default=".")
    task_resume = task_sub.add_parser("resume", help="Resume a task after approval")
    task_resume.add_argument("task_id")
    task_resume.add_argument("--workspace", default=".")
    task_resume.add_argument("--session-id", help="Resume with the same conversation session context")
    task_pause = task_sub.add_parser("pause", help="Pause a non-terminal task")
    task_pause.add_argument("task_id")
    task_pause.add_argument("--workspace", default=".")
    task_pause.add_argument("--session-id", help="Pause with the same conversation session context")
    task_pause.add_argument("--actor", default="local-user")
    task_pause.add_argument("--reason", default="")
    task_cancel = task_sub.add_parser("cancel", help="Cancel a non-terminal task")
    task_cancel.add_argument("task_id")
    task_cancel.add_argument("--workspace", default=".")
    task_cancel.add_argument("--session-id", help="Cancel with the same conversation session context")
    task_cancel.add_argument("--actor", default="local-user")
    task_cancel.add_argument("--reason", default="")
    task_evidence = task_sub.add_parser("evidence", help="Show a task evidence bundle")
    task_evidence.add_argument("task_id")
    task_evidence.add_argument("--workspace", default=".")
    task_timeline = task_sub.add_parser("timeline", help="Show ordered task timeline")
    task_timeline.add_argument("task_id")
    task_timeline.add_argument("--workspace", default=".")
    task_events = task_sub.add_parser("events", help="Show task run-event snapshot")
    task_events.add_argument("task_id")
    task_events.add_argument("--workspace", default=".")

    session = subcommands.add_parser("session", help="Manage conversation sessions")
    session_sub = session.add_subparsers(dest="session_command", required=True)
    session_create = session_sub.add_parser("create", help="Create a session")
    session_create.add_argument("title")
    session_create.add_argument("--channel", default="terminal")
    session_create.add_argument("--model")
    session_create.add_argument("--personality")
    session_list = session_sub.add_parser("list", help="List sessions")
    session_list.add_argument("--limit", type=int, default=50)
    session_show = session_sub.add_parser("show", help="Show one session")
    session_show.add_argument("session_id")
    session_update = session_sub.add_parser("update", help="Update session title, model, personality, or status")
    session_update.add_argument("session_id")
    session_update.add_argument("--title")
    session_update.add_argument("--model")
    session_update.add_argument("--personality")
    session_update.add_argument("--status", choices=("active", "paused", "archived"))
    session_history = session_sub.add_parser("history", help="Show session history")
    session_history.add_argument("session_id")
    session_history.add_argument("--limit", type=int, default=100)
    session_append = session_sub.add_parser("append", help="Append context to a session without submitting a task")
    session_append.add_argument("session_id")
    session_append.add_argument("content")
    session_append.add_argument("--role", choices=("user", "assistant"), default="user")
    session_append.add_argument("--trust-class", default=TrustClass.USER_DIRECTIVE.value, choices=tuple(item.value for item in TrustClass))
    session_compact = session_sub.add_parser("compact", help="Create a compact summary message for older session history")
    session_compact.add_argument("session_id")
    session_compact.add_argument("--keep-last", type=int, default=20)

    approval = subcommands.add_parser("approval", help="Manage approval queue")
    approval_sub = approval.add_subparsers(dest="approval_command", required=True)
    approval_list = approval_sub.add_parser("list", help="List approvals")
    approval_list.add_argument("--status")
    approval_approve = approval_sub.add_parser("approve", help="Approve a request")
    approval_approve.add_argument("approval_id")
    approval_approve.add_argument("--actor", default="local-user")
    approval_approve.add_argument("--reason", default="")
    approval_approve.add_argument("--admin", action="store_true")
    approval_deny = approval_sub.add_parser("deny", help="Deny a request")
    approval_deny.add_argument("approval_id")
    approval_deny.add_argument("--actor", default="local-user")
    approval_deny.add_argument("--reason", default="")
    approval_deny.add_argument("--admin", action="store_true")

    improvement = subcommands.add_parser("improvement", help="Review self-repair proposals")
    improvement.add_argument("--workspace", default=".", help="Workspace root for repair evidence validation")
    improvement_sub = improvement.add_subparsers(dest="improvement_command", required=True)
    improvement_list = improvement_sub.add_parser("list", help="List improvement proposals")
    improvement_list.add_argument("--status")
    improvement_list.add_argument("--limit", type=int, default=50)
    improvement_readiness = improvement_sub.add_parser("readiness", help="Summarize repair readiness blockers")
    improvement_readiness.add_argument("--status")
    improvement_readiness.add_argument("--limit", type=int, default=50)
    improvement_show = improvement_sub.add_parser("show", help="Show one improvement proposal")
    improvement_show.add_argument("proposal_id")
    improvement_status = improvement_sub.add_parser("status", help="Update proposal review status")
    improvement_status.add_argument("proposal_id")
    improvement_status.add_argument("status", choices=("proposed", "reviewing", "approved", "rejected", "implemented"))
    improvement_attempt = improvement_sub.add_parser("attempt", help="Record a governed repair attempt")
    improvement_attempt.add_argument("proposal_id")
    improvement_attempt.add_argument("--outcome", required=True)
    improvement_attempt.add_argument("--notes", default="")
    improvement_attempt.add_argument("--status", choices=("reviewing", "implemented", "rejected"), default="implemented")
    improvement_attempt.add_argument("--actor", default="local-user")
    improvement_attempt.add_argument("--changed-file", action="append", default=[])
    improvement_attempt.add_argument("--candidate-id")
    improvement_attempt.add_argument("--test-command", default="")
    improvement_attempt.add_argument("--test-result", choices=("passed", "failed", "skipped", ""), default="")
    improvement_candidate = improvement_sub.add_parser("candidate", help="Record a pending repair candidate")
    improvement_candidate.add_argument("proposal_id")
    improvement_candidate.add_argument("--summary", required=True)
    improvement_candidate.add_argument("--actor", default="local-user")
    improvement_candidate.add_argument("--changed-file", action="append", default=[])
    improvement_candidate.add_argument("--patch-plan", default="")
    improvement_candidate.add_argument("--patch-file", help="Unified diff file to attach as an unapplied repair candidate")
    improvement_generate = improvement_sub.add_parser("generate-candidate", help="Generate an isolated repair candidate plan")
    improvement_generate.add_argument("proposal_id")
    improvement_generate.add_argument("--actor", default="local-user")
    improvement_prompt = improvement_sub.add_parser("synthesis-prompt", help="Create a redacted model prompt packet for repair synthesis")
    improvement_prompt.add_argument("proposal_id")
    improvement_prompt.add_argument("--actor", default="local-user")
    improvement_synthesize = improvement_sub.add_parser("synthesize-candidate", help="Create a preflighted patch candidate from a model-style JSON synthesis file")
    improvement_synthesize.add_argument("proposal_id")
    improvement_synthesize.add_argument("--synthesis-file", required=True, help="JSON file with summary, patch_plan, unified_diff, and optional changed_files")
    improvement_synthesize.add_argument("--actor", default="local-user")
    improvement_review_candidate = improvement_sub.add_parser("review-candidate", help="Approve or reject a repair candidate before applying it")
    improvement_review_candidate.add_argument("proposal_id")
    improvement_review_candidate.add_argument("candidate_id")
    improvement_review_candidate.add_argument("status", choices=("approved", "rejected"))
    improvement_review_candidate.add_argument("--actor", default="local-user")
    improvement_apply = improvement_sub.add_parser("apply-candidate", help="Apply an approved repair candidate patch")
    improvement_apply.add_argument("proposal_id")
    improvement_apply.add_argument("candidate_id")
    improvement_apply.add_argument("--actor", default="local-user")
    improvement_rollback = improvement_sub.add_parser("rollback-candidate", help="Roll back an applied repair candidate patch")
    improvement_rollback.add_argument("proposal_id")
    improvement_rollback.add_argument("candidate_id")
    improvement_rollback.add_argument("--actor", default="local-user")

    memory = subcommands.add_parser("memory", help="Inspect and edit governed memory")
    memory_sub = memory.add_subparsers(dest="memory_command", required=True)
    memory_create = memory_sub.add_parser("create", help="Create a memory")
    memory_create.add_argument("type", choices=[item.value for item in MemoryType])
    memory_create.add_argument("content")
    memory_create.add_argument("--source", default="cli")
    memory_create.add_argument("--confidence", type=float, default=0.8)
    memory_create.add_argument("--sensitivity", choices=[item.value for item in Sensitivity], default=Sensitivity.INTERNAL.value)
    memory_create.add_argument("--tag", action="append", default=[])
    memory_create.add_argument("--confirmed", action="store_true")
    memory_create.add_argument("--ttl-days", type=int)
    memory_search = memory_sub.add_parser("search", help="Search memory")
    memory_search.add_argument("query")
    memory_health = memory_sub.add_parser("health", help="Summarize memory quality, consolidation, and review posture")
    memory_health.add_argument("--limit", type=int, default=50)
    memory_health.add_argument("--scope", default="workspace")
    memory_health.add_argument("--owner", default="local-user")
    memory_review = memory_sub.add_parser("review-queue", help="List memory items needing review")
    memory_review.add_argument("--limit", type=int, default=50)
    memory_review.add_argument("--scope", default="workspace")
    memory_session_preview = memory_sub.add_parser("session-preview", help="Preview trusted session turns as review-required memory candidates")
    memory_session_preview.add_argument("session_id")
    memory_session_preview.add_argument("--owner", default="local-user")
    memory_session_preview.add_argument("--scope", default="workspace")
    memory_session_preview.add_argument("--limit", type=int, default=25)
    memory_session_commit = memory_sub.add_parser("session-commit", help="Persist trusted session memory preview candidates")
    memory_session_commit.add_argument("session_id")
    memory_session_commit.add_argument("--owner", default="local-user")
    memory_session_commit.add_argument("--scope", default="workspace")
    memory_session_commit.add_argument("--limit", type=int, default=25)
    memory_session_commit.add_argument("--candidate-id", action="append", default=[])
    memory_session_commit.add_argument("--confirmed", action="store_true")
    memory_digest = memory_sub.add_parser("review-digest", help="Summarize memory review priorities")
    memory_digest.add_argument("--limit", type=int, default=10)
    memory_digest.add_argument("--scope", default="workspace")
    memory_escalation = memory_sub.add_parser("review-escalation", help="Summarize overdue memory review items for operator routing")
    memory_escalation.add_argument("--max-age-days", type=int, default=7)
    memory_escalation.add_argument("--limit", type=int, default=10)
    memory_escalation.add_argument("--scope", default="workspace")
    memory_escalation.add_argument("--route", default="operator")
    memory_review_action = memory_sub.add_parser("review-action", help="Confirm or delete a memory from the review queue")
    memory_review_action.add_argument("memory_id")
    memory_review_action.add_argument("action", choices=("confirm", "delete"))
    memory_review_action.add_argument("--confidence", type=float)
    memory_review_action.add_argument("--rationale", default="")
    memory_review_batch = memory_sub.add_parser("review-batch", help="Confirm or delete multiple memory review records")
    memory_review_batch.add_argument("action", choices=("confirm", "delete"))
    memory_review_batch.add_argument("memory_ids", nargs="+")
    memory_review_batch.add_argument("--confidence", type=float)
    memory_review_batch.add_argument("--rationale", default="")
    memory_recertify = memory_sub.add_parser("recertify", help="Mark stale confirmed memories for review")
    memory_recertify.add_argument("--max-age-days", type=int, help="Override configured recertification policy for this run")
    memory_recertify.add_argument("--limit", type=int, default=50)
    memory_recertify.add_argument("--scope", default="workspace")
    memory_recertify.add_argument("--dry-run", action="store_true", help="Preview stale memories without tagging them for review")
    memory_update = memory_sub.add_parser("update", help="Update a memory")
    memory_update.add_argument("memory_id")
    memory_update.add_argument("--content")
    memory_update.add_argument("--confidence", type=float)
    memory_update.add_argument("--confirmed", action="store_true")
    memory_explain = memory_sub.add_parser("explain", help="Explain why a memory matches a query")
    memory_explain.add_argument("memory_id")
    memory_explain.add_argument("query")
    memory_export = memory_sub.add_parser("export", help="Export filtered memory records")
    memory_export.add_argument("query", nargs="?", default="")
    memory_merge = memory_sub.add_parser("merge", help="Merge duplicate memories")
    memory_merge.add_argument("primary_id")
    memory_merge.add_argument("duplicate_id")
    memory_resolve = memory_sub.add_parser("resolve-conflict", help="Resolve conflicting memories")
    memory_resolve.add_argument("primary_id")
    memory_resolve.add_argument("conflicting_id")
    memory_resolve.add_argument("strategy", choices=("keep_primary", "keep_conflicting", "synthesize", "keep_both"))
    memory_resolve.add_argument("--rationale", required=True)
    memory_expire = memory_sub.add_parser("expire", help="Expire a memory")
    memory_expire.add_argument("memory_id")
    memory_sub.add_parser("cleanup-expired", help="Mark expired memories as deleted")
    memory_delete = memory_sub.add_parser("delete", help="Delete a memory")
    memory_delete.add_argument("memory_id")

    skill = subcommands.add_parser("skill", help="Manage governed skills")
    skill_sub = skill.add_subparsers(dest="skill_command", required=True)
    skill_sub.add_parser("list", help="List skills")
    skill_hub = skill_sub.add_parser("hub-search", help="Search the virtual skill hub safely")
    skill_hub.add_argument("query", nargs="?", default="")
    skill_create = skill_sub.add_parser("create", help="Create a disabled skill manifest template")
    skill_create.add_argument("skill_id")
    skill_create.add_argument("--name", required=True)
    skill_create.add_argument("--description", required=True)
    skill_create.add_argument("--output", help="Optional path to write the manifest JSON")
    skill_register = skill_sub.add_parser("register", help="Register a skill manifest JSON file")
    skill_register.add_argument("manifest_path")
    skill_register.add_argument("--enable", action="store_true")
    skill_register.add_argument("--unsigned-local", action="store_true", help="Allow unsigned local development manifests")
    skill_register.add_argument("--key-name", default="AEGIS_SKILL_SIGNING_KEY")
    skill_signing_key = skill_sub.add_parser("signing-key", help="Create or report the local skill signing key")
    skill_signing_key.add_argument("--key-name", default="AEGIS_SKILL_SIGNING_KEY")
    skill_sign = skill_sub.add_parser("sign", help="Sign a skill manifest JSON file")
    skill_sign.add_argument("manifest_path")
    skill_sign.add_argument("--output", help="Path for signed manifest JSON. Defaults to overwriting the input.")
    skill_sign.add_argument("--key-name", default="AEGIS_SKILL_SIGNING_KEY")
    skill_sign.add_argument("--signer", default="local-user")
    skill_verify = skill_sub.add_parser("verify", help="Verify a signed skill manifest JSON file")
    skill_verify.add_argument("manifest_path")
    skill_verify.add_argument("--key-name", default="AEGIS_SKILL_SIGNING_KEY")
    skill_disable = skill_sub.add_parser("disable", help="Disable a skill")
    skill_disable.add_argument("skill_id")
    skill_enable = skill_sub.add_parser("enable", help="Enable a low- or medium-risk skill")
    skill_enable.add_argument("skill_id")
    skill_enable.add_argument("--approval-id", help="Approved high-risk skill enable request")

    for plugin_name in ("plugin", "plugins"):
        plugin = subcommands.add_parser(plugin_name, help="Manage governed local plugins")
        plugin_sub = plugin.add_subparsers(dest="plugin_command", required=True)
        plugin_sub.add_parser("list", help="List installed plugins")
        plugin_install = plugin_sub.add_parser("install", help="Install a local plugin manifest")
        plugin_install.add_argument("manifest_path")
        plugin_install.add_argument("--enable", action="store_true")
        plugin_install.add_argument("--unsigned-local", action="store_true", help="Allow unsigned local development skill manifests")
        plugin_enable = plugin_sub.add_parser("enable", help="Enable plugin default-enabled resources")
        plugin_enable.add_argument("plugin_id")
        plugin_disable = plugin_sub.add_parser("disable", help="Disable plugin resources")
        plugin_disable.add_argument("plugin_id")
        plugin_remove = plugin_sub.add_parser("remove", help="Remove a plugin and its owned resources")
        plugin_remove.add_argument("plugin_id")
        plugin_sub.add_parser("reload", help="Reload plugin inventory from private local state")
        plugin_marketplace = plugin_sub.add_parser("marketplace", help="Search the metadata-only plugin marketplace catalog")
        plugin_marketplace.add_argument("--query", "-q", default="")
        plugin_marketplace.add_argument("--catalog-path", help="Optional local marketplace catalog JSON file")
        plugin_updates = plugin_sub.add_parser("updates", help="Plan plugin updates from marketplace metadata without downloading code")
        plugin_updates.add_argument("--catalog-path", help="Optional local marketplace catalog JSON file")
        plugin_fetch = plugin_sub.add_parser("fetch-manifest", help="Download and verify one marketplace plugin manifest for review")
        plugin_fetch.add_argument("plugin_id")
        plugin_fetch.add_argument("--catalog-path", help="Optional local marketplace catalog JSON file")
        plugin_bundle = plugin_sub.add_parser("fetch-bundle", help="Download and verify one signed marketplace plugin bundle for review")
        plugin_bundle.add_argument("plugin_id")
        plugin_bundle.add_argument("--catalog-path", help="Optional local marketplace catalog JSON file")
        plugin_bundle.add_argument("--key-name", default=DEFAULT_SKILL_SIGNING_KEY, help="Brokered HMAC signing key name")
        plugin_bundle_install = plugin_sub.add_parser("install-bundle", help="Fetch, verify, and install one signed marketplace plugin bundle")
        plugin_bundle_install.add_argument("plugin_id")
        plugin_bundle_install.add_argument("--catalog-path", help="Optional local marketplace catalog JSON file")
        plugin_bundle_install.add_argument("--key-name", default=DEFAULT_SKILL_SIGNING_KEY, help="Brokered HMAC signing key name")
        plugin_bundle_install.add_argument("--enable", action="store_true", help="Enable default-enabled resources after install")
        plugin_marketplace_install = plugin_sub.add_parser("install-marketplace", help="Fetch, verify, and install one marketplace plugin manifest")
        plugin_marketplace_install.add_argument("plugin_id")
        plugin_marketplace_install.add_argument("--catalog-path", help="Optional local marketplace catalog JSON file")
        plugin_marketplace_install.add_argument("--enable", action="store_true", help="Enable default-enabled resources after install")
        plugin_marketplace_update = plugin_sub.add_parser("update-marketplace", help="Fetch, verify, and apply one marketplace plugin update")
        plugin_marketplace_update.add_argument("plugin_id")
        plugin_marketplace_update.add_argument("--catalog-path", help="Optional local marketplace catalog JSON file")
        plugin_marketplace_update.add_argument("--enable", action="store_true", help="Enable default-enabled resources after update")
        plugin_marketplace_update.add_argument("--disable", action="store_true", help="Keep updated resources disabled")
        plugin_marketplace_update.add_argument("--force", action="store_true", help="Allow reinstalling the same or older catalog version")

    connector = subcommands.add_parser("connector", help="List connector status")
    connector_sub = connector.add_subparsers(dest="connector_command", required=True)
    connector_sub.add_parser("list", help="List connectors")
    connector_sub.add_parser("status", help="Show connector health")

    channels = subcommands.add_parser("channel", help="Inspect and test channel adapters")
    channel_sub = channels.add_subparsers(dest="channel_command", required=True)
    channel_sub.add_parser("list", help="List channels")
    channel_sub.add_parser("status", help="Show channel health")
    channel_events = channel_sub.add_parser("events", help="List recent channel events")
    channel_events.add_argument("--limit", type=int, default=20)
    channel_receive = channel_sub.add_parser("receive", help="Normalize an inbound channel message")
    channel_receive.add_argument("channel")
    channel_receive.add_argument("text")
    channel_receive.add_argument("--sender", default="local-user")
    channel_resolve_approval = channel_sub.add_parser("resolve-approval", help="Resolve a recorded channel approval intent against an explicit approval id")
    channel_resolve_approval.add_argument("event_id")
    channel_resolve_approval.add_argument("approval_id")
    channel_resolve_approval.add_argument("--actor", default="")
    channel_resolve_approval.add_argument("--reason", default="")
    channel_resolve_approval.add_argument("--admin", action="store_true")
    channel_render = channel_sub.add_parser("render", help="Render an outbound channel message pending approval")
    channel_render.add_argument("channel")
    channel_render.add_argument("text")
    channel_render.add_argument("--session-id")
    channel_send_webhook = channel_sub.add_parser("send-webhook", help="Send a signed live outbound webhook after approval")
    channel_send_webhook.add_argument("text")
    channel_send_webhook.add_argument("--session-id")
    channel_send_webhook.add_argument("--approved", action="store_true")
    channel_send_email = channel_sub.add_parser("send-email", help="Send a live outbound email after approval")
    channel_send_email.add_argument("subject")
    channel_send_email.add_argument("text")
    channel_send_email.add_argument("--session-id")
    channel_send_email.add_argument("--approved", action="store_true")
    channel_send_chat_webhook = channel_sub.add_parser("send-chat-webhook", help="Send a live outbound chat webhook after approval")
    channel_send_chat_webhook.add_argument("text")
    channel_send_chat_webhook.add_argument("--session-id")
    channel_send_chat_webhook.add_argument("--approved", action="store_true")

    remote_control = subcommands.add_parser(
        "remote-control",
        aliases=["rc"],
        help="Inspect local remote-control and relay readiness",
    )
    remote_control.set_defaults(command="remote-control")
    remote_control_sub = remote_control.add_subparsers(dest="remote_control_command", required=True)
    remote_control_sub.add_parser("status", help="Show local remote-control pairing readiness")
    remote_control_pair = remote_control_sub.add_parser("pair", help="Create a short-lived scoped remote-control pairing token")
    remote_control_pair.add_argument("--label", default="", help="Pairing label shown in public status")
    remote_control_pair.add_argument("--session-id", help="Optional session scope")
    remote_control_pair.add_argument("--task-id", help="Optional task scope")
    remote_control_pair.add_argument(
        "--allowed-actions",
        default="status,events,pause,cancel",
        help="Comma-separated task actions",
    )
    remote_control_pair.add_argument(
        "--expires-in-seconds",
        type=int,
        default=600,
        help="Pairing TTL, clamped between 60 and 3600",
    )
    remote_control_pair.add_argument("--host", default="127.0.0.1", help="Local API host to render in endpoint hints")
    remote_control_pair.add_argument("--port", type=int, default=8765, help="Local API port to render in endpoint hints")
    remote_control_revoke = remote_control_sub.add_parser("revoke", help="Revoke a local remote-control pairing")
    remote_control_revoke.add_argument("pairing_id")
    remote_control_revoke.add_argument("--relay-auth-secret", help="Brokered secret name used to propagate relay revocation")
    remote_control_revoke.add_argument("--approved", action="store_true", help="Approve one outbound relay revocation notice")
    remote_control_relay = remote_control_sub.add_parser("relay", help="Show outbound relay preflight blockers or register an approved pairing")
    remote_control_relay.add_argument("--relay-url")
    remote_control_relay.add_argument("--pairing-id", help="Active pairing id to register with the relay")
    remote_control_relay.add_argument("--relay-auth-secret", help="Brokered secret name for relay bearer auth")
    remote_control_relay.add_argument("--approved", action="store_true", help="Approve one outbound relay registration")
    remote_control_relay_pull = remote_control_sub.add_parser("relay-pull", help="Pull queued scoped actions from a registered relay")
    remote_control_relay_pull.add_argument("--pairing-id", required=True, help="Registered pairing id")
    remote_control_relay_pull.add_argument("--relay-auth-secret", required=True, help="Brokered secret name for relay bearer auth")
    remote_control_relay_pull.add_argument("--approved", action="store_true", help="Approve one outbound relay action pull")
    remote_control_relay_pull.add_argument("--limit", type=int, default=10, help="Maximum action envelopes to pull")
    remote_control_relay_pull.add_argument("--dry-run", action="store_true", help="Pull and validate queued actions without executing them")
    remote_control_relay_action = remote_control_sub.add_parser("relay-action", help="Execute a registered relay-authenticated task action")
    remote_control_relay_action.add_argument("--pairing-id", required=True, help="Registered pairing id")
    remote_control_relay_action.add_argument("--task-id", required=True, help="Task id to control through the relay proxy")
    remote_control_relay_action.add_argument("--action", required=True, choices=["status", "events", "resume", "pause", "cancel"], help="Scoped remote-control action")
    remote_control_relay_action.add_argument("--relay-auth-secret", required=True, help="Brokered secret name for relay bearer auth")
    remote_control_relay_action.add_argument("--session-id", help="Optional session id for resume/pause/cancel")
    remote_control_relay_action.add_argument("--reason", default="", help="Optional reason for pause/cancel")

    models = subcommands.add_parser("model", aliases=["models"], help="Manage model routes and usage")
    model_sub = models.add_subparsers(dest="model_command", required=True)
    model_sub.add_parser("list", help="List supported models")
    model_sub.add_parser("providers", help="List model providers and auth status")
    model_route = model_sub.add_parser("route", help="Resolve a model identifier or alias")
    model_route.add_argument("identifier")
    model_alias = model_sub.add_parser("alias", help="Set a model alias")
    model_alias.add_argument("alias")
    model_alias.add_argument("identifier")
    model_fallbacks = model_sub.add_parser("fallbacks", help="Set fallback model identifiers")
    model_fallbacks.add_argument("identifier")
    model_fallbacks.add_argument("fallback", nargs="+")
    model_auth = model_sub.add_parser("auth", help="Manage model provider auth")
    model_auth_sub = model_auth.add_subparsers(dest="auth_command", required=True)
    model_auth_status = model_auth_sub.add_parser("status", help="Show model provider auth status")
    model_auth_status.add_argument("provider", nargs="?")
    model_auth_methods = model_auth_sub.add_parser("methods", help="Show supported auth methods and subscription login status")
    model_auth_methods.add_argument("provider", nargs="?")
    model_auth_sub.add_parser("targets", help="Show Hermes/Claude provider auth parity targets")
    model_auth_login = model_auth_sub.add_parser("login", help="Store an API key or start a guarded provider-native login handoff")
    model_auth_login.add_argument(
        "provider",
        choices=(
            "openai",
            "openrouter",
            "anthropic",
            "google",
            "google-gemini-oauth",
            "mistral",
            "cohere",
            "nous",
            "deepseek",
            "xai",
            "kimi",
            "minimax",
            "minimax-oauth",
            "zai",
            "qwen",
            "qwen-oauth",
            "github-copilot",
            "aws-bedrock",
            "azure-foundry",
            "nous-oauth",
            "custom",
        ),
    )
    model_auth_login.add_argument("--method", choices=("api-key", "subscription", "oauth", "oauth-device", "cloud-identity"), default="api-key")
    model_auth_login.add_argument("--subscription", action="store_true", help="Alias for --method subscription")
    model_auth_login.add_argument("--run-external", action="store_true", help="Launch the provider's official interactive login command without capturing tokens")
    model_auth_login.add_argument("--verify-external", action="store_true", help="Run the provider's official non-secret status command and remember a verified external login")
    model_auth_login.add_argument("--api-key", help="API key value. Prefer --api-key-stdin or interactive entry.")
    model_auth_login.add_argument("--api-key-stdin", action="store_true", help="Read API key from stdin")
    model_auth_logout = model_auth_sub.add_parser("logout", help="Remove a model provider API key or verified external auth link")
    model_auth_logout.add_argument(
        "provider",
        choices=(
            "openai",
            "openrouter",
            "anthropic",
            "google",
            "google-gemini-oauth",
            "mistral",
            "cohere",
            "nous",
            "deepseek",
            "xai",
            "kimi",
            "minimax",
            "minimax-oauth",
            "zai",
            "qwen",
            "qwen-oauth",
            "github-copilot",
            "aws-bedrock",
            "azure-foundry",
            "nous-oauth",
            "custom",
        ),
    )
    model_sub.add_parser("usage", help="Show usage summary")

    tools = subcommands.add_parser("tool", help="List or run governed tools")
    tool_sub = tools.add_subparsers(dest="tool_command", required=True)
    tool_sub.add_parser("list", help="List tools")
    tool_run = tool_sub.add_parser("run", help="Run a governed tool with JSON params")
    tool_run.add_argument("name")
    tool_run.add_argument("params", help="JSON object of tool params")
    tool_run.add_argument("--workspace", default=".")
    tool_run.add_argument("--approved", action="store_true", help="Mark the tool call as already approved")

    backend = subcommands.add_parser("backend", help="List execution backends")
    backend_sub = backend.add_subparsers(dest="backend_command", required=True)
    backend_sub.add_parser("list", help="List execution backends")

    evaluation = subcommands.add_parser("evaluation", help="Review local evaluation reports")
    evaluation_sub = evaluation.add_subparsers(dest="evaluation_command", required=True)
    evaluation_queue = evaluation_sub.add_parser("queue", help="List evaluation reports waiting for review")
    evaluation_queue.add_argument("--limit", type=int, default=20)
    evaluation_queue.add_argument("--reviewer")
    evaluation_review = evaluation_sub.add_parser("review", help="Record reviewer disposition for an evaluation report")
    evaluation_review.add_argument("report_id")
    evaluation_review.add_argument("status", choices=("reviewed_passed", "reviewed_failed", "needs_followup", "dismissed"))
    evaluation_review.add_argument("--reviewer", default="local")
    evaluation_review.add_argument("--notes", default="")
    evaluation_trends = evaluation_sub.add_parser("trends", help="Show evaluation report trend summary")
    evaluation_trends.add_argument("--limit", type=int, default=20)
    evaluation_delta = evaluation_sub.add_parser("delta", help="Compare evaluation reports and flag regressions")
    evaluation_delta.add_argument("--baseline-report-id")
    evaluation_delta.add_argument("--candidate-report-id")
    evaluation_delta.add_argument("--scenario")
    evaluation_readiness = evaluation_sub.add_parser("readiness", help="Summarize release readiness from evaluation evidence")
    evaluation_readiness.add_argument("--baseline-report-id")
    evaluation_readiness.add_argument("--candidate-report-id")
    evaluation_readiness.add_argument("--scenario")
    evaluation_readiness.add_argument("--reviewer")
    evaluation_readiness.add_argument("--limit", type=int, default=20)
    evaluation_readiness.add_argument("--include-live-gaps", action="store_true")
    evaluation_readiness.add_argument("--defer-live-gap", action="append", default=[])
    evaluation_readiness.add_argument("--live-gap-deferral-reason")

    schedule = subcommands.add_parser("schedule", help="Manage scheduled automations")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    schedule_create = schedule_sub.add_parser("create", help="Create a paused schedule")
    schedule_create.add_argument("name")
    schedule_create.add_argument("cron")
    schedule_create.add_argument("task_request")
    schedule_create.add_argument("--natural-language", default="")
    schedule_create.add_argument("--channel", default="terminal")
    schedule_digest = schedule_sub.add_parser("memory-review-digest", help="Create a paused schedule that renders memory review digests")
    schedule_digest.add_argument("name")
    schedule_digest.add_argument("cron")
    schedule_digest.add_argument("--channel", default="terminal")
    schedule_digest.add_argument("--limit", type=int, default=10)
    schedule_digest.add_argument("--scope", default="workspace")
    schedule_escalation = schedule_sub.add_parser("memory-review-escalation", help="Create a paused schedule that renders overdue memory review escalations")
    schedule_escalation.add_argument("name")
    schedule_escalation.add_argument("cron")
    schedule_escalation.add_argument("--channel", default="terminal")
    schedule_escalation.add_argument("--max-age-days", type=int, default=7)
    schedule_escalation.add_argument("--limit", type=int, default=10)
    schedule_escalation.add_argument("--scope", default="workspace")
    schedule_escalation.add_argument("--route", default="operator")
    schedule_evaluation = schedule_sub.add_parser("evaluation-run", help="Create a paused schedule that records local evaluation reports")
    schedule_evaluation.add_argument("name")
    schedule_evaluation.add_argument("cron")
    schedule_evaluation.add_argument("scenario")
    schedule_evaluation.add_argument("steps", nargs="*")
    schedule_evaluation.add_argument("--channel", default="terminal")
    schedule_evaluation.add_argument("--reviewer", default="scheduler")
    schedule_suite = schedule_sub.add_parser("evaluation-suite", help="Create a paused schedule that records local evaluation suite reports")
    schedule_suite.add_argument("name")
    schedule_suite.add_argument("cron")
    schedule_suite.add_argument("--suite", default="security")
    schedule_suite.add_argument("--scenario-id", action="append", default=[])
    schedule_suite.add_argument("--channel", default="terminal")
    schedule_suite.add_argument("--reviewer", default="scheduler")
    schedule_sub.add_parser("list", help="List schedules")
    schedule_activate = schedule_sub.add_parser("activate", help="Activate a paused schedule")
    schedule_activate.add_argument("schedule_id")
    schedule_pause = schedule_sub.add_parser("pause", help="Pause an active schedule")
    schedule_pause.add_argument("schedule_id")
    schedule_approve = schedule_sub.add_parser("approve", help="Approve a reviewed schedule for activation")
    schedule_approve.add_argument("schedule_id")
    schedule_approve.add_argument("--approved-by", default="local-user")
    schedule_sub.add_parser("due", help="List schedules due to run now")
    schedule_sub.add_parser("run-due", help="Submit all due active schedules")

    kanban = subcommands.add_parser("kanban", help="Manage work boards")
    kanban_sub = kanban.add_subparsers(dest="kanban_command", required=True)
    board_create = kanban_sub.add_parser("board-create", help="Create a board")
    board_create.add_argument("name")
    kanban_sub.add_parser("boards", help="List boards")
    card_add = kanban_sub.add_parser("card-add", help="Add a card")
    card_add.add_argument("board_id")
    card_add.add_argument("title")
    card_add.add_argument("description")
    card_add.add_argument("--lane", default="backlog")
    card_list = kanban_sub.add_parser("cards", help="List cards")
    card_list.add_argument("board_id")
    card_move = kanban_sub.add_parser("card-move", help="Move a card")
    card_move.add_argument("card_id")
    card_move.add_argument("lane")

    agents = subcommands.add_parser("agents", help="Inspect and queue governed subagent delegations")
    agents.add_argument("--workspace", default=".")
    agents_sub = agents.add_subparsers(dest="agents_command", required=True)
    agents_status = agents_sub.add_parser("status", help="Show subagent delegation queue status")
    agents_status.add_argument("--limit", type=int, default=20)
    agents_delegate = agents_sub.add_parser("delegate", help="Queue a subagent delegation card through the governed tool path")
    agents_delegate.add_argument("role")
    agents_delegate.add_argument("task")
    agents_delegate.add_argument("--approved", action="store_true")
    agents_delegate.add_argument("--task-id")
    agents_delegate.add_argument("--limit", type=int, default=20)

    mcp = subcommands.add_parser("mcp", help="Manage governed MCP server registrations")
    mcp_sub = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_register = mcp_sub.add_parser("register", help="Register an MCP server disabled by default")
    mcp_register.add_argument("name")
    mcp_register.add_argument("server_command")
    mcp_register.add_argument("--tool", action="append", default=[])
    mcp_register.add_argument("--exclude-tool", action="append", default=[])
    mcp_register.add_argument("--discover", action="store_true")
    mcp_register.add_argument("--no-resources", action="store_true", help="Do not register MCP resource utility wrappers during discovery")
    mcp_register.add_argument("--no-prompts", action="store_true", help="Do not register MCP prompt utility wrappers during discovery")
    mcp_register.add_argument("--enable", action="store_true")
    mcp_register.add_argument("--no-approval", action="store_true")
    mcp_call = mcp_sub.add_parser("call", help="Call an allowlisted MCP tool after approval")
    mcp_call.add_argument("server")
    mcp_call.add_argument("tool")
    mcp_call.add_argument("--arguments", default="{}")
    mcp_call.add_argument("--approved", action="store_true")
    mcp_sub.add_parser("list", help="List MCP servers")

    hooks = subcommands.add_parser("hooks", help="Manage governed local lifecycle hooks")
    hooks.add_argument("--workspace", default=".")
    hooks_sub = hooks.add_subparsers(dest="hooks_command", required=True)
    hooks_sub.add_parser("list", help="List configured hooks")
    hooks_add = hooks_sub.add_parser("add", help="Register a disabled hook unless --enabled is set")
    hooks_add.add_argument("add_args", nargs=argparse.REMAINDER)
    hooks_enable = hooks_sub.add_parser("enable", help="Enable a hook")
    hooks_enable.add_argument("hook_id")
    hooks_disable = hooks_sub.add_parser("disable", help="Disable a hook")
    hooks_disable.add_argument("hook_id")
    hooks_remove = hooks_sub.add_parser("remove", help="Remove a hook")
    hooks_remove.add_argument("hook_id")
    hooks_run = hooks_sub.add_parser("run", help="Run enabled hooks for one event")
    hooks_run.add_argument("event", choices=HOOK_EVENTS)
    hooks_run.add_argument("--approved", action="store_true")
    hooks_run.add_argument("--context-json", default="{}")

    personality = subcommands.add_parser("personality", help="Inspect built-in personalities and context files")
    personality_sub = personality.add_subparsers(dest="personality_command", required=True)
    personality_sub.add_parser("list", help="List built-in personalities")
    personality_load = personality_sub.add_parser("context", help="Load SOUL/AGENTS/TOOLS context files safely")
    personality_load.add_argument("--workspace", default=".")

    migrate = subcommands.add_parser("migrate", help="Dry-run migration inspections")
    migrate_sub = migrate.add_subparsers(dest="migrate_command", required=True)
    migrate_openclaw = migrate_sub.add_parser("openclaw", help="Inspect an OpenClaw home directory")
    migrate_openclaw.add_argument("path")
    migrate_hermes = migrate_sub.add_parser("hermes", help="Inspect a Hermes home directory")
    migrate_hermes.add_argument("path")
    migrate_openclaw_memory = migrate_sub.add_parser("openclaw-memory-preview", help="Preview sanitized OpenClaw memory candidates without importing")
    migrate_openclaw_memory.add_argument("path")
    migrate_openclaw_memory.add_argument("--owner", default="local-user")
    migrate_openclaw_memory.add_argument("--scope", default="workspace")
    migrate_openclaw_commit = migrate_sub.add_parser("openclaw-memory-commit", help="Persist sanitized OpenClaw memory preview candidates")
    migrate_openclaw_commit.add_argument("path")
    migrate_openclaw_commit.add_argument("--owner", default="local-user")
    migrate_openclaw_commit.add_argument("--scope", default="workspace")
    migrate_openclaw_commit.add_argument("--candidate-id", action="append", default=[])
    migrate_openclaw_commit.add_argument("--confirmed", action="store_true")
    migrate_openclaw_commit.add_argument("--reviewer", default="local-user")
    migrate_hermes_memory = migrate_sub.add_parser("hermes-memory-preview", help="Preview sanitized Hermes memory candidates without importing")
    migrate_hermes_memory.add_argument("path")
    migrate_hermes_memory.add_argument("--owner", default="local-user")
    migrate_hermes_memory.add_argument("--scope", default="workspace")
    migrate_hermes_commit = migrate_sub.add_parser("hermes-memory-commit", help="Persist sanitized Hermes memory preview candidates")
    migrate_hermes_commit.add_argument("path")
    migrate_hermes_commit.add_argument("--owner", default="local-user")
    migrate_hermes_commit.add_argument("--scope", default="workspace")
    migrate_hermes_commit.add_argument("--candidate-id", action="append", default=[])
    migrate_hermes_commit.add_argument("--confirmed", action="store_true")
    migrate_hermes_commit.add_argument("--reviewer", default="local-user")
    migrate_sub.add_parser("schema", help="Show local SQLite schema migration status")
    migrate_sub.add_parser("plan", help="Dry-run local SQLite migration plan")
    migrate_external = migrate_sub.add_parser("external-plan", help="Dry-run an external database migration target")
    migrate_external.add_argument("target", choices=("postgresql", "postgres", "mysql", "mariadb"))
    migrate_external_runner = migrate_sub.add_parser("external-runner", help="Generate operator-reviewed external database migration runner files")
    migrate_external_runner.add_argument("target", choices=("postgresql", "postgres", "mysql", "mariadb"))
    migrate_external_runner.add_argument("--output-dir", required=True)
    migrate_external_runner.add_argument("--force", action="store_true")
    migrate_backup = migrate_sub.add_parser("backup", help="Create a private SQLite backup before migration work")
    migrate_backup.add_argument("--destination")

    policy = subcommands.add_parser("policy", help="Inspect policy bundles")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_sub.add_parser("bundles", help="List built-in policy bundles")
    policy_export = policy_sub.add_parser("export-bundle", help="Export a built-in policy bundle as TOML")
    policy_export.add_argument("name")
    policy_import = policy_sub.add_parser("import-bundle", help="Validate an external policy bundle TOML file")
    policy_import.add_argument("path")
    policy_apply = policy_sub.add_parser("apply-bundle", help="Apply a built-in bundle or external TOML policy bundle")
    policy_apply.add_argument("source")
    policy_apply.add_argument("--name")
    policy_apply.add_argument("--approved", action="store_true")
    policy_diff = policy_sub.add_parser("diff-bundle", help="Preview changes from a built-in or external policy bundle")
    policy_diff.add_argument("source")
    policy_rollback = policy_sub.add_parser("rollback-bundle", help="Roll back the last applied policy bundle")
    policy_rollback.add_argument("--approved", action="store_true")
    policy_schedule = policy_sub.add_parser("schedule-bundle", help="Schedule a policy bundle activation receipt")
    policy_schedule.add_argument("source")
    policy_schedule.add_argument("--activate-at", required=True)
    policy_schedule.add_argument("--environment", default="local")
    policy_schedule.add_argument("--name")
    policy_schedule.add_argument("--approved", action="store_true")
    policy_promote = policy_sub.add_parser("promote-bundle", help="Promote a policy bundle between named environments")
    policy_promote.add_argument("source")
    policy_promote.add_argument("--from-environment", required=True)
    policy_promote.add_argument("--to-environment", required=True)
    policy_promote.add_argument("--name")
    policy_promote.add_argument("--approved", action="store_true")
    policy_promote.add_argument("--require-clean-evaluation", action="store_true")
    policy_promote.add_argument("--require-live-parity", action="store_true")
    policy_promote.add_argument("--defer-live-gap", action="append", default=[])
    policy_promote.add_argument("--live-gap-deferral-reason")
    policy_promote.add_argument("--baseline-report-id")
    policy_promote.add_argument("--candidate-report-id")
    policy_promote.add_argument("--evaluation-scenario")
    policy_activate_due = policy_sub.add_parser("activate-due", help="Activate approved due policy rollout receipts")
    policy_activate_due.add_argument("--environment")
    policy_activate_due.add_argument("--now")
    policy_activate_due.add_argument("--limit", type=int, default=20)
    policy_sub.add_parser("rollouts", help="List scheduled policy rollout receipts")
    policy_promotions = policy_sub.add_parser("promotions", help="List policy promotion receipts")
    policy_promotions.add_argument("--limit", type=int, default=20)

    audit = subcommands.add_parser("audit", help="Inspect audit logs")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_log = audit_sub.add_parser("log", help="Tail audit log")
    audit_log.add_argument("--limit", type=int, default=20)
    audit_export = audit_sub.add_parser("export-siem", help="Export normalized redacted audit events as SIEM JSONL")
    audit_export.add_argument("--limit", type=int, default=1000)
    audit_export.add_argument("--task-id")
    audit_export.add_argument("--event-type")
    audit_sub.add_parser("verify", help="Verify audit hash chain")

    return parser


def _capabilities_view(dashboard: dict[str, Any]) -> dict[str, Any]:
    return {
        "product": dashboard.get("product", {}),
        "runtime": {
            key: value
            for key, value in dashboard.get("runtime", {}).items()
            if key
            in {
                "tools",
                "approval_gated_tools",
                "limited_or_facade_tools",
                "sessions",
                "open_subagent_delegations",
                "memory_health_score",
            }
        },
        "capability_groups": dashboard.get("capability_groups", []),
        "implementation_readiness": dashboard.get("implementation_readiness", []),
        "live_gap_backlog": dashboard.get("live_gap_backlog", []),
        "model_provider_auth_parity": dashboard.get("model_provider_auth_parity", {}),
        "competitive_targets": dashboard.get("competitive_targets", []),
    }


def dispatch(args: argparse.Namespace) -> dict[str, Any] | None:
    config = load_config(args.data_dir)
    if args.command == "init":
        path = write_default_config(args.data_dir)
        store = LocalStore(config.database_path)
        audit = AuditLogger(config.audit_log_path)
        audit.append("runtime.initialized", {"config": str(path), "database": str(store.database_path)})
        return {"ok": True, "config": str(path), "database": str(store.database_path), "audit_log": str(audit.path)}

    if args.command == "health":
        store = LocalStore(config.database_path)
        audit = AuditLogger(config.audit_log_path)
        connectors = build_default_registry(config, audit)
        return {"ok": True, "data_dir": str(config.data_dir), "database": str(store.database_path), "audit_chain_ok": audit.verify_chain(), "connectors": connectors.status()}

    if args.command == "dashboard":
        orchestrator = build_orchestrator(data_dir=args.data_dir)
        return build_product_dashboard(orchestrator)

    if args.command == "capabilities":
        orchestrator = build_orchestrator(data_dir=args.data_dir)
        return _capabilities_view(build_product_dashboard(orchestrator))

    if args.command == "enterprise-readiness":
        return _enterprise_readiness(args, config)

    if args.command == "serve":
        serve(data_dir=args.data_dir, workspace=args.workspace, host=args.host, port=args.port)
        return None

    if args.command == "tui":
        run_tui(
            data_dir=args.data_dir,
            workspace=args.workspace,
            session_id=args.session_id,
            model=args.model,
            personality=args.personality,
        )
        return None

    if args.command == "task":
        orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=getattr(args, "workspace", "."))
        if args.task_command == "list":
            return {"tasks": [_task_list_payload(orchestrator, row) for row in orchestrator.store.list_tasks(limit=args.limit, session_id=args.session_id)]}
        if args.task_command == "submit":
            return orchestrator.submit_task(args.request, path=args.path, session_id=args.session_id)
        if args.task_command == "status":
            return orchestrator.status(args.task_id)
        if args.task_command == "resume":
            return orchestrator.resume_task(args.task_id, session_id=args.session_id)
        if args.task_command == "pause":
            return orchestrator.pause_task(args.task_id, session_id=args.session_id, actor=args.actor, reason=args.reason)
        if args.task_command == "cancel":
            return orchestrator.cancel_task(args.task_id, session_id=args.session_id, actor=args.actor, reason=args.reason)
        if args.task_command == "evidence":
            return orchestrator.evidence.build(args.task_id)
        if args.task_command == "timeline":
            return orchestrator.evidence.timeline(args.task_id)
        if args.task_command == "events":
            return orchestrator.evidence.run_events(args.task_id)

    if args.command == "session":
        manager = _session_manager(config)
        if args.session_command == "create":
            return manager.create_session(title=args.title, channel=args.channel, model=args.model, personality=args.personality)
        if args.session_command == "list":
            return {"sessions": manager.list_sessions(limit=args.limit)}
        if args.session_command == "show":
            return manager.get_session(args.session_id)
        if args.session_command == "update":
            return manager.update_session(
                args.session_id,
                title=args.title,
                model=args.model,
                personality=args.personality,
                status=args.status,
            )
        if args.session_command == "history":
            return {"messages": manager.history(args.session_id, limit=args.limit)}
        if args.session_command == "append":
            return manager.add_message(
                args.session_id,
                role=args.role,
                content=args.content,
                trust_class=TrustClass(args.trust_class),
                metadata={"source": "cli", "submitted": False},
            )
        if args.session_command == "compact":
            return manager.compact_history(args.session_id, keep_last=args.keep_last)

    if args.command == "approval":
        orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=".")
        if args.approval_command == "list":
            return {"approvals": [_approval_payload(orchestrator, row) for row in orchestrator.approvals.list(status=args.status)]}
        if args.approval_command == "approve":
            return _approval_payload(orchestrator, orchestrator.approvals.approve(args.approval_id, actor=args.actor, reason=args.reason, admin=args.admin))
        if args.approval_command == "deny":
            return _approval_payload(orchestrator, orchestrator.approvals.deny(args.approval_id, actor=args.actor, reason=args.reason, admin=args.admin))

    if args.command == "improvement":
        orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=args.workspace)
        if args.improvement_command == "list":
            return {"proposals": orchestrator.list_improvement_proposals(status=args.status, limit=args.limit)}
        if args.improvement_command == "readiness":
            return orchestrator.repair_readiness_summary(status=args.status, limit=args.limit)
        if args.improvement_command == "show":
            return orchestrator.get_improvement_proposal(args.proposal_id)
        if args.improvement_command == "status":
            return orchestrator.update_improvement_proposal(args.proposal_id, status=args.status)
        if args.improvement_command == "attempt":
            return orchestrator.record_improvement_attempt(
                args.proposal_id,
                outcome=args.outcome,
                notes=args.notes,
                status=args.status,
                actor=args.actor,
                changed_files=tuple(args.changed_file),
                candidate_id=args.candidate_id,
                test_command=args.test_command,
                test_result=args.test_result,
            )
        if args.improvement_command == "candidate":
            return orchestrator.create_repair_candidate(
                args.proposal_id,
                summary=args.summary,
                actor=args.actor,
                changed_files=tuple(args.changed_file),
                patch_plan=args.patch_plan,
                unified_diff=Path(args.patch_file).read_text(encoding="utf-8") if args.patch_file else "",
            )
        if args.improvement_command == "generate-candidate":
            return orchestrator.generate_repair_candidate(args.proposal_id, actor=args.actor)
        if args.improvement_command == "synthesis-prompt":
            return orchestrator.create_repair_synthesis_prompt(args.proposal_id, actor=args.actor)
        if args.improvement_command == "synthesize-candidate":
            synthesis = json.loads(Path(args.synthesis_file).read_text(encoding="utf-8"))
            return orchestrator.synthesize_repair_candidate(args.proposal_id, synthesis=synthesis, actor=args.actor)
        if args.improvement_command == "review-candidate":
            return orchestrator.review_repair_candidate(args.proposal_id, args.candidate_id, status=args.status, actor=args.actor)
        if args.improvement_command == "apply-candidate":
            return orchestrator.apply_repair_candidate(args.proposal_id, args.candidate_id, actor=args.actor)
        if args.improvement_command == "rollback-candidate":
            return orchestrator.rollback_repair_candidate(args.proposal_id, args.candidate_id, actor=args.actor)

    if args.command == "memory":
        manager = _memory_manager(config)
        if args.memory_command == "create":
            record = manager.create_memory(
                memory_type=MemoryType(args.type),
                content=args.content,
                source=args.source,
                provenance={"cli": True},
                confidence=args.confidence,
                sensitivity=Sensitivity(args.sensitivity),
                tags=tuple(args.tag),
                confirmed=args.confirmed,
                ttl_days=args.ttl_days,
            )
            return record.to_row()
        if args.memory_command == "search":
            return {"memories": manager.retrieve_relevant(args.query)}
        if args.memory_command == "health":
            return manager.health_report(limit=args.limit, owner=args.owner, scope=args.scope)
        if args.memory_command == "review-queue":
            return manager.review_queue(limit=args.limit, scope=args.scope)
        if args.memory_command == "session-preview":
            sessions = _session_manager(config)
            return manager.preview_session_memory_candidates(
                session_id=args.session_id,
                messages=sessions.history(args.session_id, limit=1000),
                owner=args.owner,
                scope=args.scope,
                limit=args.limit,
            )
        if args.memory_command == "session-commit":
            sessions = _session_manager(config)
            return manager.commit_session_memory_candidates(
                session_id=args.session_id,
                messages=sessions.history(args.session_id, limit=1000),
                owner=args.owner,
                scope=args.scope,
                limit=args.limit,
                candidate_ids=list(args.candidate_id) or None,
                confirmed=args.confirmed,
            )
        if args.memory_command == "review-digest":
            return manager.review_digest(limit=args.limit, scope=args.scope)
        if args.memory_command == "review-escalation":
            return manager.review_escalation(max_age_days=args.max_age_days, limit=args.limit, scope=args.scope, route=args.route)
        if args.memory_command == "review-action":
            return manager.review_memory(args.memory_id, action=args.action, confidence=args.confidence, rationale=args.rationale)
        if args.memory_command == "review-batch":
            return manager.review_memory_batch(list(args.memory_ids), action=args.action, confidence=args.confidence, rationale=args.rationale)
        if args.memory_command == "recertify":
            return manager.recertify_due(max_age_days=args.max_age_days, limit=args.limit, scope=args.scope, dry_run=args.dry_run)
        if args.memory_command == "update":
            return manager.update_memory(args.memory_id, content=args.content, confidence=args.confidence, confirmed=args.confirmed)
        if args.memory_command == "explain":
            return {"memory_id": args.memory_id, "query": args.query, "explanation": manager.explain_usage(args.memory_id, args.query)}
        if args.memory_command == "export":
            return {"memories": manager.export_memory(args.query), "query": args.query}
        if args.memory_command == "merge":
            return manager.merge_duplicate(args.primary_id, args.duplicate_id)
        if args.memory_command == "resolve-conflict":
            return manager.resolve_conflict(args.primary_id, args.conflicting_id, strategy=args.strategy, rationale=args.rationale)
        if args.memory_command == "expire":
            return manager.expire_memory(args.memory_id)
        if args.memory_command == "cleanup-expired":
            return manager.cleanup_expired()
        if args.memory_command == "delete":
            manager.delete_memory(args.memory_id)
            return {"ok": True, "deleted": args.memory_id}

    if args.command == "skill":
        registry = _skill_registry(config)
        if args.skill_command == "list":
            return {"skills": registry.list()}
        if args.skill_command == "hub-search":
            return SkillHubCatalog().search(args.query)
        if args.skill_command == "create":
            manifest = create_skill_template(args.skill_id, name=args.name, description=args.description)
            if args.output:
                Path(args.output).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                return {"ok": True, "path": args.output, "manifest": manifest}
            return {"manifest": manifest}
        if args.skill_command == "register":
            raw = json.loads(Path(args.manifest_path).read_text(encoding="utf-8"))
            manifest = registry.register(
                SkillManifest.from_dict(raw),
                enable=args.enable,
                require_signature=not args.unsigned_local,
                signature_key_name=args.key_name,
            )
            return manifest.to_dict()
        if args.skill_command == "signing-key":
            return {"ok": True, **ensure_signing_key(SecretsBroker(config.secrets_path), key_name=args.key_name)}
        if args.skill_command == "sign":
            broker = SecretsBroker(config.secrets_path)
            ensure_signing_key(broker, key_name=args.key_name)
            path = Path(args.manifest_path)
            raw = json.loads(path.read_text(encoding="utf-8"))
            signed = sign_manifest(SkillManifest.from_dict(raw).to_dict(), broker, key_name=args.key_name, signer=args.signer)
            output = Path(args.output) if args.output else path
            output.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return {"ok": True, "path": str(output), "signature": signed["signature"]}
        if args.skill_command == "verify":
            raw = json.loads(Path(args.manifest_path).read_text(encoding="utf-8"))
            return verify_manifest_signature(raw, SecretsBroker(config.secrets_path), required=True, key_name=args.key_name)
        if args.skill_command == "disable":
            registry.disable(args.skill_id)
            return {"ok": True, "disabled": args.skill_id}
        if args.skill_command == "enable":
            orchestrator = build_orchestrator(data_dir=config.data_dir)
            return orchestrator.enable_skill(args.skill_id, approval_id=args.approval_id)

    if args.command in {"plugin", "plugins"}:
        manager = _plugin_manager(config)
        if args.plugin_command == "list":
            return {"status": "governed_local_ready", "plugins": manager.list_plugins()}
        if args.plugin_command == "install":
            return {"plugin": manager.install_plugin(args.manifest_path, enable=args.enable, unsigned_local=args.unsigned_local)}
        if args.plugin_command == "enable":
            return manager.enable_plugin(args.plugin_id)
        if args.plugin_command == "disable":
            return manager.disable_plugin(args.plugin_id)
        if args.plugin_command == "remove":
            return manager.remove_plugin(args.plugin_id)
        if args.plugin_command == "reload":
            return {"ok": True, "mode": "private_plugin_inventory", "plugins": manager.list_plugins()}
        if args.plugin_command == "marketplace":
            return manager.marketplace(query=args.query, catalog_path=args.catalog_path)
        if args.plugin_command == "updates":
            return manager.update_plan(catalog_path=args.catalog_path)
        if args.plugin_command == "fetch-manifest":
            return manager.fetch_marketplace_manifest(
                args.plugin_id,
                catalog_path=args.catalog_path,
                allowlist=config.network_allowlist,
            )
        if args.plugin_command == "fetch-bundle":
            return manager.fetch_marketplace_bundle(
                args.plugin_id,
                catalog_path=args.catalog_path,
                allowlist=config.network_allowlist,
                key_name=args.key_name,
            )
        if args.plugin_command == "install-bundle":
            return manager.install_marketplace_bundle(
                args.plugin_id,
                catalog_path=args.catalog_path,
                allowlist=config.network_allowlist,
                key_name=args.key_name,
                enable=args.enable,
            )
        if args.plugin_command == "install-marketplace":
            return manager.install_marketplace_plugin(
                args.plugin_id,
                catalog_path=args.catalog_path,
                allowlist=config.network_allowlist,
                enable=args.enable,
            )
        if args.plugin_command == "update-marketplace":
            if args.enable and args.disable:
                raise ValueError("use either --enable or --disable, not both")
            return manager.update_marketplace_plugin(
                args.plugin_id,
                catalog_path=args.catalog_path,
                allowlist=config.network_allowlist,
                enable=True if args.enable else False if args.disable else None,
                force=args.force,
            )

    if args.command == "connector":
        audit = AuditLogger(config.audit_log_path)
        connectors = build_default_registry(config, audit)
        if args.connector_command == "list":
            return {"connectors": connectors.list()}
        if args.connector_command == "status":
            return {"connectors": connectors.status()}

    if args.command == "channel":
        registry = _channel_registry(config)
        if args.channel_command == "list":
            return {"channels": registry.list_channels()}
        if args.channel_command == "status":
            return {"channels": registry.status()}
        if args.channel_command == "events":
            return {"events": registry.events(limit=args.limit)}
        if args.channel_command == "receive":
            registry.receive(args.channel, {"sender": args.sender, "text": args.text})
            return {"message": registry.events(limit=1)[0]}
        if args.channel_command == "resolve-approval":
            orchestrator = build_orchestrator(data_dir=config.data_dir)
            result = orchestrator.resolve_channel_approval_intent(
                event_id=args.event_id,
                approval_id=args.approval_id,
                actor=args.actor,
                reason=args.reason,
                admin=args.admin,
            )
            return {**result, "approval": _approval_payload(orchestrator, result["approval"])}
        if args.channel_command == "render":
            return {
                "status": "rendered_pending_approval",
                "rendered": registry.render(
                    ChannelResponse(
                        channel=args.channel,
                        text=args.text,
                        metadata={"session_id": args.session_id, "source": "cli"},
                    )
                ),
            }
        if args.channel_command == "send-webhook":
            return build_orchestrator(data_dir=config.data_dir).send_webhook(text=args.text, approved=args.approved, session_id=args.session_id, metadata={"source": "cli"})
        if args.channel_command == "send-email":
            return build_orchestrator(data_dir=config.data_dir).send_email(subject=args.subject, text=args.text, approved=args.approved, session_id=args.session_id, metadata={"source": "cli"})
        if args.channel_command == "send-chat-webhook":
            return build_orchestrator(data_dir=config.data_dir).send_chat_webhook(text=args.text, approved=args.approved, session_id=args.session_id, metadata={"source": "cli"})

    if args.command == "remote-control":
        registry = RemoteControlPairingRegistry(config.data_dir / "remote_control_pairings.json")
        if args.remote_control_command == "status":
            return registry.status()
        if args.remote_control_command == "pair":
            result = registry.create_pairing(
                label=args.label,
                session_id=args.session_id,
                task_id=args.task_id,
                allowed_actions=_comma_separated(args.allowed_actions),
                ttl_seconds=args.expires_in_seconds,
                endpoint_host=args.host,
                endpoint_port=args.port,
            )
            AuditLogger(config.audit_log_path).append(
                "remote_control.pairing_created",
                {
                    "pairing_id": result["pairing"]["id"],
                    "label": result["pairing"]["label"],
                    "session_id": result["pairing"].get("session_id"),
                    "task_id": result["pairing"].get("task_id"),
                    "allowed_actions": result["pairing"].get("allowed_actions"),
                    "expires_at": result["pairing"]["expires_at"],
                    "token_header": result["token_header"],
                    "token_captured": False,
                    "source": "cli",
                },
            )
            return result
        if args.remote_control_command == "revoke":
            relay_auth_token = None
            if args.relay_auth_secret or args.approved:
                if not args.relay_auth_secret or not args.approved:
                    raise ValueError("relay revocation propagation requires --relay-auth-secret and --approved")
                broker = SecretsBroker(config.secrets_path)
                handle = broker.request_handle(
                    name=args.relay_auth_secret,
                    requester="remote_control_relay",
                    reason="propagate scoped remote-control relay revocation",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
            result = registry.revoke(args.pairing_id, relay_auth_token=relay_auth_token, notify_relay=bool(relay_auth_token))
            AuditLogger(config.audit_log_path).append(
                "remote_control.pairing_revoked",
                {
                    "pairing_id": result["pairing"]["id"],
                    "label": result["pairing"]["label"],
                    "session_id": result["pairing"].get("session_id"),
                    "token_captured": False,
                    "relay_revocation_propagated": result["relay_revocation_propagated"],
                    "source": "cli",
                },
            )
            return result
        if args.remote_control_command == "relay":
            if args.approved or args.pairing_id or args.relay_auth_secret:
                if not args.relay_url or not args.pairing_id or not args.relay_auth_secret:
                    raise ValueError("approved remote-control relay requires --relay-url, --pairing-id, and --relay-auth-secret")
                broker = SecretsBroker(config.secrets_path)
                handle = broker.request_handle(
                    name=args.relay_auth_secret,
                    requester="remote_control_relay",
                    reason="register scoped remote-control pairing with relay",
                    scopes=("remote_control:relay",),
                )
                relay_auth_token = broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
                result = registry.relay_pairing(
                    args.pairing_id,
                    relay_url=args.relay_url,
                    allowlist=config.network_allowlist,
                    relay_auth_token=relay_auth_token,
                    approved=args.approved,
                )
                AuditLogger(config.audit_log_path).append(
                    "remote_control.relay_registered",
                    {
                        "pairing_id": result["pairing"]["id"],
                        "relay_target": result["relay_target"],
                        "relay_auth_secret": "[REDACTED]",
                        "pairing_token_relayed": result["pairing_token_relayed"],
                        "raw_secret_values_included": False,
                        "source": "cli",
                    },
                )
                return result
            return registry.relay_preflight(relay_url=args.relay_url)
        if args.remote_control_command == "relay-pull":
            broker = SecretsBroker(config.secrets_path)
            handle = broker.request_handle(
                name=args.relay_auth_secret,
                requester="remote_control_relay",
                reason="pull queued scoped remote-control relay actions",
                scopes=("remote_control:relay",),
            )
            relay_auth_token = broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
            pulled = registry.pull_relay_actions(
                args.pairing_id,
                relay_auth_token=relay_auth_token,
                allowlist=config.network_allowlist,
                approved=args.approved,
                limit=args.limit,
            )
            orchestrator = build_orchestrator(data_dir=config.data_dir)
            actor = f"remote-control-relay:{pulled['pairing'].get('label') or pulled['pairing']['id']}"
            executed_actions = []
            if not args.dry_run:
                for action_row in pulled["actions"]:
                    if not action_row["accepted"]:
                        continue
                    action_result = _execute_remote_control_action(orchestrator, action_row, actor=actor)
                    orchestrator.audit_logger.append(
                        "remote_control.relay_action",
                        {
                            "pairing_id": pulled["pairing"]["id"],
                            "relay_target": pulled["relay_target"],
                            "task_id": action_row["task_id"],
                            "action": action_row["action"],
                            "actor": actor,
                            "request_id": action_row.get("request_id"),
                            "pairing_token_relayed": False,
                            "relay_auth_token_captured": False,
                            "raw_secret_values_included": False,
                            "source": "cli_pull",
                        },
                    )
                    executed_actions.append(
                        {
                            "request_id": action_row.get("request_id"),
                            "action": action_row["action"],
                            "task_id": action_row["task_id"],
                            "status": "executed",
                            "result": action_result,
                        }
                    )
            orchestrator.audit_logger.append(
                "remote_control.relay_actions_pulled",
                {
                    "pairing_id": pulled["pairing"]["id"],
                    "relay_target": pulled["relay_target"],
                    "action_count": pulled["action_count"],
                    "executable_action_count": pulled["executable_action_count"],
                    "executed_action_count": len(executed_actions),
                    "dry_run": args.dry_run,
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "cli",
                },
            )
            return {**pulled, "dry_run": args.dry_run, "executed_action_count": len(executed_actions), "executed_actions": executed_actions}
        if args.remote_control_command == "relay-action":
            broker = SecretsBroker(config.secrets_path)
            handle = broker.request_handle(
                name=args.relay_auth_secret,
                requester="remote_control_relay",
                reason="authorize registered remote-control relay action proxy",
                scopes=("remote_control:relay",),
            )
            relay_auth_token = broker.resolve_for_authorized_tool(handle, requester="remote_control_relay")
            relay_auth = registry.authorize_relay_action(
                args.pairing_id,
                relay_auth_token,
                action=args.action,
                task_id=args.task_id,
            )
            if relay_auth is None:
                raise PermissionError("missing or invalid remote-control relay authorization")
            orchestrator = build_orchestrator(data_dir=config.data_dir)
            actor = f"remote-control-relay:{relay_auth['pairing'].get('label') or relay_auth['pairing']['id']}"
            if args.action == "status":
                action_result = orchestrator.status(args.task_id)
            elif args.action == "events":
                action_result = orchestrator.evidence.run_events(args.task_id)
            elif args.action == "resume":
                action_result = orchestrator.resume_task(args.task_id, session_id=args.session_id, actor=actor)
            elif args.action == "pause":
                action_result = orchestrator.pause_task(
                    args.task_id,
                    session_id=args.session_id,
                    actor=actor,
                    reason=args.reason or "remote control relay pause",
                )
            else:
                action_result = orchestrator.cancel_task(
                    args.task_id,
                    session_id=args.session_id,
                    actor=actor,
                    reason=args.reason or "remote control relay cancel",
                )
            orchestrator.audit_logger.append(
                "remote_control.relay_action",
                {
                    "pairing_id": relay_auth["pairing"]["id"],
                    "relay_target": relay_auth["relay_target"],
                    "task_id": args.task_id,
                    "action": args.action,
                    "actor": actor,
                    "pairing_token_relayed": False,
                    "relay_auth_token_captured": False,
                    "raw_secret_values_included": False,
                    "source": "cli",
                },
            )
            return {
                "status": "relay_action_proxied",
                "mode": "approved_relay_action_proxy",
                "action": args.action,
                "task_id": args.task_id,
                "pairing": relay_auth["pairing"],
                "relay_target": relay_auth["relay_target"],
                "pairing_token_relayed": False,
                "relay_auth_token_captured": False,
                "raw_secret_values_included": False,
                "result": action_result,
            }

    if args.command in {"model", "models"}:
        registry = _model_registry(config)
        if args.model_command == "list":
            return {"models": registry.list_models()}
        if args.model_command == "providers":
            return {"providers": registry.list_providers()}
        if args.model_command == "route":
            route = registry.route(args.identifier)
            return {
                "identifier": route.identifier,
                "provider": route.provider.provider,
                "model": route.model,
                "fallbacks": list(route.fallback_identifiers),
                "secret_handle_id": route.secret_handle_id,
                "auth_method": route.auth_method,
            }
        if args.model_command == "alias":
            registry.set_alias(args.alias, args.identifier)
            return {"ok": True, "alias": args.alias, "identifier": args.identifier}
        if args.model_command == "fallbacks":
            registry.set_fallbacks(args.identifier, tuple(args.fallback))
            return {"ok": True, "identifier": args.identifier, "fallbacks": list(args.fallback)}
        if args.model_command == "auth":
            if args.auth_command == "status":
                return {"auth": registry.auth_status(args.provider)}
            if args.auth_command == "methods":
                return {"auth": registry.auth_status(args.provider)}
            if args.auth_command == "targets":
                return {"auth_targets": registry.auth_targets()}
            if args.auth_command == "login":
                method = "subscription" if getattr(args, "subscription", False) else str(args.method)
                if method in {"subscription", "oauth", "oauth-device", "cloud-identity"}:
                    if getattr(args, "api_key", None) or getattr(args, "api_key_stdin", False):
                        raise ValueError(f"{method} login does not accept API key input")
                    status = registry.login_provider_external(
                        args.provider,
                        method=method,
                        run_external=bool(getattr(args, "run_external", False)),
                        verify_external=bool(getattr(args, "verify_external", False)),
                    )
                else:
                    if getattr(args, "run_external", False) or getattr(args, "verify_external", False):
                        raise ValueError("--run-external and --verify-external are only valid with subscription, OAuth, or cloud-identity login")
                    status = registry.login_provider(args.provider, _read_api_key(args))
                return {"ok": True, "auth": status}
            if args.auth_command == "logout":
                status = registry.logout_provider(args.provider)
                return {"ok": True, "auth": status}
        if args.model_command == "usage":
            return registry.usage_summary()

    if args.command == "tool":
        if args.tool_command == "list":
            registry = _mcp_registry(config)
            return {"tools": [*ToolCatalog().list(), *registry.virtual_tool_specs()]}
        if args.tool_command == "run":
            params = json.loads(args.params)
            if not isinstance(params, dict):
                raise ValueError("tool params must be a JSON object")
            orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=args.workspace)
            return orchestrator.tools.execute(args.name, params, approved=args.approved)

    if args.command == "backend":
        if args.backend_command == "list":
            return {"backends": ExecutionBackendRegistry().list()}

    if args.command == "evaluation":
        harness = ResearchHarness(data_dir=config.data_dir)
        if args.evaluation_command == "queue":
            return harness.evaluation_review_queue(limit=args.limit, reviewer=args.reviewer)
        if args.evaluation_command == "review":
            return harness.review_evaluation_report(args.report_id, status=args.status, reviewer=args.reviewer, notes=args.notes)
        if args.evaluation_command == "trends":
            return harness.evaluation_trends(limit=args.limit)
        if args.evaluation_command == "delta":
            return harness.evaluation_regression_delta(
                baseline_report_id=args.baseline_report_id,
                candidate_report_id=args.candidate_report_id,
                scenario=args.scenario,
            )
        if args.evaluation_command == "readiness":
            live_gap_backlog = None
            if args.include_live_gaps:
                orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=Path.cwd())
                live_gap_backlog = build_product_dashboard(orchestrator).get("live_gap_backlog", [])
            return harness.release_readiness_summary(
                baseline_report_id=args.baseline_report_id,
                candidate_report_id=args.candidate_report_id,
                scenario=args.scenario,
                reviewer=args.reviewer,
                limit=args.limit,
                live_gap_backlog=live_gap_backlog,
                deferred_live_gap_areas=args.defer_live_gap,
                live_gap_deferral_reason=args.live_gap_deferral_reason,
            )

    if args.command == "schedule":
        manager = _schedule_manager(config)
        if args.schedule_command == "create":
            return manager.create_schedule(
                name=args.name,
                natural_language=args.natural_language or args.task_request,
                cron=args.cron,
                task_request=args.task_request,
                channel=args.channel,
            )
        if args.schedule_command == "memory-review-digest":
            return manager.create_memory_review_digest_schedule(
                name=args.name,
                cron=args.cron,
                channel=args.channel,
                limit=args.limit,
                scope=args.scope,
            )
        if args.schedule_command == "memory-review-escalation":
            return manager.create_memory_review_escalation_schedule(
                name=args.name,
                cron=args.cron,
                channel=args.channel,
                max_age_days=args.max_age_days,
                limit=args.limit,
                scope=args.scope,
                route=args.route,
            )
        if args.schedule_command == "evaluation-run":
            return manager.create_evaluation_run_schedule(
                name=args.name,
                cron=args.cron,
                scenario=args.scenario,
                steps=tuple(args.steps),
                channel=args.channel,
                reviewer=args.reviewer,
            )
        if args.schedule_command == "evaluation-suite":
            return manager.create_evaluation_suite_schedule(
                name=args.name,
                cron=args.cron,
                suite=args.suite,
                scenario_ids=tuple(args.scenario_id),
                channel=args.channel,
                reviewer=args.reviewer,
            )
        if args.schedule_command == "list":
            return {"schedules": manager.list_schedules()}
        if args.schedule_command == "activate":
            return manager.activate(args.schedule_id)
        if args.schedule_command == "pause":
            return manager.pause(args.schedule_id)
        if args.schedule_command == "approve":
            return manager.approve(args.schedule_id, approved_by=args.approved_by)
        if args.schedule_command == "due":
            return {"schedules": manager.due()}
        if args.schedule_command == "run-due":
            orchestrator = build_orchestrator(data_dir=args.data_dir)
            return orchestrator.run_due_schedules()

    if args.command == "kanban":
        manager = _kanban_manager(config)
        if args.kanban_command == "board-create":
            return manager.create_board(args.name)
        if args.kanban_command == "boards":
            return {"boards": manager.list_boards()}
        if args.kanban_command == "card-add":
            return manager.add_card(args.board_id, title=args.title, description=args.description, lane=args.lane)
        if args.kanban_command == "cards":
            return {"cards": manager.list_cards(args.board_id)}
        if args.kanban_command == "card-move":
            manager.move_card(args.card_id, args.lane)
            return {"ok": True, "card_id": args.card_id, "lane": args.lane}

    if args.command == "agents":
        orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=args.workspace)
        if args.agents_command == "status":
            return orchestrator.kanban.subagent_status(limit=args.limit)
        if args.agents_command == "delegate":
            result = orchestrator.tools.execute(
                "subagent_delegate",
                {"role": args.role, "task": args.task},
                approved=args.approved,
                task_id=args.task_id,
            )
            return {**result, "subagents": orchestrator.kanban.subagent_status(limit=args.limit)}

    if args.command == "mcp":
        registry = _mcp_registry(config)
        if args.mcp_command == "register":
            if args.discover:
                return registry.register_discovered_server(
                    name=args.name,
                    command=args.server_command,
                    allowed_executables=config.allowed_shell_commands,
                    include_tools=tuple(args.tool),
                    exclude_tools=tuple(args.exclude_tool),
                    include_resources=not args.no_resources,
                    include_prompts=not args.no_prompts,
                    enabled=args.enable,
                    approval_required=not args.no_approval,
                    metadata={"source": "cli"},
                )
            return registry.register_server(
                name=args.name,
                command=args.server_command,
                allowed_tools=tuple(args.tool),
                enabled=args.enable,
                approval_required=not args.no_approval,
            )
        if args.mcp_command == "call":
            orchestrator = build_orchestrator(data_dir=args.data_dir)
            return orchestrator.tools.execute(
                "mcp_call",
                {"server": args.server, "tool": args.tool, "arguments": json.loads(args.arguments)},
                approved=args.approved,
            )
        if args.mcp_command == "list":
            return {"servers": registry.list_servers(), "virtual_tools": registry.virtual_tools()}

    if args.command == "hooks":
        manager = _hook_manager(config, workspace=args.workspace)
        if args.hooks_command == "list":
            return _hooks_inventory(manager, config)
        if args.hooks_command == "add":
            return {"hook": manager.register_hook(**_hook_add_spec(args.add_args))}
        if args.hooks_command == "enable":
            return {"hook": manager.set_enabled(args.hook_id, True)}
        if args.hooks_command == "disable":
            return {"hook": manager.set_enabled(args.hook_id, False)}
        if args.hooks_command == "remove":
            return {"hook": manager.remove_hook(args.hook_id), "removed": True}
        if args.hooks_command == "run":
            context = json.loads(args.context_json)
            if not isinstance(context, dict):
                raise ValueError("--context-json must decode to a JSON object")
            return manager.run_event(args.event, context=context, approved=args.approved)

    if args.command == "personality":
        if args.personality_command == "list":
            return {"personalities": list(PERSONALITY_NAMES)}
        if args.personality_command == "context":
            loader = ContextFileLoader(args.workspace)
            return {"items": [item.to_dict() for item in loader.load()]}

    if args.command == "migrate":
        if args.migrate_command == "openclaw":
            return inspect_openclaw_home(args.path)
        if args.migrate_command == "hermes":
            return inspect_hermes_home(args.path)
        if args.migrate_command == "openclaw-memory-preview":
            return preview_openclaw_memory_import(args.path, owner=args.owner, scope=args.scope)
        if args.migrate_command == "hermes-memory-preview":
            return preview_hermes_memory_import(args.path, owner=args.owner, scope=args.scope)
        if args.migrate_command == "openclaw-memory-commit":
            preview = preview_openclaw_memory_import(args.path, owner=args.owner, scope=args.scope)
            return _memory_manager(config).commit_preview_candidates(
                preview,
                candidate_ids=list(args.candidate_id) or None,
                confirmed=args.confirmed,
                reviewer=args.reviewer,
            )
        if args.migrate_command == "hermes-memory-commit":
            preview = preview_hermes_memory_import(args.path, owner=args.owner, scope=args.scope)
            return _memory_manager(config).commit_preview_candidates(
                preview,
                candidate_ids=list(args.candidate_id) or None,
                confirmed=args.confirmed,
                reviewer=args.reviewer,
            )
        if args.migrate_command == "schema":
            return LocalStore(config.database_path).schema_status()
        if args.migrate_command == "plan":
            return LocalStore(config.database_path).schema_plan()
        if args.migrate_command == "external-plan":
            return LocalStore(config.database_path).external_schema_plan(args.target)
        if args.migrate_command == "external-runner":
            return LocalStore(config.database_path).external_schema_runner(args.target, output_dir=args.output_dir, force=args.force)
        if args.migrate_command == "backup":
            return LocalStore(config.database_path).backup(args.destination)

    if args.command == "policy":
        if args.policy_command == "bundles":
            return {"bundles": list_policy_bundles()}
        if args.policy_command == "export-bundle":
            return export_policy_bundle(args.name)
        if args.policy_command == "import-bundle":
            return import_policy_bundle(args.path, base=config.policy_profile)
        if args.policy_command == "apply-bundle":
            return apply_policy_bundle(args.source, data_dir=config.data_dir, approved=args.approved, name=args.name, base=config.policy_profile)
        if args.policy_command == "diff-bundle":
            return diff_policy_bundle(args.source, current=config.policy_profile, base=config.policy_profile)
        if args.policy_command == "rollback-bundle":
            return rollback_policy_bundle(data_dir=config.data_dir, approved=args.approved)
        if args.policy_command == "schedule-bundle":
            return schedule_policy_bundle(
                args.source,
                data_dir=config.data_dir,
                activate_at=args.activate_at,
                environment=args.environment,
                approved=args.approved,
                name=args.name,
                base=config.policy_profile,
            )
        if args.policy_command == "promote-bundle":
            live_gap_backlog = None
            if args.require_live_parity:
                orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=Path.cwd())
                live_gap_backlog = build_product_dashboard(orchestrator).get("live_gap_backlog", [])
            return promote_policy_bundle(
                args.source,
                data_dir=config.data_dir,
                from_environment=args.from_environment,
                to_environment=args.to_environment,
                approved=args.approved,
                name=args.name,
                base=config.policy_profile,
                require_clean_evaluation=args.require_clean_evaluation,
                baseline_report_id=args.baseline_report_id,
                candidate_report_id=args.candidate_report_id,
                evaluation_scenario=args.evaluation_scenario,
                require_live_parity=args.require_live_parity,
                live_gap_backlog=live_gap_backlog,
                deferred_live_gap_areas=args.defer_live_gap,
                live_gap_deferral_reason=args.live_gap_deferral_reason,
            )
        if args.policy_command == "activate-due":
            return activate_due_policy_rollouts(data_dir=config.data_dir, now=args.now, environment=args.environment, limit=args.limit)
        if args.policy_command == "rollouts":
            return list_policy_rollouts(data_dir=config.data_dir)
        if args.policy_command == "promotions":
            return list_policy_promotions(data_dir=config.data_dir, limit=args.limit)

    if args.command == "audit":
        audit = AuditLogger(config.audit_log_path)
        if args.audit_command == "log":
            return {"events": audit.tail(args.limit)}
        if args.audit_command == "export-siem":
            return audit.export_siem(limit=args.limit, task_id=args.task_id, event_type=args.event_type)
        if args.audit_command == "verify":
            return {"ok": audit.verify_chain()}

    raise ValueError("unhandled command")


def _enterprise_readiness(args: argparse.Namespace, config: Any) -> dict[str, Any]:
    selected = _selected_enterprise_surfaces(args)
    surfaces: list[dict[str, Any]] = []
    if "memory" in selected:
        surfaces.append(_memory_enterprise_readiness(config))
    if "self_improvement" in selected:
        orchestrator = build_orchestrator(data_dir=args.data_dir, workspace=".")
        surfaces.append(_self_improvement_enterprise_readiness(orchestrator, limit=args.limit))
    if "tui" in selected:
        surfaces.append(_tui_enterprise_readiness())

    flags = {str(surface["surface"]): bool(surface["ready"]) for surface in surfaces}
    blocked = [surface for surface in surfaces if not surface["ready"]]
    return {
        "ok": True,
        "status": "blocked" if blocked else "ready_with_operator_gates",
        "flags": flags,
        "surface_count": len(surfaces),
        "surfaces": surfaces,
    }


def _selected_enterprise_surfaces(args: argparse.Namespace) -> list[str]:
    selected = []
    if args.memory:
        selected.append("memory")
    if args.self_improvement:
        selected.append("self_improvement")
    if args.tui:
        selected.append("tui")
    return selected or ["memory", "self_improvement", "tui"]


def _memory_enterprise_readiness(config: Any) -> dict[str, Any]:
    retention = config.memory_retention
    health = _memory_manager(config).health_report(limit=20, log=False)
    return {
        "surface": "memory",
        "ready": True,
        "status": health["status"],
        "command": "memory",
        "capabilities": [
            "create_search_update_export",
            "session_preview_and_commit",
            "health_report",
            "review_queue_digest_escalation",
            "recertification_and_expiry",
            "merge_and_conflict_resolution",
        ],
        "health_score": health["health_score"],
        "memory_count": health["memory_count"],
        "recommendation_count": health["recommendation_count"],
        "issue_counts": health["issue_counts"],
        "policy": {
            "ttl_policy_configured": retention.default_ttl_days is not None or bool(retention.ttl_days_by_type),
            "recertification_policy_configured": retention.default_recertification_days is not None or bool(retention.recertification_days_by_type),
            "escalation_routes_configured": bool(retention.escalation_routes),
        },
        "operator_gates": ["review-required memory candidates", "recertification", "sensitivity labels"],
    }


def _self_improvement_enterprise_readiness(orchestrator: Any, *, limit: int) -> dict[str, Any]:
    readiness = orchestrator.repair_readiness_summary(limit=limit)
    return {
        "surface": "self_improvement",
        "ready": bool(readiness["ready"]),
        "status": readiness["status"],
        "command": "improvement",
        "capabilities": [
            "proposal_review",
            "repair_readiness_gate",
            "candidate_generation_and_synthesis",
            "candidate_review",
            "apply_rollback_and_verification_receipts",
        ],
        "proposal_count": readiness["proposal_count"],
        "blocker_count": readiness["blocker_count"],
        "blockers": readiness["blockers"],
        "next_actions": readiness["next_actions"][:3],
    }


def _tui_enterprise_readiness() -> dict[str, Any]:
    return {
        "surface": "tui",
        "ready": True,
        "status": "ready",
        "command": "tui",
        "cli_flags": ["--workspace", "--session-id", "--model", "--personality"],
        "active_flags": ["audit", "approvals", "session", "mode", "tools", "providers", "model", "workspace"],
        "shield_frames": len(SHIELD_FRAMES),
        "slash_aliases": True,
        "slash_palette": True,
        "nested_menus": True,
        "operator_gates": ["interactive local session", "existing approval and policy gates"],
    }


def _memory_manager(config: Any) -> MemoryManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return MemoryManager(
        store,
        audit,
        default_ttl_days=config.memory_retention.default_ttl_days,
        ttl_days_by_type=config.memory_retention.ttl_days_by_type,
        default_recertification_days=config.memory_retention.default_recertification_days,
        recertification_days_by_type=config.memory_retention.recertification_days_by_type,
        escalation_routes=config.memory_retention.escalation_routes,
    )


def _skill_registry(config: Any) -> SkillRegistry:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return SkillRegistry(store, audit, SecretsBroker(config.secrets_path))


def _session_manager(config: Any) -> SessionManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return SessionManager(store, audit)


def _task_list_payload(orchestrator: Any, row: dict[str, Any]) -> dict[str, Any]:
    payload = dict(row)
    payload["action_hints"] = _task_action_hints(payload.get("id"), payload.get("session_id"), status=payload.get("status"))
    if payload.get("session_id"):
        payload["session"] = orchestrator.status(str(payload["id"])).get("session")
    else:
        payload["session"] = None
    return payload


def _task_action_hints(task_id: Any, session_id: Any, *, status: Any) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    task_id_text = str(task_id) if task_id else ""
    if session_id:
        session_id_text = str(session_id)
        hints.extend(
            [
                {"label": "Show Session", "command": f"session show {session_id_text}", "action": "session_show", "session_id": session_id_text},
                {"label": "Session History", "command": f"session history {session_id_text}", "action": "session_history", "session_id": session_id_text},
            ]
        )
    if task_id_text and status in {"waiting_approval", "paused"}:
        hints.append({"label": "Resume", "command": f"task resume {task_id_text}", "action": "task_resume", "task_id": task_id_text})
    return hints


def _approval_payload(orchestrator: Any, row: dict[str, Any]) -> dict[str, Any]:
    payload = dict(row)
    payload["session_id"] = None
    payload["session"] = None
    task_id = payload.get("task_id")
    if task_id:
        try:
            task = orchestrator.status(str(task_id))
        except KeyError:
            task = {}
        payload["session_id"] = task.get("session_id")
        payload["session"] = task.get("session")
    elif isinstance(payload.get("payload"), dict):
        payload_session_id = payload["payload"].get("session_id")
        if isinstance(payload_session_id, str):
            payload["session_id"] = payload_session_id
    request_payload = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
    payload["action_hints"] = approval_action_hints(
        payload,
        task_id=task_id,
        session_id=payload.get("session_id"),
        admin_required=bool(request_payload.get("admin_required")) if isinstance(request_payload, dict) else False,
    )
    return payload


def _execute_remote_control_action(orchestrator: Any, action_row: dict[str, Any], *, actor: str) -> dict[str, Any]:
    task_id = str(action_row["task_id"])
    action = str(action_row["action"])
    session_id = action_row.get("session_id")
    reason = str(action_row.get("reason") or "")
    if action == "status":
        return orchestrator.status(task_id)
    if action == "events":
        return orchestrator.evidence.run_events(task_id)
    if action == "resume":
        return orchestrator.resume_task(task_id, session_id=session_id, actor=actor)
    if action == "pause":
        return orchestrator.pause_task(task_id, session_id=session_id, actor=actor, reason=reason or "remote control relay pause")
    if action == "cancel":
        return orchestrator.cancel_task(task_id, session_id=session_id, actor=actor, reason=reason or "remote control relay cancel")
    raise PermissionError("remote-control relay action is not allowed")


def _channel_registry(config: Any) -> ChannelRegistry:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return ChannelRegistry(store, audit)


def _model_registry(config: Any) -> ModelRegistry:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return ModelRegistry(
        store,
        audit,
        SecretsBroker(config.secrets_path),
        custom_base_url=config.custom_model_base_url,
        azure_foundry_base_url=config.azure_foundry_base_url,
        google_vertex_project=config.google_vertex_project,
        google_vertex_location=config.google_vertex_location,
    )


def _read_api_key(args: argparse.Namespace) -> str:
    if getattr(args, "api_key", None) and getattr(args, "api_key_stdin", False):
        raise ValueError("use either --api-key or --api-key-stdin, not both")
    if getattr(args, "api_key", None):
        return str(args.api_key)
    if getattr(args, "api_key_stdin", False):
        return sys.stdin.read().strip()
    return getpass.getpass(f"{args.provider} API key: ").strip()


def _schedule_manager(config: Any) -> ScheduleManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return ScheduleManager(store, audit)


def _kanban_manager(config: Any) -> KanbanManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return KanbanManager(store, audit)


def _mcp_registry(config: Any) -> McpRegistry:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    return McpRegistry(store, audit)


def _plugin_manager(config: Any) -> PluginManager:
    store = LocalStore(config.database_path)
    audit = AuditLogger(config.audit_log_path)
    skills = SkillRegistry(store, audit, SecretsBroker(config.secrets_path))
    mcp = McpRegistry(store, audit)
    hooks = HookManager(config.data_dir / "hooks.json", audit, allowed_executables=config.allowed_shell_commands, workspace=Path.cwd())
    return PluginManager(config.data_dir / "plugins.json", audit, skills=skills, mcp=mcp, hooks=hooks, secrets_broker=SecretsBroker(config.secrets_path))


def _hook_manager(config: Any, *, workspace: str | Path) -> HookManager:
    audit = AuditLogger(config.audit_log_path)
    return HookManager(config.data_dir / "hooks.json", audit, allowed_executables=config.allowed_shell_commands, workspace=workspace)


def _hooks_inventory(manager: HookManager, config: Any) -> dict[str, Any]:
    return {
        "status": "governed_local_ready",
        "hooks": manager.list_hooks(),
        "supported_events": list(HOOK_EVENTS),
        "allowed_executables": list(config.allowed_shell_commands),
        "raw_secret_values_included": False,
    }


def _hook_add_spec(parts: list[str]) -> dict[str, Any]:
    if not parts:
        raise ValueError("hook event required")
    event = parts[0]
    if event not in HOOK_EVENTS:
        raise ValueError(f"unsupported hook event: {event}")
    hook_id: str | None = None
    enabled = False
    approval_required = True
    timeout_seconds = 10
    max_output_bytes = 4096
    command: list[str] = []
    index = 1
    while index < len(parts):
        part = parts[index]
        if part == "--":
            command = parts[index + 1 :]
            break
        if part == "--id":
            hook_id = _required_next_arg(parts, index, "--id")
            index += 2
            continue
        if part == "--enabled":
            enabled = True
            index += 1
            continue
        if part == "--disabled":
            enabled = False
            index += 1
            continue
        if part == "--approval-required":
            approval_required = True
            index += 1
            continue
        if part == "--no-approval-required":
            approval_required = False
            index += 1
            continue
        if part == "--timeout":
            timeout_seconds = int(_required_next_arg(parts, index, "--timeout"))
            index += 2
            continue
        if part == "--max-output-bytes":
            max_output_bytes = int(_required_next_arg(parts, index, "--max-output-bytes"))
            index += 2
            continue
        command = parts[index:]
        break
    if not command:
        raise ValueError("hook command required; use -- before command arguments when needed")
    return {
        "event": event,
        "command": command,
        "hook_id": hook_id,
        "enabled": enabled,
        "approval_required": approval_required,
        "timeout_seconds": timeout_seconds,
        "max_output_bytes": max_output_bytes,
    }


def _required_next_arg(parts: list[str], index: int, flag: str) -> str:
    if index + 1 >= len(parts):
        raise ValueError(f"{flag} requires a value")
    return parts[index + 1]


def _comma_separated(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def create_skill_template(skill_id: str, *, name: str, description: str) -> dict[str, Any]:
    return {
        "id": skill_id,
        "name": name,
        "description": description,
        "version": "0.1.0",
        "author": "local-user",
        "source": "cli-generated",
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


if __name__ == "__main__":
    raise SystemExit(main())
