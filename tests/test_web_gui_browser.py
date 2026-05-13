from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class WebGuiBrowserSmokeTests(unittest.TestCase):
    def test_web_shell_uses_shield_branding(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")

        self.assertIn('class="brand-shield"', markup)
        self.assertIn("Shielded local-first agent runtime", markup)
        self.assertIn("Aegis Shield Console", markup)
        self.assertIn('class="hero-shield"', markup)
        self.assertIn('class="hero-ascii"', markup)
        self.assertIn("d88888b", markup)
        self.assertIn("tone-10", markup)
        self.assertIn('id="model-auth-method"', markup)
        self.assertIn('id="model-auth-verify-external"', markup)
        self.assertIn('id="model-auth-run-external"', markup)
        self.assertIn('id="model-auth-doctor-run"', markup)
        self.assertIn('id="model-auth-readiness-packet"', markup)
        self.assertIn('id="model-auth-output"', markup)
        self.assertIn('value="oauth_device"', markup)
        self.assertIn('value="github-copilot"', markup)
        self.assertIn('value="google-gemini-oauth"', markup)
        self.assertIn('id="subagent-form"', markup)
        self.assertIn('id="subagent-role"', markup)
        self.assertIn('id="subagent-task"', markup)
        self.assertIn('id="subagent-summary"', markup)
        self.assertIn('id="subagent-output"', markup)
        self.assertIn('id="subagent-cards"', markup)
        self.assertIn('id="model-auth-targets"', markup)
        self.assertIn('id="model-auth-doctor"', markup)
        self.assertIn('<option value="deepseek">DeepSeek</option>', markup)
        self.assertIn('<option value="xai">xAI</option>', markup)
        self.assertIn('<option value="qwen">Qwen</option>', markup)
        self.assertIn("Aegis Control Plane", markup)
        self.assertIn(".brand-shield", styles)
        self.assertIn(".hero-shield", styles)
        self.assertIn(".hero-ascii", styles)
        self.assertIn('"Courier New"', styles)
        self.assertIn("10px 10px 0", styles)
        app_js = Path(__file__).resolve().parents[1].joinpath("src", "aegis", "web", "static", "app.js").read_text(encoding="utf-8")
        self.assertIn("subscription_auth_supported", app_js)
        self.assertIn('api("/models/auth/targets")', app_js)
        self.assertIn('api("/models/auth/doctor")', app_js)
        self.assertIn('api("/models/auth/readiness-packet"', app_js)
        self.assertIn('api("/models/auth/verify-readiness-packet"', app_js)
        self.assertIn("data-model-auth-readiness-packet", app_js)
        self.assertIn("data-model-auth-verify-readiness-packet", app_js)
        self.assertIn("activation_state", app_js)
        self.assertIn("missing_config", app_js)
        self.assertIn('if (method === "api_key")', app_js)
        self.assertIn("payload.verify_external", app_js)
        self.assertIn("payload.run_external", app_js)
        self.assertIn("renderModelAuthOutput", app_js)
        self.assertIn('api("/subagents/status?limit=12")', app_js)
        self.assertIn('api("/subagents/delegate"', app_js)
        self.assertIn('api("/subagents/handoff"', app_js)
        self.assertIn('api("/subagents/run"', app_js)
        self.assertIn('api("/subagents/run-batch"', app_js)
        self.assertIn('api("/subagents/review-packet"', app_js)
        self.assertIn('api("/subagents/verify-packet"', app_js)
        self.assertIn('api("/subagents/autonomy-preflight?limit=12&actor=web-operator"', app_js)
        self.assertIn('id="subagent-autonomy-preflight"', markup)
        self.assertIn('id="subagent-run-batch"', markup)
        self.assertIn("payload.enabled_profile_count", app_js)
        self.assertIn("operator_approved_batch_runtime", app_js)
        self.assertIn('document.getElementById("subagent-form").addEventListener("submit"', app_js)
        self.assertIn('document.getElementById("subagent-autonomy-preflight").addEventListener("click"', app_js)
        self.assertIn('document.getElementById("subagent-run-batch").addEventListener("click"', app_js)
        self.assertIn('document.getElementById("subagent-cards").addEventListener("click"', app_js)
        self.assertIn('data-subagent-approved', app_js)
        self.assertIn('data-subagent-lane', app_js)
        self.assertIn('data-subagent-run', app_js)
        self.assertIn('data-subagent-review-packet', app_js)
        self.assertIn('data-subagent-verify-packet', app_js)
        self.assertIn("card.subagent_runs_recorded", app_js)
        self.assertIn("card.review_packets_recorded", app_js)
        self.assertIn("card.model_ready_review_packet", app_js)
        self.assertIn('setList("subagent-cards"', app_js)
        self.assertIn('name: "subagent_delegate"', app_js)
        self.assertIn('setList("model-auth-targets"', app_js)
        self.assertIn('setList("model-auth-doctor"', app_js)
        self.assertIn('document.getElementById("model-auth-doctor-run").addEventListener("click"', app_js)
        self.assertIn('document.getElementById("model-auth-readiness-packet").addEventListener("click"', app_js)
        self.assertIn('document.getElementById("model-auth-output").addEventListener("click"', app_js)
        self.assertIn('document.getElementById("model-auth-doctor").addEventListener("click"', app_js)
        self.assertIn("modelAuthTargets.targets", app_js)
        self.assertIn("modelAuthDoctorActions", app_js)
        self.assertIn("modelAuthOutputSummary", app_js)
        self.assertIn("data-copy-command", app_js)
        self.assertIn("Web requests never execute interactive provider login", app_js)
        self.assertIn("The web console did not execute provider login.", app_js)
        self.assertIn("--shield:", styles)
        self.assertIn("--shield-glow:", styles)
        self.assertIn(".brand-shield::before", styles)
        self.assertIn("@keyframes shield-pulse", styles)

    def test_web_model_auth_output_renders_terminal_only_command_actions(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        app_js = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js"
        node_script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("const modelAuthDoctorDetail =");
const end = source.indexOf("\n\nconst renderModelUsage =", start);
if (start < 0 || end < 0) {
  throw new Error("model auth render helpers not found");
}
const node = { innerHTML: "" };
const document = { getElementById: (id) => {
  if (id !== "model-auth-output") throw new Error(`unexpected node ${id}`);
  return node;
}};
const escapeHtml = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");
const text = (value) => escapeHtml(Array.isArray(value) ? value.join(", ") : value);
const copyButton = (label, value) =>
  value ? `<button type="button" class="secondary" data-copy-command="${escapeHtml(value)}">${text(label)}</button>` : "";
eval(`${source.slice(start, end)}\nglobalThis.renderModelAuthOutput = renderModelAuthOutput;\nglobalThis.modelAuthDoctorActions = modelAuthDoctorActions;`);
const actions = modelAuthDoctorActions({
  login_command: "PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --subscription --run-external",
  verify_command: "PYTHONPATH=src python3 -m aegis.cli.main model auth login openai --subscription --verify-external",
});
if (!actions.includes("data-copy-command") || !actions.includes("Copy Login") || !actions.includes("Copy Verify")) {
  throw new Error(`copyable doctor actions missing: ${actions}`);
}
renderModelAuthOutput({
  auth_doctor: {
    status: "operator_login_required",
    operator_login_required_count: 2,
    verified_external_auth_count: 0,
    missing_external_commands: ["claude"],
    activation_state_counts: { login_required: 2 },
    next_steps: ["Run the listed login commands from a local terminal."],
  },
});
if (!node.innerHTML.includes("Web requests never execute interactive provider login") || !node.innerHTML.includes("operator_login_required") || !node.innerHTML.includes("Create Readiness Packet")) {
  throw new Error(`doctor summary missing terminal-only readiness content: ${node.innerHTML}`);
}
renderModelAuthOutput({
  auth: {
    provider: "openai",
    method: "subscription",
    status: "external_login_requires_local_terminal",
    external_command: "codex login",
    external_status_command: "codex login status",
    token_capture_supported: false,
  },
});
if (!node.innerHTML.includes("Terminal handoff required") || !node.innerHTML.includes("Copy Login") || !node.innerHTML.includes("Copy Verify") || !node.innerHTML.includes("does not execute interactive provider login")) {
  throw new Error(`external login output missing copyable terminal handoff: ${node.innerHTML}`);
}
"""
        result = subprocess.run((node, "-e", node_script, str(app_js)), capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or result.stdout.strip())

    def test_web_event_stream_parser_handles_chunk_boundaries(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        app_js = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js"
        script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("const parseEventStreamChunk =");
const end = source.indexOf("\n\nconst streamTaskEvents", start);
if (start < 0 || end < 0) {
  throw new Error("parseEventStreamChunk not found");
}
eval(source.slice(start, end).replace("const parseEventStreamChunk =", "var parseEventStreamChunk =") + ";");
const frames = [];
let remaining = parseEventStreamChunk(
  'id: task-1:1\nevent: run_event\ndata: {"task_id":"task-1","sequence":1}\n\n' +
    'id: task-1:2\nevent: task\ndata: {"task_id":"task-1",\n',
  (event, data, id) => frames.push({ event, data, id })
);
if (frames.length !== 1 || frames[0].event !== "run_event" || frames[0].data.sequence !== 1 || frames[0].id !== "task-1:1") {
  throw new Error(`first chunk parsed incorrectly: ${JSON.stringify(frames)}`);
}
remaining = parseEventStreamChunk(
  remaining + 'data: "status":"waiting_approval","progress":{"total_events":2}}\n\n',
  (event, data, id) => frames.push({ event, data, id })
);
if (remaining !== "") {
  throw new Error(`expected empty remainder, got ${JSON.stringify(remaining)}`);
}
if (frames.length !== 2 || frames[1].event !== "task" || frames[1].data.status !== "waiting_approval" || frames[1].data.progress.total_events !== 2) {
  throw new Error(`second chunk parsed incorrectly: ${JSON.stringify(frames)}`);
}
"""
        result = subprocess.run((node, "-e", script, str(app_js)), capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or result.stdout.strip())

    def test_web_slash_palette_matches_tui_fuzzy_submit_flow(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        styles = (root / "styles.css").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="slash-palette"', markup)
        self.assertIn(".slash-palette-row.active", styles)
        self.assertIn("WEB_SLASH_COMMANDS", script)
        self.assertIn('api("/commands")', script)
        self.assertIn("mergeWebSlashCommands", script)
        self.assertIn("privacy-settings", script)
        self.assertIn("setup-bedrock", script)
        self.assertIn("setup-vertex", script)
        self.assertIn("autofix-pr", script)
        self.assertIn("ultraplan", script)
        self.assertIn("ultrareview", script)
        self.assertIn("release-notes", script)
        self.assertIn("chrome", script)
        self.assertIn('taskView: "status"', script)
        self.assertIn('taskView: "events"', script)
        self.assertIn('taskView: "timeline"', script)
        self.assertIn('taskView: "evidence"', script)
        self.assertIn("const selectedTaskId = () =>", script)
        self.assertIn("const slashTaskId = (parsed)", script)
        self.assertIn('parsed.kind === "task-inspection"', script)
        self.assertIn("slashCommandMatches(prefix).slice(0, 8)", script)
        self.assertIn('document.getElementById("slash-palette").addEventListener("click"', script)
        self.assertIn('document.getElementById("task-form").requestSubmit()', script)
        self.assertIn('const request = (parsed.kind === "submit" ? parsed.request : input.value).trim()', script)

        node = shutil.which("node")
        if node is None:
            return
        app_js = root / "app.js"
        node_script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const catalogStart = source.indexOf("const WEB_SLASH_COMMANDS =");
const catalogEnd = source.indexOf("\n\nconst api =", catalogStart);
const helperStart = source.indexOf("const slashCommandTerms =", catalogEnd);
const helperEnd = source.indexOf("\n\nconst renderSlashPalette =", helperStart);
if (catalogStart < 0 || catalogEnd < 0 || helperStart < 0 || helperEnd < 0) {
  throw new Error("slash palette helpers not found");
}
const api = {};
eval(`${source.slice(catalogStart, catalogEnd)}\n${source.slice(helperStart, helperEnd)}\napi.matches = slashCommandMatches;\napi.parse = parseTaskSlashCommand;\napi.merge = mergeWebSlashCommands;\napi.commands = () => webSlashCommands;`);
const su = api.matches("su").map((entry) => entry.command);
if (su[0] !== "submit" || !su.includes("resume") || su.includes("settings")) {
  throw new Error(`/su fuzzy matches are wrong: ${JSON.stringify(su)}`);
}
const parsed = api.parse("/q inspect the failing test");
if (parsed.kind !== "submit" || parsed.command !== "background" || parsed.request !== "inspect the failing test") {
  throw new Error(`queue alias parsed incorrectly: ${JSON.stringify(parsed)}`);
}
const nav = api.parse("/models");
if (nav.kind !== "section" || nav.section !== "models") {
  throw new Error(`models navigation parsed incorrectly: ${JSON.stringify(nav)}`);
}
const status = api.parse("/status task-123");
if (status.kind !== "task-inspection" || status.taskView !== "status" || status.request !== "task-123") {
  throw new Error(`status task command parsed incorrectly: ${JSON.stringify(status)}`);
}
const events = api.matches("ev").map((entry) => entry.command);
if (!events.includes("events")) {
  throw new Error(`/events command did not fuzzy match: ${JSON.stringify(events)}`);
}
const timeline = api.matches("timeline").map((entry) => entry.command);
if (!timeline.includes("timeline")) {
  throw new Error(`/timeline command did not resolve: ${JSON.stringify(timeline)}`);
}
const audit = api.parse("/audit task-456");
if (audit.kind !== "task-inspection" || audit.taskView !== "evidence" || audit.command !== "evidence") {
  throw new Error(`/audit alias did not resolve to task evidence: ${JSON.stringify(audit)}`);
}
const privacy = api.matches("privacy").map((entry) => entry.command);
if (!privacy.includes("approvals")) {
  throw new Error(`/privacy-settings alias did not resolve to approvals: ${JSON.stringify(privacy)}`);
}
const setup = api.matches("setup").map((entry) => entry.command);
if (!setup.includes("models")) {
  throw new Error(`/setup-* aliases did not resolve to models: ${JSON.stringify(setup)}`);
}
const chrome = api.matches("chrome").map((entry) => entry.command);
if (!chrome.includes("browser")) {
  throw new Error(`/chrome alias did not resolve to browser: ${JSON.stringify(chrome)}`);
}
const ultra = api.matches("ultra").map((entry) => entry.command);
if (!ultra.includes("commands")) {
  throw new Error(`/ultra* aliases did not resolve to commands: ${JSON.stringify(ultra)}`);
}
const release = api.matches("release").map((entry) => entry.command);
if (!release.includes("settings")) {
  throw new Error(`/release-notes alias did not resolve to settings: ${JSON.stringify(release)}`);
}
api.merge([
  { command: "debug", label: "/debug", detail: "TUI diagnostics", kind: "palette", source: "tui" },
  { command: "submit", label: "/submit duplicate", detail: "duplicate should be ignored", kind: "palette" },
  { command: "aegis-project-summary", label: "/aegis-project-summary", detail: "Skill command", kind: "palette", source: "skill" },
]);
const debug = api.parse("/debug");
if (debug.kind !== "palette" || debug.command !== "debug") {
  throw new Error(`/debug catalog command parsed incorrectly: ${JSON.stringify(debug)}`);
}
const skill = api.matches("aegis-project").map((entry) => entry.command);
if (!skill.includes("aegis-project-summary")) {
  throw new Error(`dynamic skill slash command missing: ${JSON.stringify(skill)}`);
}
const submitCount = api.commands().filter((entry) => entry.command === "submit").length;
if (submitCount !== 1) {
  throw new Error(`core submit command duplicated: ${submitCount}`);
}
"""
        result = subprocess.run((node, "-e", node_script, str(app_js)), capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or result.stdout.strip())

    def test_web_task_inspection_slash_commands_call_task_loaders(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        app_js = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js"
        node_script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("const selectedTaskId =");
const end = source.indexOf("\n\nconst renderBrowserOutput =", start);
if (start < 0 || end < 0) {
  throw new Error("task inspection slash dispatcher not found");
}
const calls = [];
const state = { lastTask: { id: "latest-task" }, activeSection: "security" };
const applySectionVisibility = () => calls.push(["section", state.activeSection]);
const loadTaskStatus = async (taskId) => calls.push(["status", taskId, state.activeSection]);
const loadTaskEvents = async (taskId) => calls.push(["events", taskId, state.activeSection]);
const loadTaskTimeline = async (taskId) => calls.push(["timeline", taskId, state.activeSection]);
const loadTaskEvidence = async (taskId) => calls.push(["evidence", taskId, state.activeSection]);
const renderTaskNotice = (title, detail) => calls.push(["notice", title, detail, state.activeSection]);
const renderTaskError = (message) => calls.push(["error", message]);
const resumeTask = async (taskId) => calls.push(["resume", taskId]);
eval(`${source.slice(start, end)}\nglobalThis.executeLocalSlashCommand = executeLocalSlashCommand;`);
(async () => {
  await executeLocalSlashCommand({ kind: "task-inspection", command: "status", taskView: "status", request: "task-1" });
  await executeLocalSlashCommand({ kind: "task-inspection", command: "events", taskView: "events", request: "" });
  await executeLocalSlashCommand({ kind: "task-inspection", command: "timeline", taskView: "timeline", request: "task-3 extra" });
  await executeLocalSlashCommand({ kind: "task-inspection", command: "evidence", taskView: "evidence", request: "task-4" });
  state.lastTask = null;
  state.lastEvents = null;
  state.lastEvidence = null;
  await executeLocalSlashCommand({ kind: "task-inspection", command: "status", label: "/status [task_id]", taskView: "status", request: "" });
  const expected = [
    ["section", "activity"],
    ["status", "task-1", "activity"],
    ["events", "latest-task", "activity"],
    ["timeline", "task-3", "activity"],
    ["evidence", "task-4", "activity"],
    ["section", "activity"],
    ["notice", "/status [task_id]", "Open a task or include a task id, then run this command again.", "activity"],
  ];
  if (JSON.stringify(calls) !== JSON.stringify(expected)) {
    throw new Error(`unexpected task inspection dispatch: ${JSON.stringify(calls)}`);
  }
})().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
"""
        result = subprocess.run((node, "-e", node_script, str(app_js)), capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or result.stdout.strip())

    def test_web_event_renderer_shows_status_frames_without_events(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        app_js = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js"
        script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("const renderTaskEvents =");
const end = source.indexOf("\n\nconst appendTaskEvent", start);
if (start < 0 || end < 0) {
  throw new Error("renderTaskEvents not found");
}
const state = {};
const text = (value) => String(value ?? "");
const taskSessionLabel = () => "task-1";
const taskSessionActions = () => "";
const shortId = (value) => String(value || "").slice(0, 8);
const empty = (message) => ({ empty: message });
const created = [];
const node = {
  children: [],
  replaceChildren(...items) {
    this.children = items;
  },
};
const document = {
  getElementById(id) {
    if (id !== "task-events") throw new Error(`unexpected node ${id}`);
    return node;
  },
  createElement(tag) {
    const element = { tag, className: "", innerHTML: "", textContent: "" };
    created.push(element);
    return element;
  },
};
eval(source.slice(start, end).replace("const renderTaskEvents =", "var renderTaskEvents =") + ";");
renderTaskEvents({ task_id: "task-1", status: "waiting_approval", progress: { total_events: 0, waiting_steps: 1 } });
if (node.children.length === 1 && node.children[0].empty) {
  throw new Error("status-only frame rendered as empty state");
}
const html = node.children.map((item) => item.innerHTML || item.textContent || "").join("\n");
if (!html.includes("waiting_approval") || !html.includes("Progress Metrics") || !html.includes("0 events")) {
  throw new Error(`status-only progress not rendered: ${html}`);
}
"""
        result = subprocess.run((node, "-e", script, str(app_js)), capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or result.stdout.strip())

    def test_web_browser_renderer_exposes_interactive_artifacts_and_approval_replay(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        app_js = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js"
        script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("const renderBrowserOutput =");
const end = source.indexOf("\n\nconst renderToolRunOutput", start);
if (start < 0 || end < 0) {
  throw new Error("renderBrowserOutput not found");
}
const state = { pendingBrowserAction: { operation: "click" } };
const text = (value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
const escapeHtml = text;
const node = { innerHTML: "" };
const document = {
  getElementById(id) {
    if (id !== "browser-output") throw new Error(`unexpected node ${id}`);
    return node;
  },
};
eval(source.slice(start, end).replace("const renderBrowserOutput =", "var renderBrowserOutput =") + ";");
renderBrowserOutput({
  status: "approval_required",
  approval_id: "approval-123",
  artifact_url: "/browser-artifacts/snapshot.png",
  metadata_url: "/browser-artifacts/snapshot.json",
  packet: { packet_schema: "aegis.browser.live_activation_packet.v1", packet_id: "packet-123" },
  receipt: { receipt_schema: "aegis.browser.live_activation_packet.v1", packet_id: "packet-123" },
  session: {
    interactive_elements: [
      { tag: "a", label: "Docs", selector_hint: "#docs", supported_virtual_actions: ["navigate"] },
      { tag: "button", label: "Save", selector_hint: "#save" },
      { tag: "input", label: "Email", form_hint: "input[name=email]" },
    ],
  },
});
if (state.pendingBrowserAction.approval_id !== "approval-123") {
  throw new Error("approval id was not stored for replay");
}
for (const expected of ["Open Snapshot", "Open Metadata", "Create Live Activation Packet", "Verify Activation Packet", 'data-browser-live-activation-packet="1"', 'data-browser-verify-activation-packet="packet-123"', 'data-browser-selector="#docs"', '"navigate"', 'data-browser-selector="#save"', 'data-browser-label="Save"', 'data-browser-run-approved="approval-123"']) {
  if (!node.innerHTML.includes(expected)) {
    throw new Error(`missing browser renderer output ${expected}: ${node.innerHTML}`);
  }
}
"""
        result = subprocess.run((node, "-e", script, str(app_js)), capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or result.stdout.strip())

    def test_web_tool_renderer_exposes_artifact_and_approval_replay(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        app_js = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js"
        script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("const renderToolRunOutput =");
const end = source.indexOf("\n\nconst installToolRunPresets", start);
if (start < 0 || end < 0) {
  throw new Error("renderToolRunOutput not found");
}
const state = { pendingToolRun: { name: "email_draft" } };
const text = (value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
const escapeHtml = text;
const node = { innerHTML: "" };
const document = {
  getElementById(id) {
    if (id !== "tool-run-output") throw new Error(`unexpected node ${id}`);
    return node;
  },
};
eval(source.slice(start, end).replace("const renderToolRunOutput =", "var renderToolRunOutput =") + ";");
renderToolRunOutput({
  status: "approval_required",
  approval_id: "tool-approval-123",
  artifact_url: "/tool-artifacts/result.txt",
  metadata_url: "/tool-artifacts/result.metadata.json",
});
if (state.pendingToolRun.approval_id !== "tool-approval-123") {
  throw new Error("tool approval id was not stored for replay");
}
for (const expected of ["Open Artifact", 'href="/tool-artifacts/result.txt"', "Open Metadata", 'href="/tool-artifacts/result.metadata.json"', 'data-tool-run-approved="tool-approval-123"']) {
  if (!node.innerHTML.includes(expected)) {
    throw new Error(`missing tool renderer output ${expected}: ${node.innerHTML}`);
  }
}
"""
        result = subprocess.run((node, "-e", script, str(app_js)), capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or result.stdout.strip())

    def test_web_approval_detail_collects_actor_reason_and_admin_decision(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not installed")
        app_js = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js"
        script = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const start = source.indexOf("const approvalDecisionPayload =");
const end = source.indexOf("\n\nconst renderMemories", start);
if (start < 0 || end < 0) {
  throw new Error("approval detail renderer not found");
}
const state = {};
const text = (value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
const escapeHtml = text;
const shortId = (value) => String(value || "").slice(0, 8);
const approvalSessionLabel = (approval) => approval?.session_id || "none";
const controls = {
  "approval-actor": { value: "security-admin" },
  "approval-reason": { value: "Reviewed live write scope." },
  "approval-admin": { checked: true },
};
const detailNode = { children: [], replaceChildren(...items) { this.children = items; } };
const document = {
  getElementById(id) {
    if (id === "approval-detail") return detailNode;
    return controls[id] || null;
  },
  createElement(tag) {
    return { tag, className: "", innerHTML: "" };
  },
};
eval(
  source
    .slice(start, end)
    .replace("const approvalDecisionPayload =", "var approvalDecisionPayload =")
    .replace("const renderApprovalDetail =", "var renderApprovalDetail =") + ";"
);
renderApprovalDetail({
  id: "approval-12345678",
  status: "pending",
  reason: "live write requires approval",
  risk_level: "high",
  task_id: "task-12345678",
  session_id: "session-12345678",
  payload: { step: { operation: "send_email", connector: "smtp" } },
});
if (detailNode.children.length !== 1) {
  throw new Error("approval detail did not render one card");
}
const html = detailNode.children[0].innerHTML;
for (const expected of ['id="approval-actor"', 'id="approval-reason"', 'id="approval-admin"', 'data-approve="approval-12345678"', 'data-deny="approval-12345678"']) {
  if (!html.includes(expected)) {
    throw new Error(`missing approval detail output ${expected}: ${html}`);
  }
}
const payload = approvalDecisionPayload();
if (payload.actor !== "security-admin" || payload.reason !== "Reviewed live write scope." || payload.admin !== true) {
  throw new Error(`decision payload did not preserve operator inputs: ${JSON.stringify(payload)}`);
}
"""
        result = subprocess.run((node, "-e", script, str(app_js)), capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr.strip() or result.stdout.strip())

    def test_web_approval_panel_exposes_recent_decision_history(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="approval-decisions"', markup)
        self.assertIn("Recent Decisions", markup)
        self.assertIn("deniedApprovals", script)
        self.assertIn('api("/approvals?status=denied&limit=8")', script)
        self.assertIn('api("/approvals?status=approved&limit=8")', script)
        self.assertIn('setList("approval-decisions"', script)
        self.assertIn("const recentDecisions = [...(approvedApprovals.approvals || []), ...(deniedApprovals.approvals || [])]", script)
        self.assertIn(".sort((left, right) => String(right.updated_at || right.created_at || \"\").localeCompare(String(left.updated_at || left.created_at || \"\")))", script)
        self.assertIn("meta: approvalDecisionMeta(x)", script)
        self.assertIn('document.getElementById("approval-decisions").addEventListener("click"', script)
        self.assertIn("const approvalDecisionMeta = (approval) => {", script)
        self.assertIn('decision.admin ? " · admin" : ""', script)

    def test_web_resume_uses_original_task_session_context(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn("const existingTask = await api(`/tasks/${encodeURIComponent(taskId)}`);", script)
        self.assertIn("const resumeSessionId = existingTask.session_id || state.activeSessionId || undefined;", script)
        self.assertIn("state.activeSessionId = existingTask.session_id;", script)
        self.assertIn("body: JSON.stringify({ session_id: resumeSessionId })", script)
        self.assertIn("const cancelTask = async (taskId) => {", script)
        self.assertIn("const cancelSessionId = existingTask.session_id || state.activeSessionId || undefined;", script)
        self.assertIn("api(`/tasks/${encodeURIComponent(taskId)}/cancel`,", script)
        self.assertIn('reason: "Cancelled from web console"', script)
        self.assertIn("data-task-cancel", script)
        self.assertIn("const pauseTask = async (taskId) => {", script)
        self.assertIn("const pauseSessionId = existingTask.session_id || state.activeSessionId || undefined;", script)
        self.assertIn("api(`/tasks/${encodeURIComponent(taskId)}/pause`,", script)
        self.assertIn('reason: "Paused from web console"', script)
        self.assertIn("data-task-pause", script)
        self.assertIn("const since = state.runEventCursors[taskId] || 0;", script)
        self.assertIn("const existingEvents = since && state.lastEvents?.task_id === taskId ? (state.lastEvents.events || []) : [];", script)
        self.assertIn("state.lastEvents = { ...data, events: existingEvents };", script)
        self.assertIn("renderTaskEvents(state.lastEvents);", script)
        self.assertIn("progress: data.progress || state.lastEvents?.progress || {}", script)
        self.assertIn("const stepGroups = payload.step_groups || [];", script)
        self.assertIn("const providerSubsteps = payload.provider_substeps || [];", script)
        self.assertIn("const progress = payload.progress || {};", script)
        self.assertIn("Progress Metrics", script)
        self.assertIn("Provider Substeps", script)
        self.assertIn("run-event step-group", script)
        self.assertIn("Event Log", script)
        self.assertIn("const taskSessionLabel = (task) => {", script)
        self.assertIn("session ${taskSessionLabel(x)}", script)
        self.assertIn("<div><dt>Session</dt><dd>${text(taskSessionLabel(task))}</dd></div>", script)
        self.assertIn("const openSession = async (sessionId) => {", script)
        self.assertIn('data-task-session="${escapeHtml(task.session_id)}"', script)
        self.assertIn("await openSession(sessionId);", script)
        self.assertIn("const sessionLabel = taskSessionLabel(payload);", script)
        self.assertIn("const taskSessionActions = (payload) => {", script)
        self.assertIn("Array.isArray(payload?.action_hints) ? payload.action_hints : []", script)
        self.assertIn('hint?.action === "session_show"', script)
        self.assertIn('hint?.action === "session_history"', script)
        self.assertIn("<div><dt>Session</dt><dd>${text(sessionLabel)}</dd></div>", script)
        self.assertIn("const sessionLabel = taskSessionLabel(timeline);", script)
        self.assertIn("Timeline Context", script)
        self.assertIn('document.getElementById("task-events").addEventListener("click"', script)
        self.assertIn('document.getElementById("task-timeline").addEventListener("click"', script)
        self.assertIn("const approvalSessionLabel = (approval) => {", script)
        self.assertIn("session ${approvalSessionLabel(x)}", script)
        self.assertIn("runtime approval · session ${approvalSessionLabel(x)}", script)
        self.assertIn("<div><dt>Session</dt><dd>${text(approvalSessionLabel(approval))}</dd></div>", script)
        self.assertIn('data-approval-session="${escapeHtml(x.session_id)}"', script)
        self.assertIn('data-approval-session="${escapeHtml(approval.session_id)}"', script)
        self.assertIn("event.target.dataset.approvalSession", script)
        self.assertIn("const sessionMessageMeta = (message) => {", script)
        self.assertIn("const sessionMessageActions = (message) => {", script)
        self.assertIn("message?.current_task_status", script)
        self.assertIn("message?.current_approval_status", script)
        self.assertIn("Array.isArray(message?.action_hints) ? message.action_hints : []", script)
        self.assertIn('hint?.action === "task_status"', script)
        self.assertIn('hint?.action === "task_resume"', script)
        self.assertIn('hint?.action === "approval_review"', script)
        self.assertIn('hint?.action === "approval_approve"', script)
        self.assertIn('hint?.action === "approval_deny"', script)
        self.assertIn("metadata.checkpoint_approval_id ? `approval ${shortId(metadata.checkpoint_approval_id)}` : \"\"", script)
        self.assertIn('<div class="message-meta">${meta.map((item) => `<span>${text(item)}</span>`).join("")}</div>', script)
        self.assertIn('data-transcript-task-status="${encodedTask}"', script)
        self.assertIn('data-transcript-task-resume="${encodedTaskResume}"', script)
        self.assertIn('data-transcript-approval-review="${encodedApproval}"', script)
        self.assertIn('data-transcript-approval-approve="${encodedApprovalApprove}"', script)
        self.assertIn('data-transcript-approval-deny="${encodedApprovalDeny}"', script)
        self.assertIn('document.getElementById("session-transcript").addEventListener("click"', script)
        self.assertIn("event.target.dataset.transcriptTaskTimeline", script)
        self.assertIn("event.target.dataset.transcriptTaskResume", script)
        self.assertIn("event.target.dataset.transcriptApprovalReview", script)
        self.assertIn("event.target.dataset.transcriptApprovalApprove", script)
        self.assertIn("event.target.dataset.transcriptApprovalDeny", script)

    def test_web_recent_tasks_can_toggle_between_session_and_all_tasks(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('data-task-scope="session"', markup)
        self.assertIn('data-task-scope="all"', markup)
        self.assertIn('id="tasks-session-label"', markup)
        self.assertIn('id="active-work"', markup)
        self.assertIn('id="session-linked-tasks"', markup)
        self.assertIn('id="session-compact-keep" type="number" min="0"', markup)
        self.assertIn('taskScope: "session"', script)
        self.assertIn("inspectedTaskSessionId: null", script)
        self.assertIn("const taskSessionId = state.inspectedTaskSessionId || state.activeSessionId;", script)
        self.assertIn("taskSessionLabel(x)", script)
        self.assertIn("runtime.active_work_count", script)
        self.assertIn("dashboard.active_work_tasks || []", script)
        self.assertIn('setList("active-work"', script)
        self.assertIn("dashboard.recent_session_tasks || []", script)
        self.assertIn('setList("session-linked-tasks"', script)
        self.assertIn("task.session.title", script)
        self.assertIn('taskSessionId && state.taskScope === "session"', script)
        self.assertIn("state.inspectedTaskSessionId = taskSession;", script)
        self.assertIn("data-session-tasks", script)
        self.assertIn("${x.message_count || 0} msgs", script)
        self.assertIn("${x.task_count || 0} tasks", script)
        self.assertIn("x.latest_task ? `latest ${shortId(x.latest_task.id)} · ${x.latest_task.status}` : x.updated_at", script)
        self.assertIn("state.inspectedTaskSessionId = null;", script)
        self.assertIn('document.querySelectorAll("[data-task-scope]")', script)
        self.assertIn("state.taskScope = button.dataset.taskScope;", script)

    def test_web_connector_panel_surfaces_policy_metadata(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn("const connectorPolicyMeta = (connector) => {", script)
        self.assertIn("connector.risk_by_operation", script)
        self.assertIn("connector.operation_scopes", script)
        self.assertIn("connector.required_scopes", script)
        self.assertIn("connector.optional_scopes", script)
        self.assertIn("connector.data_sensitivity", script)
        self.assertIn("meta: connectorPolicyMeta(x)", script)

    def test_web_competitive_targets_surface_security_delta_and_live_gap(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn('setList("competitor-targets"', script)
        self.assertIn("Security: ${x.security_delta}", script)
        self.assertIn("Live gap: ${x.live_gap}", script)

    def test_web_implementation_readiness_surfaces_sample_tools(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('setFeatureGrid("implementation-readiness"', script)
        self.assertIn("x.sample_tools?.length", script)
        self.assertIn("Sample tools: ${x.sample_tools.slice(0, 6).join(\", \")}", script)
        self.assertIn('id="live-gap-backlog"', markup)
        self.assertIn("Live Gap Backlog", markup)
        self.assertIn('setList("live-gap-backlog"', script)
        self.assertIn("dashboard.live_gap_backlog || []", script)
        self.assertIn("x.area", script)
        self.assertIn("x.status", script)
        self.assertIn("x.required_controls", script)
        self.assertIn("x.verification_gates", script)
        self.assertIn("backendActivationSummary", script)
        self.assertIn("backendBlockerSummary", script)
        self.assertIn("preflight_status", script)
        self.assertIn("Blockers:", script)
        self.assertIn("x.next_steps", script)
        self.assertIn("x.live_read_surfaces", script)
        self.assertIn("x.target_provider_count", script)
        self.assertIn("x.subscription_bridge_targets", script)
        self.assertIn("x.not_started_targets", script)
        self.assertIn("Provider targets:", script)
        self.assertIn("Auth bridges:", script)
        self.assertIn("x.implemented_live_adapters", script)
        self.assertIn("x.available_live_adapters", script)
        self.assertIn("x.operator_checklist", script)
        self.assertIn("Readiness checklist:", script)
        self.assertIn("x.implemented_backend_adapters", script)
        self.assertIn("x.available_backend_adapters", script)
        self.assertIn("x.implemented_hardening_controls", script)
        self.assertIn("x.remaining_depth_work", script)
        self.assertIn("Hardened:", script)
        self.assertIn("Remaining depth:", script)
        self.assertIn("x.evaluation_scenarios", script)
        self.assertIn("Evaluations:", script)
        self.assertIn("/evaluation/readiness?limit=20&include_live_gaps=1", script)
        self.assertIn("x.live_gap_backlog || []", script)
        self.assertIn('id="policy-promote-live-parity"', markup)
        self.assertIn('id="policy-promote-defer-live-gap"', markup)
        self.assertIn('id="policy-promote-deferral-reason"', markup)
        self.assertIn("require_live_parity", script)
        self.assertIn("deferred_live_gap_areas", script)
        self.assertIn("live_gap_deferral_reason", script)

    def test_web_can_append_non_submitting_session_context_with_trust_label(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="session-message-form"', markup)
        self.assertIn('id="session-message-trust"', markup)
        self.assertIn('<option value="CHAT_CONTENT">Chat content</option>', markup)
        self.assertIn('document.getElementById("session-message-form").addEventListener("submit"', script)
        self.assertIn("submit: false", script)
        self.assertIn('trust_class: document.getElementById("session-message-trust").value', script)

    def test_web_tool_runner_has_presets_for_live_capable_tools(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="tool-run-presets"', markup)
        self.assertIn('id="mcp-server-transport"', markup)
        self.assertIn('id="mcp-server-token-secret"', markup)
        self.assertIn('value="streamable-http"', markup)
        self.assertIn("TOOL_RUN_PRESETS", script)
        self.assertIn('name: "message_send"', script)
        self.assertIn('transport: document.getElementById("mcp-server-transport").value', script)
        self.assertIn('token_secret: document.getElementById("mcp-server-token-secret").value || undefined', script)
        self.assertIn('x.metadata?.transport || "stdio"', script)
        self.assertIn('name: "service_ticket_read"', script)
        self.assertIn('name: "github_issue"', script)
        self.assertIn('name: "gitlab_issue"', script)
        self.assertIn("payload.artifact_url", script)
        self.assertIn("Open Artifact", script)
        self.assertIn("payload.metadata_url", script)
        self.assertIn("Open Metadata", script)
        self.assertIn("interactive_elements", script)
        self.assertIn("payload.metadata_url", script)
        self.assertIn("Open Snapshot", script)
        self.assertIn("Open Metadata", script)
        self.assertIn("payload.evidence_url", script)
        self.assertIn("Open Evidence", script)
        self.assertIn("/browser/inspect", script)
        self.assertIn("browser-inspect", markup)
        self.assertIn("/browser/live-navigate", script)
        self.assertIn("browser-live-navigate", markup)
        self.assertIn("/browser/render-screenshot", script)
        self.assertIn("browser-render-screenshot", markup)
        self.assertIn("/browser/live-screenshot", script)
        self.assertIn("browser-live-screenshot", markup)
        self.assertIn('data-browser-live-activation-packet="1"', script)
        self.assertIn("Create Live Activation Packet", script)
        self.assertIn("data-browser-verify-activation-packet", script)
        self.assertIn("Verify Activation Packet", script)
        self.assertIn('api("/browser/live-activation-packet"', script)
        self.assertIn('api("/browser/verify-activation-packet"', script)
        self.assertIn('body: JSON.stringify({ actor: "web-operator" })', script)
        self.assertIn('body: JSON.stringify({ packet: activationPacket, actor: "web-operator" })', script)
        self.assertIn("data-browser-selector", script)
        self.assertIn('document.getElementById("browser-selector").value = selector', script)
        self.assertIn('document.getElementById("browser-fill-fields").value = JSON.stringify({ [selector]: "" }, null, 2)', script)
        self.assertIn('button.dataset.toolPreset = preset.name', script)
        self.assertIn('document.getElementById("tool-run-name").value = preset.name', script)
        self.assertIn('document.getElementById("tool-run-params").value = JSON.stringify(preset.params, null, 2)', script)

    def test_web_models_panel_renders_usage_breakdowns(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="model-usage-providers"', markup)
        self.assertIn('id="model-usage-models"', markup)
        self.assertIn('id="model-usage-events"', markup)
        self.assertIn('value="minimax-token-plan"', markup)
        self.assertIn('api("/model-usage")', script)
        self.assertIn("const renderModelUsage = (payload) => {", script)
        self.assertIn('setList("model-usage-providers", payload.by_provider', script)
        self.assertIn('setList("model-usage-models", payload.by_model', script)
        self.assertIn('setList("model-usage-events", payload.recent_events', script)
        self.assertIn("renderModelUsage(modelUsage)", script)

    def test_web_skills_panel_exposes_installed_skill_inventory(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="installed-skills"', markup)
        self.assertIn('api("/skills")', script)
        self.assertIn('setList("installed-skills"', script)
        self.assertIn("permissions_summary", script)
        self.assertIn("sandbox_profile", script)
        self.assertIn("data-skill-disable", script)
        self.assertIn("data-skill-enable", script)
        self.assertIn('document.getElementById("installed-skills").addEventListener("click"', script)
        self.assertIn('const action = disableId ? "disable" : "enable";', script)
        self.assertIn("pendingSkillEnable", script)
        self.assertIn("const syncPendingSkillEnableApprovals = (approvals) =>", script)
        self.assertIn('payload.kind === "skill_enable"', script)
        self.assertIn("state.pendingSkillEnable = next", script)
        self.assertIn('api("/approvals?status=approved&limit=8")', script)
        self.assertIn("syncPendingSkillEnableApprovals([...(approvedApprovals.approvals || []), ...(approvals.approvals || [])])", script)
        self.assertIn("${pendingApprovalStatus} enable approval", script)
        self.assertIn('pendingApprovalId ? "Replay Enable" : "Enable"', script)
        self.assertIn('tone: x.enabled ? "ready" : pendingApprovalId ? "attention" : ""', script)
        self.assertIn("body.approval_id = state.pendingSkillEnable[skillId].id || state.pendingSkillEnable[skillId]", script)
        self.assertIn('state.pendingSkillEnable[skillId] = { id: result.approval_id, status: "pending" }', script)
        self.assertIn('result.status === "approval_required"', script)
        self.assertIn('api(`/skills/${encodeURIComponent(skillId)}/${action}`', script)
        self.assertNotIn("x.manifest", script)
        self.assertNotIn("x.source", script)
        self.assertNotIn("x.commands", script)
        self.assertNotIn("x.secrets", script)

    def test_web_plugins_panel_exposes_governed_local_lifecycle(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="plugin-install-form"', markup)
        self.assertIn('id="plugin-manifest-path"', markup)
        self.assertIn('id="plugin-install-enable"', markup)
        self.assertIn('id="plugin-install-unsigned"', markup)
        self.assertIn('id="plugin-reload"', markup)
        self.assertIn('id="plugin-marketplace-form"', markup)
        self.assertIn('id="plugin-marketplace-query"', markup)
        self.assertIn('id="plugin-marketplace-catalog"', markup)
        self.assertIn('id="plugin-prepared-update-form"', markup)
        self.assertIn('id="plugin-prepared-candidate-id"', markup)
        self.assertIn('id="plugin-prepared-update-approved"', markup)
        self.assertIn('id="plugin-prepared-update-enable"', markup)
        self.assertIn('id="plugin-prepared-update-disable"', markup)
        self.assertIn('id="installed-plugins"', markup)
        self.assertIn('id="plugin-marketplace"', markup)
        self.assertIn('id="plugin-updates"', markup)
        self.assertIn('id="plugin-output"', markup)
        self.assertIn('api("/plugins")', script)
        self.assertIn('api("/plugins/reload"', script)
        self.assertIn("/plugins/marketplace?q=", script)
        self.assertIn("/plugins/updates", script)
        self.assertIn('api("/plugins/marketplace/fetch-manifest"', script)
        self.assertIn('api("/plugins/marketplace/install"', script)
        self.assertIn('api("/plugins/marketplace/prepare-update"', script)
        self.assertIn('api("/plugins/marketplace/apply-prepared-update"', script)
        self.assertIn('api("/plugins/marketplace/fetch-bundle"', script)
        self.assertIn('api("/plugins/marketplace/install-bundle"', script)
        self.assertIn('api("/plugins/marketplace/update"', script)
        self.assertIn("approved: true", script)
        self.assertIn('setList("installed-plugins"', script)
        self.assertIn('setList("plugin-marketplace"', script)
        self.assertIn('setList("plugin-updates"', script)
        self.assertIn("data-plugin-enable", script)
        self.assertIn("data-plugin-disable", script)
        self.assertIn("data-plugin-remove", script)
        self.assertIn("data-plugin-marketplace-install", script)
        self.assertIn("data-plugin-marketplace-fetch-manifest", script)
        self.assertIn("data-plugin-marketplace-fetch-bundle", script)
        self.assertIn("data-plugin-marketplace-install-bundle", script)
        self.assertIn("data-plugin-marketplace-prepare-update", script)
        self.assertIn("data-plugin-marketplace-update", script)
        self.assertIn("pluginPreparedUpdateCandidateId", script)
        self.assertIn("payload.candidate_id", script)
        self.assertIn('document.getElementById("plugin-install-form").addEventListener("submit"', script)
        self.assertIn('document.getElementById("plugin-marketplace-form").addEventListener("submit"', script)
        self.assertIn('document.getElementById("plugin-prepared-update-form").addEventListener("submit"', script)
        self.assertIn('document.getElementById("plugin-marketplace").addEventListener("click"', script)
        self.assertIn('document.getElementById("plugin-updates").addEventListener("click"', script)
        self.assertIn('document.getElementById("installed-plugins").addEventListener("click"', script)
        self.assertIn('api(`/plugins/${encodeURIComponent(pluginId)}/${action}`', script)
        self.assertIn("renderPluginOutput", script)
        self.assertNotIn("x.manifest", script)
        self.assertNotIn("x.commands", script)
        self.assertNotIn("x.secrets", script)

    def test_web_remote_control_panel_exposes_scoped_pairing_lifecycle(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="remote-control-form"', markup)
        self.assertIn('id="remote-control-label"', markup)
        self.assertIn('id="remote-control-session-id"', markup)
        self.assertIn('id="remote-control-task-id"', markup)
        self.assertIn('id="remote-control-actions"', markup)
        self.assertIn('id="remote-control-ttl"', markup)
        self.assertIn('id="remote-control-relay-form"', markup)
        self.assertIn('id="remote-control-relay-url"', markup)
        self.assertIn('id="remote-control-relay-pairing-id"', markup)
        self.assertIn('id="remote-control-relay-secret"', markup)
        self.assertIn('id="remote-control-relay-event"', markup)
        self.assertIn('id="remote-control-relay-task-id"', markup)
        self.assertIn('id="remote-control-relay-outbox-id"', markup)
        self.assertIn('id="remote-control-push-target-id"', markup)
        self.assertIn('id="remote-control-push-label"', markup)
        self.assertIn('id="remote-control-push-provider"', markup)
        self.assertIn('id="remote-control-push-secret"', markup)
        self.assertIn('id="remote-control-device-secret"', markup)
        self.assertIn('id="remote-control-apns-topic"', markup)
        self.assertIn('id="remote-control-fcm-project"', markup)
        self.assertIn('id="remote-control-relay-approved"', markup)
        self.assertIn('id="remote-control-push-approved"', markup)
        self.assertIn('id="remote-control-relay-dry-run"', markup)
        self.assertIn('id="remote-control-relay-check"', markup)
        self.assertIn('id="remote-control-directory"', markup)
        self.assertIn('id="remote-control-relay-directory"', markup)
        self.assertIn('id="remote-control-relay-notify"', markup)
        self.assertIn('id="remote-control-push-register"', markup)
        self.assertIn('id="remote-control-push-rotate"', markup)
        self.assertIn('id="remote-control-push-disable"', markup)
        self.assertIn('id="remote-control-native-push"', markup)
        self.assertIn('id="remote-control-relay-outbox-refresh"', markup)
        self.assertIn('id="remote-control-relay-retry"', markup)
        self.assertIn('id="remote-control-relay-confirm"', markup)
        self.assertIn('id="remote-control-relay-preview"', markup)
        self.assertIn('id="remote-control-relay-apply"', markup)
        self.assertIn('id="remote-control-relay-summary"', markup)
        self.assertIn('id="remote-control-relay"', markup)
        self.assertIn('id="remote-control-relay-outbox"', markup)
        self.assertIn('id="remote-control-push-targets"', markup)
        self.assertIn('id="remote-control-pairings"', markup)
        self.assertIn('id="remote-control-output"', markup)
        self.assertIn('api("/remote-control/status")', script)
        self.assertIn('api("/remote-control/relay")', script)
        self.assertIn('api("/remote-control/relay/outbox")', script)
        self.assertIn('api("/remote-control/relay/directory"', script)
        self.assertIn('api("/remote-control/relay/notify"', script)
        self.assertIn('api("/remote-control/relay/confirm"', script)
        self.assertIn('api("/remote-control/push/register"', script)
        self.assertIn('api("/remote-control/push/rotate"', script)
        self.assertIn('api("/remote-control/push/disable"', script)
        self.assertIn('api("/remote-control/push"', script)
        self.assertIn('api("/remote-control/relay/retry"', script)
        self.assertIn('api("/remote-control/relay/pull"', script)
        self.assertIn('api(`/remote-control/directory?pairing_id=${encodeURIComponent', script)
        self.assertIn('api(`/remote-control/relay${relayUrl', script)
        self.assertIn("relay_auth_secret", script)
        self.assertIn("remoteControlRelayBody", script)
        self.assertIn("renderRemoteControlRelayPull", script)
        self.assertIn("pullRemoteControlRelayActions", script)
        self.assertIn("remote-control-relay-event", script)
        self.assertIn("remote-control-relay-task-id", script)
        self.assertIn("remote-control-relay-outbox-id", script)
        self.assertIn("remote-control-push-provider", script)
        self.assertIn("remote-control-push-target-id", script)
        self.assertIn("push_auth_secret", script)
        self.assertIn("device_token_secret", script)
        self.assertIn("fcm_project_id", script)
        self.assertIn('setList("remote-control-push-targets"', script)
        self.assertIn("remote-control-relay-dry-run", script)
        self.assertIn('document.getElementById("remote-control-relay-preview").addEventListener("click"', script)
        self.assertIn('document.getElementById("remote-control-relay-apply").addEventListener("click"', script)
        self.assertIn("dry_run: dryRun", script)
        self.assertIn('api("/remote-control/pair"', script)
        self.assertIn('api("/remote-control/revoke"', script)
        self.assertIn('setList("remote-control-relay"', script)
        self.assertIn('setList("remote-control-relay-outbox"', script)
        self.assertIn('setList("remote-control-pairings"', script)
        self.assertIn("allowed_actions", script)
        self.assertIn("expires_in_seconds", script)
        self.assertIn("data-remote-control-revoke", script)
        self.assertIn("data-remote-control-directory", script)
        self.assertIn('document.getElementById("remote-control-form").addEventListener("submit"', script)
        self.assertIn('document.getElementById("remote-control-relay-form").addEventListener("submit"', script)
        self.assertIn('document.getElementById("remote-control-pairings").addEventListener("click"', script)
        self.assertIn("renderRemoteControlRelay", script)
        self.assertIn("renderRemoteControlOutbox", script)
        self.assertIn("renderRemoteControlOutput", script)
        self.assertNotIn("token_sha256", script)

    def test_web_channel_control_exposes_live_channel_sends(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="channel-webhook-send-form"', markup)
        self.assertIn('id="channel-webhook-send-approved"', markup)
        self.assertIn('id="channel-chat-webhook-form"', markup)
        self.assertIn('id="channel-chat-webhook-approved"', markup)
        self.assertIn('id="channel-email-send-form"', markup)
        self.assertIn('id="channel-email-send-approved"', markup)
        self.assertIn('id="channel-live-activation-packet"', markup)
        self.assertIn('id="channel-verify-activation-packet"', markup)
        self.assertIn('document.getElementById("channel-webhook-send-form").addEventListener("submit"', script)
        self.assertIn('document.getElementById("channel-chat-webhook-form").addEventListener("submit"', script)
        self.assertIn('document.getElementById("channel-email-send-form").addEventListener("submit"', script)
        self.assertIn('document.getElementById("channel-live-activation-packet").addEventListener("click"', script)
        self.assertIn('document.getElementById("channel-verify-activation-packet").addEventListener("click"', script)
        self.assertIn('api("/channels/webhook/send"', script)
        self.assertIn('api("/channels/chat-webhook/send"', script)
        self.assertIn('api("/channels/email/send"', script)
        self.assertIn('api("/channels/live-activation-packet"', script)
        self.assertIn('api("/channels/verify-activation-packet"', script)
        self.assertIn('api("/channels/approval-intent/resolve"', script)
        self.assertIn('data-channel-intent-event', script)
        self.assertIn('data-channel-intent-approval', script)
        self.assertIn("channelActivationPacketId", script)
        self.assertIn('approved: document.getElementById("channel-webhook-send-approved").checked', script)
        self.assertIn('approved: document.getElementById("channel-chat-webhook-approved").checked', script)
        self.assertIn('approved: document.getElementById("channel-email-send-approved").checked', script)
        self.assertIn('session_id: state.activeSessionId || undefined', script)

    def test_web_policy_control_exposes_rollout_workflows(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="policy-schedule-form"', markup)
        self.assertIn('id="policy-schedule-source"', markup)
        self.assertIn('id="policy-schedule-activate-at"', markup)
        self.assertIn('id="policy-schedule-environment"', markup)
        self.assertIn('id="policy-schedule-approved"', markup)
        self.assertIn('id="policy-rollouts"', markup)
        self.assertIn('id="policy-promotions"', markup)
        self.assertIn('id="policy-activate-due"', markup)
        self.assertIn('document.getElementById("policy-schedule-form").addEventListener("submit"', script)
        self.assertIn('api("/policy/schedule-bundle"', script)
        self.assertIn('api("/policy/rollouts")', script)
        self.assertIn('api("/policy/promotions")', script)
        self.assertIn('api("/policy/activate-due"', script)

    def test_web_memory_panel_exposes_review_digest(self) -> None:
        root = Path(__file__).resolve().parents[1] / "src" / "aegis" / "web" / "static"
        markup = (root / "index.html").read_text(encoding="utf-8")
        script = (root / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="memory-review-digest"', markup)
        self.assertIn('id="memory-review-escalation"', markup)
        self.assertIn('id="memory-session-preview"', markup)
        self.assertIn('id="memory-session-commit"', markup)
        self.assertIn('id="migration-memory-form"', markup)
        self.assertIn('id="migration-memory-platform"', markup)
        self.assertIn('id="migration-memory-path"', markup)
        self.assertIn('document.getElementById("memory-review-digest").addEventListener("click"', script)
        self.assertIn('document.getElementById("memory-review-escalation").addEventListener("click"', script)
        self.assertIn('document.getElementById("memory-session-preview").addEventListener("click"', script)
        self.assertIn('document.getElementById("memory-session-commit").addEventListener("click"', script)
        self.assertIn('document.getElementById("migration-memory-form").addEventListener("submit"', script)
        self.assertIn('api("/memory/review-digest")', script)
        self.assertIn('api("/memory/review-escalation")', script)
        self.assertIn('/memory-preview?owner=local-user&scope=workspace', script)
        self.assertIn('/memory-commit', script)
        self.assertIn("data-memory-candidate-select", script)
        self.assertIn("const selectedMemoryCandidateIds = () =>", script)
        self.assertIn('data-memory-candidate-select="${escapeHtml(candidate.id)}" checked', script)
        self.assertIn("if (candidateIds !== null)", script)
        self.assertIn("body.candidate_ids = candidateIds", script)
        self.assertIn('/migration/memory-preview?platform=', script)
        self.assertIn('api("/migration/memory-commit"', script)
        self.assertIn('api("/memory/review-batch"', script)
        self.assertIn("data-memory-review-select", script)
        self.assertIn("data-memory-review-batch", script)
        self.assertIn('id="schedule-memory-escalation"', markup)
        self.assertIn('document.getElementById("schedule-memory-escalation").addEventListener("click"', script)
        self.assertIn('api("/schedules/memory-review-escalation"', script)
        self.assertIn("memory_review_escalation", script)

    def test_headless_chrome_loads_gui_and_renders_api_backed_state(self) -> None:
        chrome = _chrome_binary()
        if chrome is None:
            self.skipTest("Chrome/Chromium is not installed")

        with tempfile.TemporaryDirectory() as temp:
            port = _free_port()
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            data_dir = Path(temp) / ".aegis"
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "aegis.cli.main",
                    "--data-dir",
                    str(data_dir),
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
                session = _json_post(port, "/sessions", {"title": "GUI browser smoke", "channel": "web"}, token=token)
                task = _json_post(
                    port,
                    f"/sessions/{session['id']}/messages",
                    {"content": "send message hello", "submit": True},
                    token=token,
                )
                pending_dom = _dump_dom(chrome, port)
                other_session = _json_post(port, "/sessions", {"title": "Other GUI session", "channel": "web"}, token=token)
                _json_post(
                    port,
                    f"/sessions/{other_session['id']}/messages",
                    {"content": "other session noise", "submit": False},
                    token=token,
                )
                _json_post(
                    port,
                    f"/approvals/{task['checkpoint']['approval_id']}/approve",
                    {"actor": "browser-admin", "reason": "browser smoke", "admin": True},
                    token=token,
                )
                resumed = _json_post(port, f"/tasks/{task['id']}/resume", {}, token=token)

                dom = _dump_dom(chrome, port)

                self.assertIn('data-transcript-task-resume="', pending_dom)
                self.assertIn('data-transcript-approval-approve="', pending_dom)
                self.assertIn('data-transcript-approval-deny="', pending_dom)
                self.assertIn('data-approval-session="', pending_dom)
                self.assertIn('id="app-status" class="status-pill good">Healthy', dom)
                self.assertIn('id="runtime-stats"', dom)
                self.assertIn("<strong>Verified</strong><span>Audit</span>", dom)
                self.assertIn("GUI browser smoke", dom)
                self.assertIn(f'title="GUI browser smoke">{session["id"][:8]}', dom)
                self.assertIn("send message hello", dom)
                self.assertNotIn('id="active-session" title="Other GUI session"', dom)
                self.assertNotIn("other session noise", dom)
                self.assertIn(str(task["id"])[:8], dom)
                self.assertIn(str(resumed["id"])[:8], dom)
                self.assertIn("task_resume_result", dom)
                self.assertIn('data-task-session="', dom)
                self.assertIn('data-transcript-task-status="', dom)
                self.assertIn('data-transcript-task-events="', dom)
                self.assertIn('data-transcript-task-timeline="', dom)
                self.assertIn('data-transcript-approval-review="', dom)
                self.assertNotIn('data-transcript-task-resume="', dom)
                self.assertNotIn('data-transcript-approval-approve="', dom)
                self.assertNotIn('data-transcript-approval-deny="', dom)
                self.assertIn("current completed", dom)
                self.assertIn("approval approved", dom)
                self.assertIn("completed", dom)
                self.assertIn("Security Posture", dom)
                self.assertIn("Approvals", dom)
                self.assertIn("Recent Decisions", dom)
                self.assertIn("approved · browser-admin · admin · browser smoke", dom)
                self.assertNotIn('id="app-status" class="status-pill bad">Error', dom)
                self.assertNotIn('id="app-status" class="status-pill bad">Auth Error', dom)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _chrome_binary() -> str | None:
    for candidate in ("google-chrome", "chromium", "chromium-browser"):
        binary = shutil.which(candidate)
        if binary:
            return binary
    return None


def _dump_dom(chrome: str, port: int) -> str:
    result = subprocess.run(
        [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--virtual-time-budget=3000",
            "--dump-dom",
            f"http://127.0.0.1:{port}/",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"Chrome failed with exit {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        handle.bind(("127.0.0.1", 0))
        return int(handle.getsockname()[1])


def _wait_for_server(port: int) -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            _json_get(port, "/health")
            return
        except (HTTPError, URLError, ConnectionError):
            time.sleep(0.05)
    raise RuntimeError("server did not start")


def _json_get(port: int, path: str, *, token: str | None = None) -> dict[str, object]:
    headers = {}
    if token is not None:
        headers["X-Aegis-Token"] = token
    request = Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    with urlopen(request, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def _json_post(port: int, path: str, payload: dict[str, object], *, token: str) -> dict[str, object]:
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Aegis-Token": token},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
