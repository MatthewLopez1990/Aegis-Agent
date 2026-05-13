const state = {
  boards: [],
  selectedBoardId: null,
  activeSession: null,
  activeSessionId: null,
  inspectedTaskSessionId: null,
  browserSessionId: null,
  apiToken: null,
  lastTask: null,
  lastEvidence: null,
  lastEvents: null,
  runEventCursors: {},
  runEventStreamController: null,
  selectedApproval: null,
  pendingToolRun: null,
  pendingMcpCall: null,
  pendingBrowserAction: null,
  selectedRepairProposalId: null,
  activeSection: "security",
  taskScope: "session",
  memoryQuery: "",
  skillHubQuery: "",
  channelActivationPacketId: "",
  pluginMarketplaceQuery: "",
  pluginMarketplaceCatalogPath: "",
  pluginPreparedUpdateCandidateId: "",
  pendingSubagentDelegation: null,
  pendingSkillEnable: {},
  slashSelectionIndex: 0,
  slashPaletteEntries: [],
};

const TERMINAL_TASK_STATUSES = new Set(["completed", "failed", "blocked", "cancelled"]);
const RUN_EVENT_STREAM_TIMEOUT_SECONDS = 60;
const RUN_EVENT_STREAM_RECONNECT_LIMIT = 10;
const TOOL_RUN_PRESETS = [
  { label: "Calculator", name: "calculator", params: { expression: "2+2" } },
  { label: "Web Search", name: "web_search", params: { query: "aegis agent", num_results: 3 } },
  { label: "GitHub Issue", name: "github_issue", params: { operation: "read", provider_url: "https://api.github.com/repos/example/aegis/issues/1" } },
  { label: "GitLab Issue", name: "gitlab_issue", params: { operation: "read", provider_url: "https://gitlab.com/api/v4/projects/1/issues/1" } },
  { label: "Calendar", name: "calendar_read", params: { provider_url: "https://graph.example.com/me/events" } },
  { label: "Contacts", name: "contacts_search", params: { query: "local", provider_url: "https://graph.example.com/me/contacts" } },
  { label: "Create Contact", name: "contacts_write", params: { operation: "create", contact: { displayName: "Local User", email: "local@example.test" } } },
  { label: "Subagent", name: "subagent_delegate", params: { role: "Researcher", task: "Compare provider auth gaps." } },
  { label: "Service Ticket", name: "service_ticket_read", params: { operation: "search", query: "incident" } },
  { label: "Close Ticket", name: "service_ticket_write", params: { operation: "close", ticket: { id: "INC000001" } } },
  { label: "Message", name: "message_send", params: { message: { text: "Hello from Aegis", channel: "general" } } },
];

const WEB_SLASH_COMMANDS = [
  { command: "submit", label: "/submit <request>", detail: "Submit a governed task", kind: "submit", acceptsRequest: true },
  { command: "background", aliases: ["bg", "btw"], label: "/background|/bg|/btw <request>", detail: "Queue governed work from the active session", kind: "submit", acceptsRequest: true },
  { command: "queue", aliases: ["q"], label: "/queue|/q [status|all|session|submit]", detail: "Open the active queue or submit governed work", kind: "queue-control", section: "activity" },
  { command: "resume", aliases: ["continue"], label: "/resume [task_id]", detail: "Resume the selected waiting or paused task", kind: "task-control", taskAction: "resume" },
  { command: "pause", label: "/pause [task_id]", detail: "Pause the selected non-terminal task", kind: "task-control", taskAction: "pause" },
  { command: "cancel", aliases: ["stop"], label: "/cancel|/stop [task_id]", detail: "Cancel the selected non-terminal task", kind: "task-control", taskAction: "cancel" },
  { command: "tasks", aliases: ["task", "list"], label: "/tasks", detail: "Open the task feed", kind: "section", section: "activity" },
  { command: "approval", label: "/approval <approval_id>", detail: "Review an approval request", kind: "approval-control", approvalAction: "review" },
  { command: "approve", label: "/approve <approval_id>", detail: "Approve a pending approval", kind: "approval-control", approvalAction: "approve" },
  { command: "deny", label: "/deny <approval_id>", detail: "Deny a pending approval", kind: "approval-control", approvalAction: "deny" },
  { command: "approvals", aliases: ["permissions", "privacy-settings", "whoami", "yolo"], label: "/approvals", detail: "Open pending approval and privacy gates", kind: "section", section: "security" },
  { command: "models", aliases: ["model", "login", "logout", "setup-bedrock", "setup-vertex", "upgrade", "extra-usage", "passes"], label: "/models", detail: "Open provider login and model routing controls", kind: "section", section: "models" },
  { command: "tools", aliases: ["tool", "allowed-tools"], label: "/tools", detail: "Open governed tool and MCP controls", kind: "section", section: "tools" },
  { command: "browser", aliases: ["chrome"], label: "/browser|/chrome", detail: "Open guarded browser controls", kind: "section", section: "tools" },
  { command: "memory", aliases: ["mem"], label: "/memory", detail: "Open governed memory controls", kind: "section", section: "memory" },
  { command: "remote-control", aliases: ["rc", "remote", "mobile", "ios", "android"], label: "/remote-control", detail: "Open remote pairing and relay controls", kind: "section", section: "automation" },
  { command: "schedules", aliases: ["schedule", "hooks"], label: "/schedules", detail: "Open automation, hooks, and scheduled runs", kind: "section", section: "automation" },
  { command: "status", label: "/status [task_id]", detail: "Show task status for an id or the selected task", kind: "task-inspection", taskView: "status" },
  { command: "events", label: "/events [task_id]", detail: "Stream grouped run events for an id or the selected task", kind: "task-inspection", taskView: "events" },
  { command: "timeline", label: "/timeline [task_id]", detail: "Open ordered plan, receipt, and audit events", kind: "task-inspection", taskView: "timeline" },
  { command: "evidence", aliases: ["audit"], label: "/evidence [task_id]", detail: "Open receipts and audit evidence for an id or the selected task", kind: "task-inspection", taskView: "evidence" },
  { command: "settings", aliases: ["dashboard", "controls", "setup", "recap", "release-notes", "tui", "scroll-speed", "radio", "stickers", "focus", "heapdump", "ide"], label: "/settings", detail: "Open runtime posture and UI controls", kind: "section", section: "security" },
  { command: "commands", aliases: ["help", "keybindings", "autofix-pr", "simplify", "ultraplan", "ultrareview", "claude-api", "fewer-permission-prompts", "powerup", "team-onboarding", "install-github-app", "install-slack-app"], label: "/commands", detail: "Show slash command suggestions", kind: "palette" },
];

let webSlashCommands = WEB_SLASH_COMMANDS.slice();

const normalizeWebSlashCommand = (entry) => {
  const command = String(entry?.command || "").replace(/^\/+/, "").trim();
  if (!command) return null;
  return {
    command,
    aliases: Array.isArray(entry.aliases) ? entry.aliases.map((alias) => String(alias).replace(/^\/+/, "").trim()).filter(Boolean) : [],
    label: entry.label || `/${command}`,
    detail: entry.detail || "Open governed local command metadata",
    kind: entry.kind || "palette",
    section: entry.section || "settings",
    source: entry.source || "web",
    surfaces: Array.isArray(entry.surfaces) ? entry.surfaces.map(String) : ["web"],
    args: Array.isArray(entry.args) ? entry.args.map(String) : [],
    flags: Array.isArray(entry.flags) ? entry.flags.map(String) : [],
    requiresLocalToken: Boolean(entry.requires_local_token ?? entry.requiresLocalToken),
    requiresRemoteToken: Boolean(entry.requires_remote_token ?? entry.requiresRemoteToken),
    mutates: Boolean(entry.mutates),
    webActions: Array.isArray(entry.web_actions) ? entry.web_actions : Array.isArray(entry.webActions) ? entry.webActions : [],
    taskAction: entry.taskAction || entry.task_action || "",
    approvalAction: entry.approvalAction || entry.approval_action || "",
    acceptsRequest: Boolean(entry.acceptsRequest),
  };
};

const mergeWebSlashCommands = (commands = []) => {
  const merged = WEB_SLASH_COMMANDS.map((entry) => ({ ...entry }));
  const knownTerms = new Set(merged.flatMap((entry) => slashCommandTerms(entry)));
  commands
    .map(normalizeWebSlashCommand)
    .filter(Boolean)
    .forEach((entry) => {
      const terms = slashCommandTerms(entry);
      const existing = merged.find((candidate) => terms.some((term) => slashCommandTerms(candidate).includes(term)));
      if (existing) {
        if (entry.webActions.length) {
          existing.aliases = [...new Set([...(existing.aliases || []), ...(entry.aliases || [])])];
          existing.detail = entry.detail || existing.detail;
          existing.kind = entry.kind || existing.kind;
          existing.section = entry.section || existing.section;
          existing.source = entry.source || existing.source;
          existing.surfaces = entry.surfaces.length ? entry.surfaces : existing.surfaces;
          existing.args = entry.args.length ? entry.args : existing.args;
          existing.flags = entry.flags.length ? entry.flags : existing.flags;
          existing.requiresLocalToken = entry.requiresLocalToken;
          existing.requiresRemoteToken = entry.requiresRemoteToken;
          existing.mutates = entry.mutates;
          existing.webActions = entry.webActions;
          existing.taskAction = entry.taskAction || existing.taskAction;
          existing.approvalAction = entry.approvalAction || existing.approvalAction;
        }
        return;
      }
      terms.forEach((term) => knownTerms.add(term));
      merged.push(entry);
    });
  webSlashCommands = merged;
};

const api = async (url, options = {}) => {
  const method = String(options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.apiToken) {
    headers["X-Aegis-Token"] = state.apiToken;
  }
  const response = await fetch(url, {
    ...options,
    headers,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || payload.error || `Request failed: ${response.status}`);
  }
  return payload;
};

const bootstrapAuth = async () => {
  const payload = await api("/auth");
  state.apiToken = payload.token;
};

const escapeHtml = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const text = (value) => escapeHtml(Array.isArray(value) ? value.join(", ") : value);

const fieldList = (id) =>
  String(document.getElementById(id)?.value || "")
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);

const copyButton = (label, value) =>
  value ? `<button type="button" class="secondary" data-copy-command="${escapeHtml(value)}">${text(label)}</button>` : "";

const slashCommandTerms = (entry) => [entry.command, ...(entry.aliases || [])].map((term) => String(term).toLowerCase());

const slashMatchRank = (prefix, entry) => {
  const normalized = String(prefix || "").replace(/^\/+/, "").toLowerCase();
  if (!normalized) return [0, entry.command];
  const terms = slashCommandTerms(entry);
  if (terms.includes(normalized)) return [0, entry.command];
  if (terms.some((term) => term.startsWith(normalized))) return [1, entry.command];
  if (terms.some((term) => term.includes(normalized))) return [2, entry.command];
  if (String(entry.detail || "").toLowerCase().includes(normalized)) return [3, entry.command];
  return [9, entry.command];
};

const slashCommandMatches = (prefix) =>
  webSlashCommands
    .filter((entry) => slashMatchRank(prefix, entry)[0] < 9)
    .sort((left, right) => {
      const leftRank = slashMatchRank(prefix, left);
      const rightRank = slashMatchRank(prefix, right);
      return leftRank[0] - rightRank[0] || leftRank[1].localeCompare(rightRank[1]);
    });

const slashCommandForToken = (token) => {
  const normalized = String(token || "").replace(/^\/+/, "").toLowerCase();
  return webSlashCommands.find((entry) => slashCommandTerms(entry).includes(normalized)) || null;
};

const slashConcreteOptions = (options = []) =>
  options.map(String).filter((option) => option && !option.endsWith("_id") && option !== "request");

const slashInputContext = (rawValue) => {
  const raw = String(rawValue || "");
  const trimmedStart = raw.trimStart();
  if (!trimmedStart.startsWith("/")) return { kind: "task" };
  const match = trimmedStart.match(/^\/([a-zA-Z0-9_.:-]*)([\s\S]*)$/);
  if (!match) return { kind: "unknown", prefix: "" };
  const commandToken = match[1] || "";
  const remainder = match[2] || "";
  if (!commandToken || !remainder) {
    return { kind: "command", prefix: commandToken };
  }
  const entry = slashCommandForToken(commandToken);
  if (!entry) return { kind: "command", prefix: commandToken };
  const endsWithSpace = /\s$/.test(remainder);
  const current = endsWithSpace ? "" : (remainder.match(/(\S+)$/)?.[1] || "");
  const replaceStart = raw.length - current.length;
  const parts = remainder.trim().split(/\s+/).filter(Boolean);
  const wantsFlag = current.startsWith("--") || parts.some((part) => part.startsWith("--"));
  return {
    kind: wantsFlag ? "flag" : "arg",
    command: entry.command,
    entry,
    prefix: current,
    replaceStart,
    replaceEnd: raw.length,
  };
};

const slashOptionMatches = (context) => {
  const options = slashConcreteOptions(context.kind === "flag" ? context.entry?.flags : context.entry?.args);
  const prefix = String(context.prefix || "").toLowerCase();
  return options
    .filter((option) => !prefix || option.toLowerCase().startsWith(prefix) || option.toLowerCase().includes(prefix))
    .map((option) => ({
      command: context.command,
      label: option,
      detail: `${context.kind === "flag" ? "Flag" : "Option"} for /${context.command}`,
      kind: "completion",
      completionKind: context.kind,
      completionValue: option,
      replaceStart: context.replaceStart,
      replaceEnd: context.replaceEnd,
    }));
};

const slashPaletteMatches = (rawValue) => {
  const context = slashInputContext(rawValue);
  if (context.kind === "arg" || context.kind === "flag") {
    return slashOptionMatches(context);
  }
  return slashCommandMatches(context.prefix || "");
};

const parseTaskSlashCommand = (rawValue) => {
  const raw = String(rawValue || "");
  const trimmedStart = raw.trimStart();
  if (!trimmedStart.startsWith("/")) {
    return { kind: "task", request: raw };
  }
  const match = trimmedStart.match(/^\/([a-zA-Z0-9_.:-]+)(?:\s+([\s\S]*))?$/);
  if (!match) {
    return { kind: "unknown", token: trimmedStart.slice(1).split(/\s+/, 1)[0], request: "" };
  }
  const entry = slashCommandForToken(match[1]);
  if (!entry) {
    return { kind: "unknown", token: match[1], request: match[2] || "" };
  }
  return { ...entry, request: match[2] || "", token: match[1] };
};

const renderSlashPalette = () => {
  const input = document.getElementById("task-request");
  const palette = document.getElementById("slash-palette");
  const value = input.value.trimStart();
  if (!value.startsWith("/")) {
    palette.hidden = true;
    palette.replaceChildren();
    state.slashSelectionIndex = 0;
    state.slashPaletteEntries = [];
    return;
  }
  const prefix = value.slice(1).split(/\s+/, 1)[0];
  const matches = slashPaletteMatches(value).slice(0, 8);
  state.slashPaletteEntries = matches;
  if (!matches.length) {
    palette.hidden = false;
    palette.innerHTML = `<div class="slash-palette-header"><span>No slash matches</span><span>/${text(prefix)}</span></div>`;
    return;
  }
  state.slashSelectionIndex = Math.min(state.slashSelectionIndex, matches.length - 1);
  palette.hidden = false;
  palette.innerHTML = `
    <div class="slash-palette-header"><span>Slash Commands</span><span>Tab completes · Ctrl+Enter sends</span></div>
    ${matches.map((entry, index) => `
      <button type="button" class="slash-palette-row ${index === state.slashSelectionIndex ? "active" : ""}" data-slash-index="${index}">
        <strong>${text(entry.label)}</strong>
        <span>${text(entry.detail)}</span>
      </button>
    `).join("")}
  `;
};

const applySlashCompletion = (entry) => {
  const input = document.getElementById("task-request");
  if (entry.completionKind) {
    input.value = `${input.value.slice(0, entry.replaceStart)}${entry.completionValue} ${input.value.slice(entry.replaceEnd)}`;
    input.focus();
    renderSlashPalette();
    return;
  }
  const parsed = parseTaskSlashCommand(input.value);
  const suffix = parsed.request ? ` ${parsed.request}` : entry.acceptsRequest ? " " : "";
  input.value = `/${entry.command}${suffix}`;
  input.focus();
  renderSlashPalette();
};

const item = ({ title, detail = "", meta = "", tone = "", actions = "", data = {} }) => {
  const node = document.createElement("div");
  node.className = `item ${tone}`.trim();
  Object.entries(data).forEach(([key, value]) => {
    node.dataset[key] = value;
  });
  node.innerHTML = `
    <div class="item-copy">
      <strong>${text(title)}</strong>
      ${detail ? `<span>${text(detail)}</span>` : ""}
      ${meta ? `<small>${text(meta)}</small>` : ""}
    </div>
    ${actions ? `<div class="item-actions">${actions}</div>` : ""}
  `;
  return node;
};

const empty = (label) => {
  const node = document.createElement("div");
  node.className = "empty-state";
  node.textContent = label;
  return node;
};

const setList = (id, rows, mapper, emptyLabel = "No records") => {
  const node = document.getElementById(id);
  if (!rows.length) {
    node.replaceChildren(empty(emptyLabel));
    return;
  }
  node.replaceChildren(...rows.map((row) => item(mapper(row))));
};

const modelProviderFallbackLabel = (provider) =>
  String(provider || "")
    .split("-")
    .filter(Boolean)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");

const syncModelProviderOptions = (providerRows = [], authTargets = []) => {
  const select = document.getElementById("model-provider");
  const selected = select.value;
  const labels = new Map(Array.from(select.options).map((option) => [option.value, option.textContent]));
  providerRows.forEach((row) => {
    const provider = row.provider;
    if (provider && !labels.has(provider)) {
      labels.set(provider, row.label || modelProviderFallbackLabel(provider));
    }
  });
  authTargets.forEach((row) => {
    const provider = row.aegis_provider || row.provider;
    if (provider && !labels.has(provider)) {
      labels.set(provider, row.target || modelProviderFallbackLabel(provider));
    }
  });
  const existing = new Set(Array.from(select.options).map((option) => option.value));
  Array.from(labels.entries())
    .filter(([provider]) => provider && !existing.has(provider))
    .sort(([left], [right]) => left.localeCompare(right))
    .forEach(([provider, label]) => {
      const option = document.createElement("option");
      option.value = provider;
      option.textContent = label;
      select.append(option);
    });
  if (labels.has(selected)) {
    select.value = selected;
  }
  syncModelAuthMethodForProvider();
};

const connectorPolicyMeta = (connector) => {
  const risks = Object.entries(connector.risk_by_operation || {})
    .map(([operation, risk]) => `${operation}:${risk}`)
    .slice(0, 4)
    .join(", ");
  const scopes = Object.entries(connector.operation_scopes || {})
    .map(([operation, values]) => `${operation}:${(values || []).join("/") || "none"}`)
    .slice(0, 4)
    .join(", ");
  const required = (connector.required_scopes || []).join("/");
  const optional = (connector.optional_scopes || []).join("/");
  return [
    connector.auth_type,
    connector.data_sensitivity ? `sensitivity ${connector.data_sensitivity}` : "",
    required ? `required ${required}` : "",
    optional ? `optional ${optional}` : "",
    risks ? `risk ${risks}` : "",
    scopes ? `scopes ${scopes}` : "",
  ].filter(Boolean).join(" · ");
};

const backendBlockerSummary = (activation) => {
  const blockers = activation?.blockers || [];
  if (!blockers.length) return "none";
  return blockers.slice(0, 4).map((blocker) => blocker.control || "unknown").join(", ");
};

const backendActivationSummary = (backends) => {
  const rows = (backends || []).slice(0, 6).map((backend) => {
    const activation = backend.activation || {};
    const blockers = backendBlockerSummary(activation);
    return `${backend.name}:${activation.preflight_status || activation.status || "unknown"}${blockers !== "none" ? ` blockers ${blockers}` : ""}`;
  });
  return rows.join("; ") || "none";
};

const setFeatureGrid = (id, rows, mapper) => {
  const node = document.getElementById(id);
  node.replaceChildren(
    ...rows.map((row) => {
      const mapped = mapper(row);
      const card = document.createElement("article");
      card.className = "feature-card";
      card.innerHTML = `
        <strong>${text(mapped.title)}</strong>
        <span>${text(mapped.detail)}</span>
        ${mapped.meta ? `<small>${text(mapped.meta)}</small>` : ""}
      `;
      return card;
    })
  );
};

const renderMetrics = (dashboard) => {
  const runtime = dashboard.runtime;
  const stats = [
    ["Audit", runtime.audit_chain_ok ? "Verified" : "Failed", runtime.audit_chain_ok ? "good" : "bad"],
    ["Channels", runtime.channels, "neutral"],
    ["Tools", runtime.tools, "neutral"],
    ["Approval Gates", runtime.approval_gated_tools, "warn"],
    ["Providers", runtime.model_providers, "neutral"],
    ["Active Work", runtime.active_work_count || 0, runtime.active_work_count ? "warn" : "good"],
    ["Pending", runtime.pending_approvals, runtime.pending_approvals ? "warn" : "good"],
  ];
  document.getElementById("runtime-stats").replaceChildren(
    ...stats.map(([label, value, tone]) => {
      const stat = document.createElement("div");
      stat.className = `metric ${tone}`;
      stat.innerHTML = `<strong>${text(value)}</strong><span>${text(label)}</span>`;
      return stat;
    })
  );
  document.getElementById("app-status").textContent = runtime.audit_chain_ok ? "Healthy" : "Degraded";
  document.getElementById("app-status").className = runtime.audit_chain_ok ? "status-pill good" : "status-pill bad";
};

const refresh = async () => {
  try {
    const [
      dashboard,
      remoteControl,
      remoteControlRelay,
      remoteControlOutbox,
      connectors,
      policy,
      policyBundles,
      channels,
      channelEvents,
      models,
      modelProviders,
      modelAuthTargets,
      modelAuthDoctor,
      modelUsage,
      tools,
      backends,
      browserSessions,
      skillHub,
      skills,
      plugins,
      pluginMarketplace,
      pluginUpdates,
      mcpServers,
      schedules,
      sessions,
      audit,
      auditSiem,
      improvements,
      repairReadiness,
      tasks,
      approvals,
      approvedApprovals,
      deniedApprovals,
      boards,
      subagents,
      evaluationQueue,
      evaluationTrends,
      evaluationDelta,
      evaluationReadiness,
      commandCatalog,
    ] = await Promise.all([
      api("/dashboard"),
      api("/remote-control/status"),
      api("/remote-control/relay"),
      api("/remote-control/relay/outbox"),
      api("/connectors"),
      api("/policy"),
      api("/policy/bundles"),
      api("/channels"),
      api("/channel-events?limit=20"),
      api("/models"),
      api("/model-providers"),
      api("/models/auth/targets"),
      api("/models/auth/doctor"),
      api("/model-usage"),
      api("/tools"),
      api("/backends"),
      api("/browser/sessions"),
      api(`/skill-hub?q=${encodeURIComponent(state.skillHubQuery)}`),
      api("/skills"),
      api("/plugins"),
      api(`/plugins/marketplace?q=${encodeURIComponent(state.pluginMarketplaceQuery)}${state.pluginMarketplaceCatalogPath ? `&catalog_path=${encodeURIComponent(state.pluginMarketplaceCatalogPath)}` : ""}`),
      api(`/plugins/updates${state.pluginMarketplaceCatalogPath ? `?catalog_path=${encodeURIComponent(state.pluginMarketplaceCatalogPath)}` : ""}`),
      api("/mcp/servers"),
      api("/schedules"),
      api("/sessions"),
      api("/audit?limit=40"),
      api("/audit/export-siem?limit=40"),
      api("/improvements?limit=20"),
      api("/improvements/readiness?limit=20"),
      api("/tasks?limit=12"),
      api("/approvals?status=pending&limit=20"),
      api("/approvals?status=approved&limit=8"),
      api("/approvals?status=denied&limit=8"),
      api("/kanban/boards"),
      api("/subagents/status?limit=12"),
      api("/evaluation/queue?limit=20"),
      api("/evaluation/trends?limit=20"),
      api("/evaluation/delta"),
      api("/evaluation/readiness?limit=20&include_live_gaps=1"),
      api("/commands"),
    ]);

    mergeWebSlashCommands(commandCatalog.commands || []);
    syncModelProviderOptions(modelProviders.providers || [], modelAuthTargets.targets || dashboard.model_provider_auth_parity?.targets || []);
    syncPendingSkillEnableApprovals([...(approvedApprovals.approvals || []), ...(approvals.approvals || [])]);
    renderMetrics(dashboard);
    renderRemoteControlRelay(remoteControlRelay);
    renderRemoteControlOutbox(remoteControlOutbox);
    setList("remote-control-push-targets", remoteControl.native_push_targets || [], (x) => ({
      title: x.label || x.id,
      detail: `${x.provider || "provider"} · auth ${x.push_auth_secret_configured ? "configured" : "missing"} · device ${x.device_token_secret_configured ? "configured" : "missing"}`,
      meta: `${x.status} · rotated ${x.rotation_count || 0} · ${x.last_push_delivery_state || "not pushed"}${x.last_push_at ? ` · ${x.last_push_at}` : ""}`,
      tone: x.status === "active" ? "ready" : "attention",
    }), "No native push targets");
    setList("remote-control-pairings", remoteControl.pairings || [], (x) => ({
      title: x.label || x.id,
      detail: `Session ${x.session_id || "any"} · task ${x.task_id || "any"} · actions ${(x.allowed_actions || []).join(", ") || "none"}`,
      meta: `${x.status} · expires ${x.expires_at}`,
      tone: x.status === "active" ? "ready" : "attention",
      actions: x.status === "active"
        ? `<button type="button" class="secondary" data-remote-control-directory="${escapeHtml(x.id)}">Directory</button><button type="button" class="secondary" data-remote-control-revoke="${escapeHtml(x.id)}">Revoke</button>`
        : "",
    }), "No remote-control pairings");
    setFeatureGrid("security-controls", dashboard.security_controls, (x) => ({
      title: x.name,
      detail: x.detail,
      meta: x.state,
    }));
    renderPolicyOutput(policy);
    setList("policy-bundles", policyBundles.bundles, (x) => ({
      title: x.name,
      detail: x.description,
      meta: `${x.profile.message_send} messages · ${x.profile.shell_execution} shell`,
      actions: `
        <button type="button" class="secondary" data-policy-diff="${escapeHtml(x.name)}">Diff</button>
        <button type="button" class="secondary" data-policy-apply="${escapeHtml(x.name)}">Apply</button>
      `,
    }));
    setFeatureGrid("capability-groups", dashboard.capability_groups, (x) => ({
      title: x.name,
      detail: x.detail,
      meta: `${x.state} · ${x.coverage}`,
    }));
    setFeatureGrid("implementation-readiness", dashboard.implementation_readiness || [], (x) => ({
      title: x.label,
      detail: `${x.detail}${x.sample_tools?.length ? ` Sample tools: ${x.sample_tools.slice(0, 6).join(", ")}` : ""}`,
      meta: `${x.count} tools · ${(x.statuses || []).slice(0, 4).join(", ") || x.state}`,
    }));
    setList("live-gap-backlog", dashboard.live_gap_backlog || [], (x) => ({
      title: x.area,
      detail: `${x.detail} Provider targets: ${x.target_provider_count || "n/a"}. Auth bridges: ${(x.subscription_bridge_targets || []).slice(0, 6).join(", ") || "none"}. Not started: ${(x.not_started_targets || []).slice(0, 6).join(", ") || "none"}. Live reads: ${(x.live_read_surfaces || []).slice(0, 6).join(", ") || "none"}. Live adapters: ${(x.implemented_live_adapters || []).slice(0, 6).map((adapter) => adapter.name).join(", ") || "none"}. Available adapters: ${(x.available_live_adapters || []).slice(0, 6).map((adapter) => adapter.name).join(", ") || "none"}. Backend adapters: ${(x.implemented_backend_adapters || []).slice(0, 6).map((adapter) => adapter.name).join(", ") || "none"}. Available backends: ${(x.available_backend_adapters || []).slice(0, 6).map((adapter) => adapter.name).join(", ") || "none"}. Backend preflight: ${backendActivationSummary([...(x.implemented_backend_adapters || []), ...(x.available_backend_adapters || [])])}. Readiness checklist: ${(x.operator_checklist || []).slice(0, 8).map((item) => `${item.control}:${item.state}`).join(", ") || "none"}. Hardened: ${(x.implemented_hardening_controls || []).slice(0, 8).map((control) => control.control).join(", ") || "none"}. Remaining depth: ${(x.remaining_depth_work || []).slice(0, 6).join(", ") || "none"}. Controls: ${(x.required_controls || []).join(", ") || "none"}. Gates: ${(x.verification_gates || []).join(", ") || "none"}. Evaluations: ${(x.evaluation_scenarios || []).join(", ") || "none"}. Next: ${(x.next_steps || []).slice(0, 2).join(" ")}`,
      meta: `${x.status} · ${(x.platforms || []).join(", ")} · tools ${(x.sample_tools || []).slice(0, 6).join(", ") || "none"}`,
    }), "No live gaps");
    setList("competitor-targets", dashboard.competitive_targets, (x) => ({
      title: x.platform,
      detail: `Security: ${x.security_delta}`,
      meta: `Covered: ${x.covered.slice(0, 5).join(", ")} · Live gap: ${x.live_gap}`,
      tone: "highlight",
    }));

    setList("connectors", connectors.connectors, (x) => ({
      title: x.name,
      detail: `${x.default_mode} · ${x.supported_operations.join(", ")}`,
      meta: connectorPolicyMeta(x),
    }));
    setList("channels", channels.channels.slice(0, 30), (x) => ({
      title: x.name,
      detail: `${x.rich_messages.join(", ")}`,
      meta: `${x.difficulty} · ${x.auth_type}`,
    }));
    setList("channel-events", channelEvents.events, (x) => ({
      title: `${x.channel} · ${x.normalized?.sender || "unknown"}`,
      detail: channelEventDetail(x),
      meta: `${x.direction || "event"} · ${x.status || "recorded"} · ${x.created_at}`,
      tone: x.normalized?.approval_intent ? "ready" : x.normalized?.text?.includes("QUARANTINED") ? "attention" : "",
      actions: channelApprovalIntentActions(x, approvals.approvals || []),
    }), "No inbound channel events");
    setList(
      "model-providers",
      modelProviders.providers,
      (x) => ({
        title: x.provider,
        detail: x.local
          ? "Local provider"
          : x.auth_configured
            ? `Auth configured via ${x.auth_source}`
            : x.subscription_auth_supported
              ? `Auth missing · subscription setup: ${x.subscription_auth?.external_command || "external login required"}`
              : "Auth missing",
        meta: `${x.models.length} models · tools ${formatBool(x.supports_tools)} · auth ${(x.auth_methods || []).join(", ") || "none"} · subscription ${formatBool(x.subscription_auth_supported)}`,
        tone: x.local || x.auth_configured ? "ready" : "attention",
      })
    );
    setList("model-auth-targets", modelAuthTargets.targets || dashboard.model_provider_auth_parity?.targets || [], (x) => ({
      title: x.target,
      detail: `${(x.platforms || []).join(", ") || "provider"} · ${x.account_surface || ""}`,
      meta: `${x.status} · auth ${(x.required_auth || []).join(", ") || "unknown"} · methods ${(x.existing_auth_methods || []).join(", ") || "none"} · bridge ${x.bridge_status || "not_started"}`,
      tone: x.status === "api_key_ready" || x.status === "local_ready" ? "ready" : "attention",
    }), "No provider auth targets");
    setList("model-auth-doctor", modelAuthDoctor.checks || [], (x) => ({
      title: x.target,
      detail: modelAuthDoctorDetail(x),
      meta: `${x.activation_state || (x.verified ? "verified" : "login_required")} · ${x.method} · command ${x.external_command_available ? "available" : "missing"} · provider ${x.provider}`,
      tone: x.activation_state === "verified_ready" ? "ready" : "attention",
      actions: modelAuthDoctorActions(x),
    }), "No provider login checks");
    setList("models", models.models.slice(0, 24), (x) => ({
      title: x.identifier,
      detail: x.local ? "local" : x.auth_configured ? "cloud · auth configured" : "cloud · auth missing",
      meta: `${x.supports_tools ? "tools" : "chat"}${x.supports_vision ? " · vision" : ""}${x.supports_audio ? " · audio" : ""}`,
    }));
    renderModelUsage(modelUsage);
    setList("tools", tools.tools, (x) => ({
      title: x.name,
      detail: x.description,
      meta: `${x.risk_level} · ${x.implementation_status || "local"} · ${x.approval_required ? "approval required" : x.permission}`,
      tone: x.approval_required || !x.implemented ? "attention" : "",
    }));
    setList("backends", backends.backends, (x) => ({
      title: x.name,
      detail: `${x.description}${x.activation?.required_controls?.length ? ` Controls: ${x.activation.required_controls.join(", ")}. Gates: ${x.activation.verification_gates.join(", ")}. Blockers: ${backendBlockerSummary(x.activation)}` : ""}`,
      meta: `${x.risk_level} · ${x.enabled ? "enabled" : "disabled"} · ${x.activation?.status || "unknown"} · ${x.activation?.preflight_status || "unknown"}`,
      tone: x.enabled ? "ready" : "",
    }));
    if (!state.browserSessionId && browserSessions.sessions.length) {
      state.browserSessionId = browserSessions.sessions[0].id;
    }
    setList("browser-sessions", browserSessions.sessions, (x) => ({
      title: x.title || x.label,
      detail: x.current_url || "no page loaded",
      meta: `${shortId(x.id)} · ${x.status}`,
      tone: x.id === state.browserSessionId ? "highlight" : "",
      actions: `<button type="button" class="secondary" data-browser-session="${escapeHtml(x.id)}">Open</button><button type="button" class="secondary" data-browser-close="${escapeHtml(x.id)}">Close</button>`,
    }), "No browser sessions");
    setList("skill-hub", skillHub.entries, (x) => ({
      title: x.name,
      detail: x.risk,
      meta: `${x.category} · ${x.install_mode}`,
    }), state.skillHubQuery ? "No matching Skill Hub entries" : "No Skill Hub entries");
    setList("installed-skills", skills.skills, (x) => {
      const skillEnableApproval = state.pendingSkillEnable[x.id];
      const pendingApprovalId = skillEnableApproval?.id || skillEnableApproval;
      const pendingApprovalStatus = skillEnableApproval?.status || "pending";
      const pendingMeta = pendingApprovalId ? ` · ${pendingApprovalStatus} enable approval ${shortId(pendingApprovalId)}` : "";
      return {
        title: x.name || x.id,
        detail: x.description,
        meta: `${x.enabled ? "enabled" : "disabled"} · ${x.risk_level} · ${x.approval_required ? "approval required" : "approval optional"} · ${x.sandbox_profile} · ${(x.permissions_summary || []).join(", ") || "no permissions"}${pendingMeta}`,
        tone: x.enabled ? "ready" : pendingApprovalId ? "attention" : "",
        actions: x.enabled
          ? `<button type="button" class="secondary" data-skill-disable="${escapeHtml(x.id)}">Disable</button>`
          : `<button type="button" class="secondary" data-skill-enable="${escapeHtml(x.id)}">${pendingApprovalId ? "Replay Enable" : "Enable"}</button>`,
      };
    }, "No installed skills");
    setList("installed-plugins", plugins.plugins || [], (x) => ({
      title: x.name || x.id,
      detail: `${x.description || "Local plugin"} Resources: ${(x.resources || []).map((resource) => `${resource.kind}:${resource.id || resource.name}`).join(", ") || "none"}`,
      meta: `${x.enabled ? "enabled" : "disabled"} · v${x.version || "0.0.0"} · ${x.unsigned_local ? "unsigned local" : "signed resources"} · ${x.resources?.length || 0} resources`,
      tone: x.enabled ? "ready" : "",
      actions: `
        <button type="button" class="secondary" data-plugin-enable="${escapeHtml(x.id)}">Enable</button>
        <button type="button" class="secondary" data-plugin-disable="${escapeHtml(x.id)}">Disable</button>
        <button type="button" class="secondary" data-plugin-remove="${escapeHtml(x.id)}">Remove</button>
      `,
    }), "No installed plugins");
    setList("plugin-marketplace", pluginMarketplace.entries || [], (x) => ({
      title: x.name || x.id,
      detail: `${x.description || "Marketplace metadata"} Resources: ${(x.resource_kinds || []).join(", ") || "none"}`,
      meta: `${x.installed ? `installed ${x.installed_version || "unknown"}` : "not installed"} · catalog v${x.version || "0.0.0"} · ${x.install_mode || "manual"} · verified manifest ${formatBool(x.marketplace_install_supported)} · signed bundle ${formatBool(x.marketplace_bundle_install_supported)}`,
      tone: x.update_available ? "attention" : x.installed ? "ready" : "",
      actions: `${x["manifest_fetch_supported"] ? `<button type="button" class="secondary" data-plugin-marketplace-fetch-manifest="${escapeHtml(x.id)}">Fetch Manifest</button>` : ""}${x.bundle_fetch_supported ? `<button type="button" class="secondary" data-plugin-marketplace-fetch-bundle="${escapeHtml(x.id)}">Fetch Bundle</button>` : ""}${x.marketplace_bundle_install_supported ? `<button type="button" class="secondary" data-plugin-marketplace-install-bundle="${escapeHtml(x.id)}">Install Bundle</button>` : ""}${x.marketplace_install_supported ? `<button type="button" class="secondary" data-plugin-marketplace-install="${escapeHtml(x.id)}">Install</button>` : ""}`,
    }), "No marketplace plugin metadata");
    setList("plugin-updates", pluginUpdates.updates || [], (x) => ({
      title: x.name || x.id,
      detail: `${x.installed_version} -> ${x.available_version}. ${(x.next_actions || []).join(" ")}`,
      meta: `${x.status} · ${x.install_mode || "manual_manifest_review"} · review ${formatBool(x.requires_review)}`,
      tone: "attention",
      actions: `<button type="button" class="secondary" data-plugin-marketplace-prepare-update="${escapeHtml(x.id)}">Prepare</button><button type="button" class="secondary" data-plugin-marketplace-update="${escapeHtml(x.id)}">Apply Direct</button>`,
    }), "No plugin updates");
    setList("mcp-servers", mcpServers.servers, (x) => ({
      title: x.name,
      detail: x.command,
      meta: `${x.metadata?.transport || "stdio"} · ${x.enabled ? "enabled" : "disabled"} · ${x.approval_required ? "approval required" : "approval optional"} · ${x.allowed_tools.join(", ") || "no tools"}`,
    }), "No MCP servers");
    setList("schedules", schedules.schedules, (x) => ({
      title: x.name,
      detail:
        x.metadata?.kind === "memory_review_digest"
          ? `Memory review digest for ${x.metadata.scope || "workspace"}`
          : x.metadata?.kind === "memory_review_escalation"
            ? `Memory review escalation for ${x.metadata.route || "operator"}`
            : x.metadata?.kind === "evaluation_run"
              ? `Evaluation run for ${x.metadata.scenario || "scheduled evaluation"}`
              : x.metadata?.kind === "evaluation_suite"
                ? `Evaluation suite ${x.metadata.suite || "security"} for ${x.metadata.reviewer || "scheduler"}`
                : x.metadata?.kind === "no_agent_hook"
                  ? `No-agent hook ${x.metadata.hook_id || "scheduled hook"}`
                  : x.task_request,
      meta: `${x.status} · ${x.cron} · next ${x.next_run_at}`,
      tone: "attention",
      actions: `
        ${
          x.status === "active"
            ? `<button type="button" class="secondary" data-schedule-pause="${escapeHtml(x.id)}">Pause</button>`
            : x.status === "paused_pending_approval"
              ? `<button type="button" data-schedule-approve="${escapeHtml(x.id)}">Approve</button>`
              : `<button type="button" data-schedule-activate="${escapeHtml(x.id)}">Activate</button>`
        }
      `,
    }));
    setList("evaluation-trends", Object.entries(evaluationTrends.by_status || {}).map(([status, count]) => ({ status, count })), (x) => ({
      title: x.status,
      detail: `${x.count} report${x.count === 1 ? "" : "s"}`,
      meta: `latest ${evaluationTrends.latest_status || "none"}`,
      tone: x.status === "reviewed_passed" ? "ready" : "attention",
    }), "No evaluation trends");
    setList("evaluation-readiness", [evaluationReadiness], (x) => ({
      title: x.status || "readiness",
      detail: x.blockers?.length
        ? x.blockers.map((blocker) => `${blocker.type}: ${blocker.count}`).join("; ")
        : "No evaluation release blockers",
      meta: `${x.scenario || "all scenarios"} · live gaps ${(x.live_gap_backlog || []).length}`,
      tone: x.ready ? "ready" : "attention",
    }), "No release readiness summary");
    setList("evaluation-delta", [evaluationDelta], (x) => ({
      title: x.status || "delta",
      detail: x.reason || `${x.status_change?.from || "unknown"} -> ${x.status_change?.to || "unknown"}`,
      meta: x.scenario || "all scenarios",
      tone: x.regression ? "attention" : x.improvement ? "ready" : "",
    }), "No evaluation delta");
    setList("evaluation-queue", evaluationQueue.items || [], (x) => ({
      title: x.scenario || x.id,
      detail: x.compressed_summary || x.status,
      meta: `${shortId(x.id)} · ${x.status} · ${x.reviewer || "unassigned"}`,
      tone: "attention",
      actions: `<button type="button" class="secondary" data-evaluation-report="${escapeHtml(x.id)}">Select</button>`,
    }), "No evaluation reports awaiting review");
    if (!state.activeSessionId && sessions.sessions.length) {
      state.activeSessionId = sessions.sessions[0].id;
    }
    if (state.inspectedTaskSessionId && !sessions.sessions.some((session) => session.id === state.inspectedTaskSessionId)) {
      state.inspectedTaskSessionId = null;
    }
    renderActiveSession(sessions.sessions);
    const taskSessionId = state.inspectedTaskSessionId || state.activeSessionId;
    const visibleTasks = taskSessionId && state.taskScope === "session"
      ? await api(`/sessions/${encodeURIComponent(taskSessionId)}/tasks?limit=12`)
      : tasks;
    document.querySelectorAll("[data-task-scope]").forEach((button) => {
      button.classList.toggle("active", button.dataset.taskScope === state.taskScope);
    });
    const inspectedSession = sessions.sessions.find((session) => session.id === state.inspectedTaskSessionId);
    const tasksSessionLabel = document.getElementById("tasks-session-label");
    tasksSessionLabel.textContent = state.taskScope === "all"
      ? "All sessions"
      : inspectedSession
        ? `Inspecting ${shortId(inspectedSession.id)}`
        : "Active session";
    tasksSessionLabel.className = inspectedSession ? "status-pill good" : "status-pill";
    setList("sessions", sessions.sessions, (x) => ({
      title: x.title,
      detail: `${x.channel} · ${x.status} · ${x.message_count || 0} msgs · ${x.task_count || 0} tasks`,
      meta: x.latest_task ? `latest ${shortId(x.latest_task.id)} · ${x.latest_task.status}` : x.updated_at,
      tone: `${x.id === state.activeSessionId ? "highlight" : ""} ${x.id === state.inspectedTaskSessionId ? "inspected" : ""}`.trim(),
      data: { session: x.id },
      actions: `<button type="button" class="secondary" data-session-select="${escapeHtml(x.id)}">Open</button><button type="button" class="secondary" data-session-tasks="${escapeHtml(x.id)}">Tasks</button>`,
    }));
    setList("audit", audit.events, (x) => ({
      title: x.event_type,
      detail: x.task_id || "runtime",
      meta: x.timestamp,
    }));
    document.getElementById("audit-siem-output").textContent = auditSiem.jsonl
      ? `SIEM JSONL export (${auditSiem.count} events)\n${auditSiem.jsonl.slice(0, 1600)}`
      : "SIEM JSONL export has no events.";
    setList("improvements", improvements.proposals, (x) => ({
      title: x.summary,
      detail: x.task_id || "runtime",
      meta: `${x.status} · ${x.kind} · ${x.created_at}`,
      tone: x.status === "proposed" ? "attention" : x.status === "implemented" ? "ready" : "",
      actions: improvementActions(x),
    }), "No repair proposals");
    setList("repair-readiness", [repairReadiness], (x) => ({
      title: x.status || "repair readiness",
      detail: x.blocker_count ? `${x.blocker_count} blocker${x.blocker_count === 1 ? "" : "s"}` : "No repair readiness blockers",
      meta: `${x.proposal_count || 0} proposals · ${x.candidate_counts?.total || 0} candidates · ${x.attempt_count || 0} attempts`,
      tone: x.ready ? "ready" : "attention",
    }), "No repair readiness summary");
    setList("active-work", dashboard.active_work_tasks || [], (x) => ({
      title: x.user_request,
      detail: x.interpretation,
      meta: `${shortId(x.id)} · ${x.status} · session ${taskSessionLabel(x)}`,
      tone: x.status === "waiting_approval" || x.status === "paused" ? "attention" : "",
      actions: taskActions(x),
    }), "No active work");
    setList("tasks", visibleTasks.tasks, (x) => ({
      title: x.user_request,
      detail: x.interpretation,
      meta: `${shortId(x.id)} · ${x.status} · ${x.risk_level} · session ${taskSessionLabel(x)}`,
      tone: x.status === "waiting_approval" ? "attention" : x.status === "completed" ? "ready" : "",
      actions: taskActions(x),
    }), taskSessionId && state.taskScope === "session" ? "No tasks in this session" : "No tasks");
    setList("session-linked-tasks", dashboard.recent_session_tasks || [], (x) => ({
      title: x.user_request,
      detail: x.interpretation,
      meta: `${shortId(x.id)} · ${x.status} · session ${taskSessionLabel(x)}`,
      tone: x.status === "waiting_approval" ? "attention" : x.status === "completed" ? "ready" : "",
      actions: taskActions(x),
    }), "No session-linked tasks");
    setList("approvals", approvals.approvals, (x) => ({
      title: x.reason,
      detail: x.task_id ? `${x.task_id} · session ${approvalSessionLabel(x)}` : `runtime approval · session ${approvalSessionLabel(x)}`,
      meta: `${x.risk_level} · ${x.created_at}`,
      tone: "attention",
      actions: `
        <button type="button" class="secondary" data-approval-review="${escapeHtml(x.id)}">Review</button>
        ${x.session_id ? `<button type="button" class="secondary" data-approval-session="${escapeHtml(x.session_id)}">Open Session</button>` : ""}
        <button type="button" data-approve="${escapeHtml(x.id)}">Approve</button>
        <button type="button" class="secondary" data-deny="${escapeHtml(x.id)}">Deny</button>
      `,
    }), "No pending approvals");
    const recentDecisions = [...(approvedApprovals.approvals || []), ...(deniedApprovals.approvals || [])]
      .sort((left, right) => String(right.updated_at || right.created_at || "").localeCompare(String(left.updated_at || left.created_at || "")))
      .slice(0, 8);
    setList("approval-decisions", recentDecisions, (x) => ({
      title: x.reason,
      detail: x.task_id ? `${x.task_id} · session ${approvalSessionLabel(x)}` : `runtime approval · session ${approvalSessionLabel(x)}`,
      meta: approvalDecisionMeta(x),
      tone: x.status === "approved" ? "ready" : "attention",
      actions: `
        <button type="button" class="secondary" data-approval-review="${escapeHtml(x.id)}">Review</button>
        ${x.session_id ? `<button type="button" class="secondary" data-approval-session="${escapeHtml(x.session_id)}">Open Session</button>` : ""}
      `,
    }), "No approval decisions");

    state.boards = boards.boards;
    if (!state.selectedBoardId && state.boards.length) {
      state.selectedBoardId = state.boards[0].id;
    }
    renderBoards();
    await renderCards();
    renderSubagents(subagents);
    await renderSessionTranscript();
    applySectionVisibility();
  } catch (error) {
    document.getElementById("app-status").textContent = "Error";
    document.getElementById("app-status").className = "status-pill bad";
    renderTaskError(error.message);
  }
};

const renderSubagents = (payload) => {
  const summary = document.getElementById("subagent-summary");
  const batchControl = (payload.implemented_controls || []).includes("operator_approved_batch_runtime") ? " · batch run ready" : "";
  const reviewPacketControl = (payload.implemented_controls || []).includes("model_ready_review_packets") ? " · review packets ready" : "";
  summary.textContent = `${payload.open_cards || 0} open · ${payload.ready_cards || 0} ready · ${payload.in_progress_cards || 0} active · ${payload.review_cards || 0} review · ${payload.done_cards || 0} done · profiles ${payload.enabled_profile_count || 0}/${payload.profile_count || 0} · autonomous runtime ${payload.autonomous_runtime ? "enabled" : "blocked"}${batchControl}${reviewPacketControl}`;
  setList("subagent-cards", payload.cards || [], (x) => ({
    title: x.title,
    detail: x.description_preview || "No preview",
    meta: subagentCardMeta(x),
    actions: subagentLaneActions(x),
    tone: x.lane === "done" ? "ready" : x.lane === "blocked" ? "attention" : "",
  }), "No subagent delegation cards");
};

const subagentCardMeta = (card) => {
  const reviewPacketCount = Number(card.review_packets_recorded || 0);
  const hasReviewPacket = Boolean(card.model_ready_review_packet || card.model_ready_review_packet_available || card.model_review_packet || card.review_packet);
  const parts = [
    card.lane,
    card.owner || "unassigned",
    `tainted ${card.instructions_tainted ? "yes" : "no"}`,
    `handoffs ${card.handoff_receipts_recorded || 0}`,
    `runs ${card.subagent_runs_recorded || 0}`,
  ];
  if (card.review_status) {
    parts.push(`review ${card.review_status}`);
  }
  if (reviewPacketCount || hasReviewPacket) {
    parts.push(`packets ${reviewPacketCount || 1}`);
  }
  if (card.model_reviews_recorded) {
    parts.push(`model reviews ${card.model_reviews_recorded}`);
  }
  if (hasReviewPacket) {
    parts.push("model-ready");
  }
  return parts.join(" · ");
};

const subagentHasReviewPacket = (card) =>
  Boolean(card.model_ready_review_packet || card.model_ready_review_packet_available || card.model_review_packet || card.review_packet);

const subagentLaneActions = (card) => {
  const nextLane = {
    backlog: "ready",
    ready: "in_progress",
    in_progress: "review",
    review: "done",
    blocked: "ready",
  }[card.lane];
  const actions = [];
  if (["ready", "in_progress"].includes(card.lane)) {
    actions.push(`<button type="button" data-subagent-run="${escapeHtml(card.id)}">Run</button>`);
  }
  if (card.lane !== "done") {
    const label = subagentHasReviewPacket(card) ? "Refresh Review Packet" : "Create Review Packet";
    actions.push(`<button type="button" class="secondary" data-subagent-review-packet="${escapeHtml(card.id)}">${text(label)}</button>`);
  }
  const reviewPacket = card.review_packet || card.model_review_packet || {};
  if (reviewPacket.packet_id) {
    actions.push(`<button type="button" class="secondary" data-subagent-verify-packet="${escapeHtml(reviewPacket.packet_id)}">Verify Packet</button>`);
    actions.push(`<button type="button" class="secondary" data-subagent-model-review="${escapeHtml(card.id)}">Model Review</button>`);
  }
  if (nextLane) {
    actions.push(`<button type="button" class="secondary" data-subagent-card="${escapeHtml(card.id)}" data-subagent-lane="${escapeHtml(nextLane)}">${text(nextLane.replaceAll("_", " "))}</button>`);
  }
  if (!["blocked", "done"].includes(card.lane)) {
    actions.push(`<button type="button" class="secondary" data-subagent-card="${escapeHtml(card.id)}" data-subagent-lane="blocked">Block</button>`);
  }
  return actions.join("");
};

const renderSubagentOutput = (payload) => {
  const node = document.getElementById("subagent-output");
  const replay = payload.status === "approval_required" && payload.approval_id
    ? `<div class="item-actions"><button type="button" class="secondary" data-subagent-approved="${escapeHtml(payload.approval_id)}">Run Approved Delegation</button></div>`
    : "";
  node.innerHTML = `<pre>${escapeHtml(JSON.stringify(payload, null, 2))}</pre>${replay}`;
};

const renderBoards = () => {
  setList("boards", state.boards, (x) => ({
    title: x.name,
    detail: x.id,
    meta: x.updated_at,
    tone: x.id === state.selectedBoardId ? "highlight" : "",
    data: { board: x.id },
  }), "No boards");
  const select = document.getElementById("card-board");
  select.replaceChildren(
    ...state.boards.map((board) => {
      const option = document.createElement("option");
      option.value = board.id;
      option.textContent = board.name;
      option.selected = board.id === state.selectedBoardId;
      return option;
    })
  );
};

const renderCards = async () => {
  const node = document.getElementById("cards");
  if (!state.selectedBoardId) {
    node.replaceChildren(empty("No cards"));
    return;
  }
  const payload = await api(`/kanban/boards/${state.selectedBoardId}/cards`);
  const lanes = ["backlog", "ready", "in_progress", "review", "blocked", "done"];
  node.replaceChildren(
    ...lanes.map((lane) => {
      const laneNode = document.createElement("section");
      laneNode.className = "lane";
      const cards = payload.cards.filter((card) => card.lane === lane);
      laneNode.innerHTML = `<h4>${text(lane.replaceAll("_", " "))}</h4>`;
      if (!cards.length) {
        laneNode.appendChild(empty("Empty"));
      } else {
        laneNode.append(
          ...cards.map((card) =>
            item({
              title: card.title,
              detail: card.description,
              meta: `${card.risk_level} · ${card.owner || "unassigned"}`,
              actions: lane === "done" ? "" : `<button type="button" class="secondary" data-card="${escapeHtml(card.id)}" data-lane="done">Done</button>`,
            })
          )
        );
      }
      return laneNode;
    })
  );
};

const formatBool = (value) => (value ? "yes" : "no");

const renderActiveSession = (sessions) => {
  const session = sessions.find((row) => row.id === state.activeSessionId);
  state.activeSession = session || null;
  const node = document.getElementById("active-session");
  node.textContent = session ? shortId(session.id) : "No session";
  node.title = session ? session.title : "";
  document.getElementById("session-update-title").value = session?.title || "";
  document.getElementById("session-update-model").value = session?.model || "";
  document.getElementById("session-update-personality").value = session?.personality || "";
  document.getElementById("session-update-status").value = session?.status || "active";
};

const renderSessionTranscript = async () => {
  const node = document.getElementById("session-transcript");
  if (!state.activeSessionId) {
    node.replaceChildren(empty("Create or open a session"));
    return;
  }
  const payload = await api(`/sessions/${encodeURIComponent(state.activeSessionId)}/messages?limit=40`);
  if (!payload.messages.length) {
    node.replaceChildren(empty("No messages yet"));
    return;
  }
  node.replaceChildren(
    ...payload.messages.map((message) => {
      const bubble = document.createElement("article");
      bubble.className = `message ${message.role === "assistant" ? "assistant" : "user"}`;
      const meta = sessionMessageMeta(message);
      const actions = sessionMessageActions(message);
      bubble.innerHTML = `
        <strong>${text(message.role)}</strong>
        <p>${text(message.content)}</p>
        ${meta.length ? `<div class="message-meta">${meta.map((item) => `<span>${text(item)}</span>`).join("")}</div>` : ""}
        ${actions}
        <small>${text(message.trust_class)} · ${text(message.created_at)}</small>
      `;
      return bubble;
    })
  );
  node.scrollTop = node.scrollHeight;
};

const applySectionVisibility = () => {
  document.querySelectorAll("[data-section]").forEach((node) => {
    node.hidden = node.dataset.section !== state.activeSection;
  });
  document.querySelectorAll("[data-section-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.sectionTab === state.activeSection);
  });
};

const taskModelResponse = (task) => task?.receipt?.model_response || null;

const taskSessionLabel = (task) => {
  if (task?.session) {
    return `${task.session.title || "Session"} · ${shortId(task.session.id)}`;
  }
  return task?.session_id ? shortId(task.session_id) : "none";
};

const approvalSessionLabel = (approval) => {
  if (approval?.session) {
    return `${approval.session.title || "Session"} · ${shortId(approval.session.id)}`;
  }
  return approval?.session_id ? shortId(approval.session_id) : "none";
};

const approvalDecisionMeta = (approval) => {
  const decision = approval?.decision || {};
  const actor = decision.actor || "unknown actor";
  const reason = decision.reason || "no reason recorded";
  return `${approval.status} · ${actor}${decision.admin ? " · admin" : ""} · ${reason}`;
};

const sessionMessageMeta = (message) => {
  const metadata = message?.metadata || {};
  const currentTask = message?.current_task_status && message.current_task_status !== metadata.status ? `current ${message.current_task_status}` : "";
  const currentApproval = message?.current_approval_status ? `approval ${message.current_approval_status}` : "";
  return [
    metadata.source,
    metadata.status,
    currentTask,
    metadata.task_id ? `task ${shortId(metadata.task_id)}` : "",
    metadata.checkpoint_approval_id ? `approval ${shortId(metadata.checkpoint_approval_id)}` : "",
    currentApproval,
  ].filter(Boolean);
};

const sessionMessageActions = (message) => {
  const hints = Array.isArray(message?.action_hints) ? message.action_hints : [];
  const taskId = hints.find((hint) => hint?.action === "task_status")?.task_id || message?.metadata?.task_id;
  const taskResumeId = hints.find((hint) => hint?.action === "task_resume")?.task_id;
  const approvalId = hints.find((hint) => hint?.action === "approval_review")?.approval_id || message?.metadata?.checkpoint_approval_id;
  const approvalApproveId = hints.find((hint) => hint?.action === "approval_approve")?.approval_id;
  const approvalDenyId = hints.find((hint) => hint?.action === "approval_deny")?.approval_id;
  if (!taskId && !approvalId) return "";
  const encodedTask = escapeHtml(taskId || "");
  const encodedTaskResume = escapeHtml(taskResumeId || "");
  const encodedApproval = escapeHtml(approvalId || "");
  const encodedApprovalApprove = escapeHtml(approvalApproveId || "");
  const encodedApprovalDeny = escapeHtml(approvalDenyId || "");
  return `
    <div class="message-actions">
      ${taskId ? `<button type="button" class="secondary" data-transcript-task-status="${encodedTask}">Status</button>` : ""}
      ${taskId ? `<button type="button" class="secondary" data-transcript-task-events="${encodedTask}">Events</button>` : ""}
      ${taskId ? `<button type="button" class="secondary" data-transcript-task-timeline="${encodedTask}">Timeline</button>` : ""}
      ${taskResumeId ? `<button type="button" data-transcript-task-resume="${encodedTaskResume}">Resume</button>` : ""}
      ${approvalId ? `<button type="button" class="secondary" data-transcript-approval-review="${encodedApproval}">Approval</button>` : ""}
      ${approvalApproveId ? `<button type="button" data-transcript-approval-approve="${encodedApprovalApprove}">Approve</button>` : ""}
      ${approvalDenyId ? `<button type="button" class="secondary" data-transcript-approval-deny="${encodedApprovalDeny}">Deny</button>` : ""}
    </div>
  `;
};

const taskSessionActions = (payload) => {
  const hints = Array.isArray(payload?.action_hints) ? payload.action_hints : [];
  const sessionId =
    hints.find((hint) => hint?.action === "session_show")?.session_id ||
    hints.find((hint) => hint?.action === "session_history")?.session_id ||
    payload?.session_id;
  if (!sessionId) return "";
  return `
    <div class="item-actions">
      <button type="button" class="secondary" data-task-session="${escapeHtml(sessionId)}">Open Session</button>
    </div>
  `;
};

const improvementActions = (proposal) => {
  if (proposal.status === "proposed") {
    return `
      <button type="button" class="secondary" data-improvement-select="${escapeHtml(proposal.id)}">Select</button>
      <button type="button" data-improvement-review="${escapeHtml(proposal.id)}">Review</button>
    `;
  }
  if (proposal.status === "reviewing") {
    return `
      <button type="button" class="secondary" data-improvement-select="${escapeHtml(proposal.id)}">Select</button>
      <button type="button" data-improvement-approve="${escapeHtml(proposal.id)}">Approve</button>
    `;
  }
  if (proposal.status === "approved") {
    return `
      <button type="button" class="secondary" data-improvement-select="${escapeHtml(proposal.id)}">Select</button>
      <button type="button" data-improvement-implement="${escapeHtml(proposal.id)}">Record Repair</button>
    `;
  }
  return `<button type="button" class="secondary" data-improvement-select="${escapeHtml(proposal.id)}">Select</button>`;
};

const taskActions = (task) => `
  <button type="button" class="secondary" data-task-status="${escapeHtml(task.id)}">Status</button>
  <button type="button" class="secondary" data-task-events="${escapeHtml(task.id)}">Events</button>
  <button type="button" class="secondary" data-task-evidence="${escapeHtml(task.id)}">Evidence</button>
  <button type="button" class="secondary" data-task-timeline="${escapeHtml(task.id)}">Timeline</button>
  ${task.session_id ? `<button type="button" class="secondary" data-task-session="${escapeHtml(task.session_id)}">Open Session</button>` : ""}
  ${["waiting_approval", "paused"].includes(task.status) ? `<button type="button" data-task-resume="${escapeHtml(task.id)}">Resume</button>` : ""}
  ${!TERMINAL_TASK_STATUSES.has(task.status) && task.status !== "paused" ? `<button type="button" class="secondary" data-task-pause="${escapeHtml(task.id)}">Pause</button>` : ""}
  ${!TERMINAL_TASK_STATUSES.has(task.status) ? `<button type="button" class="secondary" data-task-cancel="${escapeHtml(task.id)}">Cancel</button>` : ""}
  <button type="button" class="secondary" data-copy-id="${escapeHtml(task.id)}">ID</button>
`;

const renderTaskResult = (task) => {
  state.lastTask = task;
  const node = document.getElementById("task-output");
  const model = taskModelResponse(task);
  const approvalId = task?.checkpoint?.approval_id;
  const sessionLabel = taskSessionLabel(task);
  const card = document.createElement("section");
  card.className = `task-card ${task.status}`;
  card.innerHTML = `
    <div class="task-card-header">
      <div>
        <span class="status-chip">${text(task.status)}</span>
        <h4>${text(task.interpretation)}</h4>
      </div>
      <div class="item-actions">${taskActions(task)}</div>
    </div>
    <dl class="task-facts">
      <div><dt>Risk</dt><dd>${text(task.risk_level)}</dd></div>
      <div><dt>Receipt</dt><dd>${text(task.receipt?.result || "pending")}</dd></div>
      <div><dt>Model</dt><dd>${text(model?.identifier || model?.status || "not invoked")}</dd></div>
      <div><dt>Task</dt><dd>${text(shortId(task.id))}</dd></div>
      <div><dt>Session</dt><dd>${text(sessionLabel)}</dd></div>
    </dl>
    ${
      approvalId
        ? `<div class="next-action">Approval ${text(shortId(approvalId))} is pending. Approve it, then resume this task.</div>`
        : ""
    }
    ${
      model?.content
        ? `<div class="model-answer"><strong>Model Response</strong><p>${text(model.content)}</p></div>`
        : model?.reason || model?.error
          ? `<div class="model-answer"><strong>Model ${text(model.status)}</strong><p>${text(model.reason || model.error)}</p></div>`
          : ""
    }
  `;
  node.replaceChildren(card);
};

const renderTaskEvents = (payload) => {
  state.lastEvents = payload;
  const node = document.getElementById("task-events");
  const events = payload.events || [];
  const stepGroups = payload.step_groups || [];
  const providerSubsteps = payload.provider_substeps || [];
  const progress = payload.progress || {};
  const sessionLabel = taskSessionLabel(payload);
  if (!events.length && !payload.status && !Object.keys(progress).length) {
    node.replaceChildren(empty("No run events"));
    return;
  }
  const progressCard = document.createElement("article");
  progressCard.className = "run-event progress";
  progressCard.innerHTML = `
    <div class="run-event-main">
      <span class="status-chip">${text(progress.status || payload.status || "unknown")}</span>
      <strong>Progress Metrics</strong>
      <small>${text(progress.completed_steps || 0)} / ${text(progress.total_steps || 0)} steps · ${text(progress.total_events || events.length)} events</small>
    </div>
    ${taskSessionActions(payload)}
    <dl class="task-facts compact-facts">
      <div><dt>Complete</dt><dd>${text(progress.step_completion_ratio ?? 0)}</dd></div>
      <div><dt>Waiting</dt><dd>${text(progress.waiting_steps || 0)}</dd></div>
      <div><dt>Failed</dt><dd>${text(progress.failed_steps || 0)}</dd></div>
      <div><dt>Substeps</dt><dd>${text(progress.provider_substeps || providerSubsteps.length || 0)}</dd></div>
      <div><dt>Latest Seq</dt><dd>${text(progress.latest_sequence || 0)}</dd></div>
    </dl>
  `;
  const groupCards = stepGroups.map((group) => {
    const card = document.createElement("article");
    card.className = `run-event step-group ${group.status || ""}`.trim();
    card.innerHTML = `
      <div class="run-event-main">
        <span class="status-chip">${text(group.status || "planned")}</span>
        <strong>${text(group.title || `Step ${group.sequence || ""}`)}</strong>
        <small>${text(group.event_count || 0)} events · ${text(group.latest_event || "pending")}</small>
      </div>
      <dl class="task-facts compact-facts">
        <div><dt>Step</dt><dd>${text(group.step_id || "")}</dd></div>
        <div><dt>Tool</dt><dd>${text(group.connector || "runtime")}</dd></div>
        <div><dt>Operation</dt><dd>${text(group.operation || "")}</dd></div>
        <div><dt>Session</dt><dd>${text(sessionLabel)}</dd></div>
      </dl>
    `;
    return card;
  });
  const divider = document.createElement("div");
  divider.className = "section-label";
  divider.textContent = "Event Log";
  const substepDivider = document.createElement("div");
  substepDivider.className = "section-label";
  substepDivider.textContent = "Provider Substeps";
  const substepCards = providerSubsteps.map((entry) => {
    const card = document.createElement("article");
    card.className = `run-event provider-substep ${entry.kind || ""}`.trim();
    card.innerHTML = `
      <div class="run-event-main">
        <span class="status-chip">${text(entry.status || "recorded")}</span>
        <strong>${text(entry.identifier || entry.provider || "substep")}</strong>
        <small>${text(entry.provider || "provider")} · #${text(entry.sequence || "")}</small>
        <p>${text(entry.summary || "")}</p>
      </div>
      <dl class="task-facts compact-facts">
        <div><dt>Kind</dt><dd>${text(entry.kind || "")}</dd></div>
        <div><dt>Operation</dt><dd>${text(entry.operation || "")}</dd></div>
        <div><dt>Session</dt><dd>${text(sessionLabel)}</dd></div>
      </dl>
    `;
    return card;
  });
  node.replaceChildren(
    progressCard,
    ...groupCards,
    ...(substepCards.length ? [substepDivider, ...substepCards] : []),
    divider,
    ...events.map((entry) => {
      const card = document.createElement("article");
      card.className = `run-event ${entry.kind || ""}`.trim();
      card.innerHTML = `
        <div class="run-event-main">
          <span class="status-chip">${text(entry.kind || "event")}</span>
          <strong>${text(entry.title)}</strong>
          <small>${text(entry.timestamp || `#${entry.sequence || ""}`)} · ${text(entry.status || "")}</small>
          <p>${text(entry.summary || "")}</p>
        </div>
        <dl class="task-facts compact-facts">
          <div><dt>Tool</dt><dd>${text(entry.tool || "runtime")}</dd></div>
          <div><dt>Operation</dt><dd>${text(entry.operation || "")}</dd></div>
          <div><dt>Session</dt><dd>${text(sessionLabel)}</dd></div>
          <div><dt>Hash</dt><dd>${text(shortId(entry.hash))}</dd></div>
          <div><dt>Seq</dt><dd>${text(entry.sequence || "")}</dd></div>
        </dl>
      `;
      return card;
    })
  );
};

const appendTaskEvent = (eventPayload) => {
  const current = state.lastEvents || { task_id: eventPayload.task_id, status: "streaming", events: [] };
  renderTaskEvents({ ...current, events: [...(current.events || []), eventPayload] });
};

const parseEventStreamChunk = (buffer, onFrame) => {
  let remaining = buffer;
  let boundary = remaining.indexOf("\n\n");
  while (boundary !== -1) {
    const frame = remaining.slice(0, boundary);
    remaining = remaining.slice(boundary + 2);
    const lines = frame.split("\n");
    const id = lines.find((line) => line.startsWith("id: "))?.slice(4) || "";
    const event = lines.find((line) => line.startsWith("event: "))?.slice(7) || "message";
    const data = lines
      .filter((line) => line.startsWith("data: "))
      .map((line) => line.slice(6))
      .join("\n");
    if (data) {
      onFrame(event, JSON.parse(data), id);
    }
    boundary = remaining.indexOf("\n\n");
  }
  return remaining;
};

const streamTaskEvents = async (taskId) => {
  if (!window.ReadableStream || !window.TextDecoder) {
    return loadTaskEventsSnapshot(taskId);
  }
  if (state.runEventStreamController) {
    state.runEventStreamController.abort();
  }
  const controller = new AbortController();
  state.runEventStreamController = controller;
  renderTaskEvents({ task_id: taskId, status: "streaming", events: [] });
  state.activeSection = "evidence";
  applySectionVisibility();
  let reconnects = 0;
  try {
    while (!controller.signal.aborted) {
      const since = state.runEventCursors[taskId] || 0;
      const streamUrl = `/tasks/${encodeURIComponent(taskId)}/events/stream?follow=1&live=1&timeout=${RUN_EVENT_STREAM_TIMEOUT_SECONDS}&since=${encodeURIComponent(since)}`;
      let streamStatus = state.lastEvents?.task_id === taskId ? state.lastEvents.status : "streaming";
      const response = await fetch(streamUrl, {
        headers: state.apiToken ? { "X-Aegis-Token": state.apiToken } : {},
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        throw new Error(`Event stream failed: ${response.status}`);
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer = parseEventStreamChunk(buffer + decoder.decode(value, { stream: true }), (event, data, id) => {
          if (event === "task") {
            streamStatus = data.status || streamStatus;
            const existingEvents = since && state.lastEvents?.task_id === taskId ? (state.lastEvents.events || []) : [];
            state.lastEvents = { ...data, events: existingEvents };
            renderTaskEvents(state.lastEvents);
          }
          if (event === "run_event") {
            if (id.includes(":")) {
              state.runEventCursors[taskId] = Number(id.split(":").pop() || data.sequence || 0) || Number(data.sequence || 0);
            } else if (data.sequence) {
              state.runEventCursors[taskId] = Number(data.sequence);
            }
            appendTaskEvent(data);
          }
          if (event === "task_status" || event === "heartbeat") {
            streamStatus = data.status || streamStatus;
            state.lastEvents = {
              ...(state.lastEvents || { task_id: taskId, events: [] }),
              task_id: data.task_id || taskId,
              status: streamStatus,
              progress: data.progress || state.lastEvents?.progress || {},
            };
            renderTaskEvents(state.lastEvents);
          }
          if (event === "done") {
            streamStatus = data.status || streamStatus;
            state.lastEvents = { ...(state.lastEvents || {}), status: streamStatus };
            renderTaskEvents(state.lastEvents);
          }
        });
      }
      if (TERMINAL_TASK_STATUSES.has(streamStatus)) {
        break;
      }
      reconnects += 1;
      if (reconnects > RUN_EVENT_STREAM_RECONNECT_LIMIT) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  } finally {
    if (state.runEventStreamController === controller) {
      state.runEventStreamController = null;
    }
  }
};

const renderTaskEvidence = (bundle) => {
  state.lastEvidence = bundle;
  const node = document.getElementById("task-evidence");
  const task = bundle.task || {};
  const receipt = task.receipt || {};
  const checkpoint = task.checkpoint || {};
  const auditRows = bundle.audit_tail || [];
  const proposalRows = bundle.improvement_proposals || [];
  const candidateRows = bundle.repair_candidates || [];
  const attemptRows = bundle.repair_attempts || [];
  const verificationRows = bundle.verification_receipts || [];
  const learnedMemoryRows = bundle.learned_memories || [];
  const missingRows = bundle.missing_evidence || [];
  const actionRows = Array.isArray(receipt.actions) ? receipt.actions.slice(0, 8) : [];
  const shell = document.createElement("section");
  shell.className = "evidence-card";
  shell.innerHTML = `
    <div class="task-card-header">
      <div>
        <span class="status-chip">${text(task.status || "unknown")}</span>
        <h4>${text(task.interpretation || "Task evidence")}</h4>
      </div>
      <div class="item-actions">
        ${task.session_id ? `<button type="button" class="secondary" data-task-session="${escapeHtml(task.session_id)}">Open Session</button>` : ""}
        <button type="button" class="secondary" data-copy-id="${escapeHtml(task.id || "")}">ID</button>
      </div>
    </div>
    <dl class="task-facts">
      <div><dt>Task</dt><dd>${text(shortId(task.id))}</dd></div>
      <div><dt>Receipt</dt><dd>${text(receipt.result || "pending")}</dd></div>
      <div><dt>Audit Events</dt><dd>${text(auditRows.length)}</dd></div>
      <div><dt>Repair Candidates</dt><dd>${text(candidateRows.length)}</dd></div>
      <div><dt>Checkpoint</dt><dd>${text(checkpoint.approval_id ? shortId(checkpoint.approval_id) : "none")}</dd></div>
      <div><dt>Session</dt><dd>${text(taskSessionLabel(task))}</dd></div>
    </dl>
    ${
      actionRows.length
        ? `<div class="evidence-block"><strong>Actions</strong>${actionRows.map((action) => `<code>${text(JSON.stringify(action))}</code>`).join("")}</div>`
        : ""
    }
    ${
      proposalRows.length
        ? `<div class="evidence-block"><strong>Repair Proposals</strong>${proposalRows.map((proposal) => `<code>${text(proposal.status)} ${text(shortId(proposal.id))} ${text(proposal.summary || "")}</code>`).join("")}</div>`
        : ""
    }
    ${
      candidateRows.length
        ? `<div class="evidence-block"><strong>Repair Candidates</strong>${candidateRows.map((candidate) => `<code>${text(candidate.status)} ${text(shortId(candidate.id))} ${text(candidate.summary || "")} ${text((candidate.changed_files || []).join(", "))}</code>`).join("")}</div>`
        : ""
    }
    ${
      attemptRows.length
        ? `<div class="evidence-block"><strong>Repair Attempts</strong>${attemptRows.map((attempt) => `<code>${text(attempt.status)} ${text(attempt.outcome || "")}</code>`).join("")}</div>`
        : ""
    }
    ${
      verificationRows.length
        ? `<div class="evidence-block"><strong>Verification Receipts</strong>${verificationRows.map((receiptRow) => `<code>${text(receiptRow.test_result || "unknown")} ${text(receiptRow.test_command || "")}</code>`).join("")}</div>`
        : ""
    }
    ${
      learnedMemoryRows.length
        ? `<div class="evidence-block"><strong>Learned Memories</strong>${learnedMemoryRows.map((memory) => `<code>${text(shortId(memory.id))} ${text(memory.summary || "")}</code>`).join("")}</div>`
        : ""
    }
    ${
      missingRows.length
        ? `<div class="evidence-block"><strong>Missing Repair Evidence</strong>${missingRows.map((item) => `<code>${text(item.kind || "evidence")} ${text(item.reason || "")}</code>`).join("")}</div>`
        : ""
    }
    ${
      Object.keys(checkpoint).length
        ? `<div class="evidence-block"><strong>Checkpoint</strong><code>${text(JSON.stringify(checkpoint, null, 2))}</code></div>`
        : ""
    }
    ${
      auditRows.length
        ? `<div class="evidence-block"><strong>Task Audit Trail</strong>${auditRows
            .slice(-12)
            .map((event) => `<code>${text(event.timestamp)} ${text(event.event_type)} ${text(JSON.stringify(event.payload || {}))}</code>`)
            .join("")}</div>`
        : `<div class="next-action">No task-specific audit events found.</div>`
    }
  `;
  node.replaceChildren(shell);
};

const renderTaskTimeline = (timeline) => {
  const node = document.getElementById("task-timeline");
  const sessionLabel = taskSessionLabel(timeline);
  if (!timeline.items?.length) {
    node.replaceChildren(empty("No timeline entries"));
    return;
  }
  const summary = document.createElement("article");
  summary.className = "timeline-item summary";
  summary.innerHTML = `
    <div>
      <span class="status-chip">timeline</span>
      <strong>Timeline Context</strong>
      <small>${text(timeline.items.length)} entries · session ${text(sessionLabel)}</small>
    </div>
    ${taskSessionActions(timeline)}
    <dl class="task-facts compact-facts">
      <div><dt>Task</dt><dd>${text(shortId(timeline.task_id))}</dd></div>
      <div><dt>Session</dt><dd>${text(sessionLabel)}</dd></div>
    </dl>
  `;
  node.replaceChildren(
    summary,
    ...timeline.items.map((entry) => {
      const card = document.createElement("article");
      card.className = `timeline-item ${entry.kind || ""}`.trim();
      card.innerHTML = `
        <div>
          <span class="status-chip">${text(entry.kind || "event")}</span>
          <strong>${text(entry.title)}</strong>
          <small>${text(entry.timestamp || `step ${entry.sequence || ""}`)} · ${text(entry.status || "")}</small>
        </div>
        <dl class="task-facts compact-facts">
          <div><dt>Risk</dt><dd>${text(entry.risk_level || "")}</dd></div>
          <div><dt>Connector</dt><dd>${text(entry.connector || "")}</dd></div>
          <div><dt>Operation</dt><dd>${text(entry.operation || "")}</dd></div>
          <div><dt>Session</dt><dd>${text(sessionLabel)}</dd></div>
          <div><dt>Hash</dt><dd>${text(shortId(entry.hash))}</dd></div>
        </dl>
        <code>${text(JSON.stringify(entry.details || {}, null, 2))}</code>
      `;
      return card;
    })
  );
};

const approvalDecisionPayload = () => ({
  actor: document.getElementById("approval-actor")?.value || "web-console",
  reason: document.getElementById("approval-reason")?.value || "Reviewed from web console.",
  admin: Boolean(document.getElementById("approval-admin")?.checked),
});

const channelEventDetail = (event) => {
  const intent = event.normalized?.approval_intent;
  const textValue = event.normalized?.text || JSON.stringify(event.payload || {});
  if (!intent) return textValue;
  return `${textValue} Intent: ${intent.action} (${intent.matched_phrase})`;
};

const channelApprovalIntentActions = (event, pendingApprovals) => {
  const intent = event.normalized?.approval_intent;
  if (!intent || intent.auto_execute !== false || intent.requires_explicit_approval_id !== true) return "";
  const candidates = pendingApprovals
    .filter((approval) => approval?.status === "pending")
    .filter((approval) => !event.session_id || !approval.session_id || approval.session_id === event.session_id)
    .slice(0, 3);
  if (!candidates.length) return "";
  const label = intent.action === "approval_approve" ? "Approve" : intent.action === "approval_review" ? "Review" : "Deny";
  return candidates
    .map(
      (approval) =>
        `<button type="button" class="secondary" data-channel-intent-event="${escapeHtml(event.id)}" data-channel-intent-approval="${escapeHtml(approval.id)}">${label} ${escapeHtml(shortId(approval.id))}</button>`
    )
    .join("");
};

const renderApprovalDetail = (approval) => {
  state.selectedApproval = approval;
  const node = document.getElementById("approval-detail");
  const payload = approval.payload || {};
  const step = payload.step || payload.action || {};
  const decision = approval.decision || {};
  const card = document.createElement("section");
  card.className = "approval-card";
  card.innerHTML = `
    <div class="task-card-header">
      <div>
        <span class="status-chip">${text(approval.status)}</span>
        <h4>${text(approval.reason)}</h4>
      </div>
    </div>
    <dl class="task-facts">
      <div><dt>Risk</dt><dd>${text(approval.risk_level)}</dd></div>
      <div><dt>Task</dt><dd>${text(shortId(approval.task_id))}</dd></div>
      <div><dt>Session</dt><dd>${text(approvalSessionLabel(approval))}</dd></div>
      <div><dt>Approval</dt><dd>${text(shortId(approval.id))}</dd></div>
      <div><dt>Operation</dt><dd>${text(step.operation || step.tool || step.connector || "unknown")}</dd></div>
    </dl>
    <div class="evidence-block">
      <strong>Requested Step</strong>
      <code>${text(JSON.stringify(step, null, 2))}</code>
    </div>
    <div class="evidence-block">
      <strong>Approval Payload</strong>
      <code>${text(JSON.stringify(payload, null, 2))}</code>
    </div>
    ${
      decision.status
        ? `<div class="evidence-block"><strong>Decision</strong><code>${text(JSON.stringify(decision, null, 2))}</code></div>`
        : ""
    }
    <div class="inline-form approval-decision-form">
      <input id="approval-actor" value="web-console" placeholder="actor">
      <input id="approval-reason" placeholder="decision reason">
      <label class="checkline"><input id="approval-admin" type="checkbox"> Admin</label>
    </div>
    <div class="item-actions">
      ${approval.task_id ? `<button type="button" class="secondary" data-task-evidence="${escapeHtml(approval.task_id)}">Task Evidence</button>` : ""}
      ${approval.session_id ? `<button type="button" class="secondary" data-approval-session="${escapeHtml(approval.session_id)}">Open Session</button>` : ""}
      <button type="button" data-approve="${escapeHtml(approval.id)}">Approve</button>
      <button type="button" class="secondary" data-deny="${escapeHtml(approval.id)}">Deny</button>
    </div>
  `;
  node.replaceChildren(card);
};

const renderMemories = (payload) => {
  setList("memories", payload.memories || [], (memory) => ({
    title: memory.content,
    detail: `${memory.type} · ${memory.source}`,
    meta: `${memory.sensitivity} · confidence ${memory.confidence} · ${memory.expires_at ? `expires ${memory.expires_at}` : "no expiry"}`,
    tone: memory.last_confirmed_at ? "ready" : "attention",
    actions: `
      <button type="button" class="secondary" data-memory-edit="${escapeHtml(memory.id)}" data-memory-content="${escapeHtml(memory.content)}" data-memory-confidence="${escapeHtml(memory.confidence)}">Edit</button>
      <button type="button" class="secondary" data-memory-merge-primary="${escapeHtml(memory.id)}">Primary</button>
      <button type="button" class="secondary" data-memory-merge-duplicate="${escapeHtml(memory.id)}">Duplicate</button>
      <button type="button" class="secondary" data-memory-resolve-primary="${escapeHtml(memory.id)}">Resolve Primary</button>
      <button type="button" class="secondary" data-memory-resolve-conflicting="${escapeHtml(memory.id)}">Resolve Conflict</button>
      <button type="button" class="secondary" data-memory-explain="${escapeHtml(memory.id)}">Explain</button>
      <button type="button" class="secondary" data-memory-expire="${escapeHtml(memory.id)}">Expire</button>
      <button type="button" class="secondary" data-memory-delete="${escapeHtml(memory.id)}">Delete</button>
    `,
  }), state.memoryQuery ? "No matching memories" : "Search to inspect governed memory");
};

const renderMemoryOutput = (payload) => {
  const node = document.getElementById("memory-output");
  if (Array.isArray(payload.items)) {
    const reviewIds = payload.items
      .filter((item) => item.kind === "memory_review" && item.memory_id)
      .map((item) => item.memory_id);
    const batchActions = reviewIds.length
      ? `
        <div class="item-actions">
          <button type="button" class="secondary" data-memory-review-batch="confirm">Confirm Selected</button>
          <button type="button" class="secondary" data-memory-review-batch="delete">Delete Selected</button>
        </div>
      `
      : "";
    const actions = payload.items
      .map((item) => {
        if (item.kind === "memory_review") {
          return `
            <div class="item-actions">
              <label class="checkline"><input type="checkbox" data-memory-review-select="${escapeHtml(item.memory_id)}"> Select</label>
              <button type="button" class="secondary" data-memory-review-confirm="${escapeHtml(item.memory_id)}">Confirm</button>
              <button type="button" class="secondary" data-memory-review-delete="${escapeHtml(item.memory_id)}">Delete</button>
            </div>
          `;
        }
        if (item.kind === "unresolved_conflict") {
          return `
            <div class="item-actions">
              <button type="button" class="secondary" data-memory-review-resolve-primary="${escapeHtml(item.primary_id)}" data-memory-review-resolve-conflicting="${escapeHtml(item.conflicting_id)}">Resolve</button>
            </div>
          `;
        }
        return "";
      })
      .join("");
    node.innerHTML = `
      <strong>Memory Review Queue</strong>
      <code>${text(JSON.stringify(payload, null, 2))}</code>
      ${batchActions}
      ${actions}
    `;
    return;
  }
  if (Array.isArray(payload.candidates)) {
    const candidateActions = payload.candidates
      .map((candidate) => `
        <label class="checkline">
          <input type="checkbox" data-memory-candidate-select="${escapeHtml(candidate.id)}" checked>
          ${text(candidate.id)} · ${text(candidate.summary || candidate.content || "")}
        </label>
      `)
      .join("");
    node.innerHTML = `
      <strong>${text(payload.mode || "Memory Candidates")}</strong>
      <code>${text(JSON.stringify(payload, null, 2))}</code>
      <div class="item-actions candidate-actions">
        ${candidateActions || "<span>No commit-ready candidates</span>"}
      </div>
    `;
    return;
  }
  node.innerHTML = `
    <strong>${text(payload.status || payload.type || payload.memory_id || "Memory")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const selectedMemoryCandidateIds = () => {
  const boxes = Array.from(document.querySelectorAll("#memory-output [data-memory-candidate-select]"));
  if (!boxes.length) {
    return null;
  }
  return boxes
    .filter((input) => input.checked)
    .map((input) => input.dataset.memoryCandidateSelect)
    .filter(Boolean);
};

const renderPolicyOutput = (payload) => {
  const node = document.getElementById("policy-output");
  const title = payload.decision?.decision || "Policy Profile";
  node.innerHTML = `
    <strong>${text(title)}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const renderSessionOutput = (payload) => {
  const node = document.getElementById("session-output");
  node.innerHTML = `
    <strong>${text(payload.title || "Session")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const renderScheduleOutput = (payload) => {
  const node = document.getElementById("schedule-output");
  node.innerHTML = `
    <strong>${text(payload.name || payload.status || "Schedule")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const renderEvaluationOutput = (payload) => {
  const node = document.getElementById("evaluation-output");
  node.innerHTML = `
    <strong>${text(payload.status || payload.id || "Evaluation")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const modelAuthDoctorDetail = (check = {}) => {
  const missingConfig = check.activation?.missing_config || [];
  return [
    check.external_command ? `provider ${check.external_command}` : "",
    check.login_command ? `login ${check.login_command}` : "",
    check.verify_command ? `verify ${check.verify_command}` : "",
    missingConfig.length ? `config ${missingConfig.join(", ")}` : "",
    check.setup_required ? `setup ${check.setup_required}` : "",
  ].filter(Boolean).join(" · ");
};

const modelAuthDoctorActions = (check = {}) =>
  [
    copyButton("Copy Login", check.login_command),
    copyButton("Copy Verify", check.verify_command),
  ].filter(Boolean).join("");

const modelAuthCommandActions = (auth = {}) =>
  [
    copyButton("Copy Login", auth.login_command || auth.external_command),
    copyButton("Copy Verify", auth.verify_command || auth.external_status_command),
  ].filter(Boolean).join("");

const modelAuthDoctorSummary = (doctor = {}) => {
  const counts = Object.entries(doctor.activation_state_counts || {})
    .map(([stateName, count]) => `${stateName}:${count}`)
    .join(" · ");
  const nextSteps = (doctor.next_steps || []).slice(0, 3);
  return `
    <dl class="task-facts">
      <div><dt>Status</dt><dd>${text(doctor.status || "unknown")}</dd></div>
      <div><dt>Login Needed</dt><dd>${text(doctor.operator_login_required_count || 0)}</dd></div>
      <div><dt>Verified</dt><dd>${text(doctor.verified_external_auth_count || 0)}</dd></div>
      <div><dt>Missing CLI</dt><dd>${text((doctor.missing_external_commands || []).join(", ") || "none")}</dd></div>
      <div><dt>States</dt><dd>${text(counts || "none")}</dd></div>
    </dl>
    <div class="next-action">Web requests never execute interactive provider login. Copy login and verify commands, run them in a local terminal, then verify the readiness packet.</div>
    ${nextSteps.length ? `<div class="evidence-block"><strong>Next Steps</strong>${nextSteps.map((step) => `<code>${text(step)}</code>`).join("")}</div>` : ""}
  `;
};

const modelAuthOutputSummary = (payload = {}) => {
  const doctor = payload.auth_doctor || (Array.isArray(payload.checks) ? payload : null);
  if (doctor) {
    return modelAuthDoctorSummary(doctor);
  }
  const auth = payload.auth || payload;
  if (auth && auth.method === "none") {
    return `
      <dl class="task-facts">
        <div><dt>Provider</dt><dd>${text(auth.provider || "unknown")}</dd></div>
        <div><dt>Method</dt><dd>No auth / local</dd></div>
        <div><dt>State</dt><dd>${text(auth.status || "no_auth_required")}</dd></div>
        <div><dt>Token Capture</dt><dd>not used</dd></div>
      </dl>
      <div class="next-action">This provider is local and does not require a stored API key or subscription login.</div>
    `;
  }
  if (!auth || !["subscription", "oauth", "oauth_device", "cloud_identity"].includes(auth.method)) {
    return "";
  }
  const stateLabel = auth.status === "external_login_requires_local_terminal" ? "Terminal handoff required" : auth.status || "External login";
  return `
    <dl class="task-facts">
      <div><dt>Provider</dt><dd>${text(auth.provider || "unknown")}</dd></div>
      <div><dt>Method</dt><dd>${text(auth.method)}</dd></div>
      <div><dt>State</dt><dd>${text(stateLabel)}</dd></div>
      <div><dt>Token Capture</dt><dd>${text(auth.token_capture_supported === false ? "denied" : "not used")}</dd></div>
    </dl>
    <div class="next-action">Run provider-owned login commands from a local terminal. The web console can show and copy commands, but it does not execute interactive provider login or accept browser/session tokens.</div>
  `;
};

const renderModelRouteOutput = (payload) => {
  const node = document.getElementById("model-route-output");
  node.innerHTML = `
    <strong>${text(payload.identifier || payload.alias || payload.events !== undefined ? "Model Control" : "Model")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const renderModelAuthOutput = (payload) => {
  const auth = payload.auth || payload;
  const packet = payload.packet && typeof payload.packet === "object" ? payload.packet : {};
  const receipt = payload.receipt && typeof payload.receipt === "object" ? payload.receipt : {};
  const readinessPacketRef = packet.packet_id || receipt.packet_id || payload.packet_id || "";
  const commandActions = modelAuthCommandActions(auth);
  const label = auth.external_command
    ? `${auth.status || "auth"} · ${auth.external_command}`
    : auth.provider || auth.status || payload.auth_doctor?.status || "Model auth";
  const readinessActions = `
    <div class="item-actions">
      <button type="button" class="secondary" data-model-auth-readiness-packet="1">Create Readiness Packet</button>
      ${readinessPacketRef ? `<button type="button" class="secondary" data-model-auth-verify-readiness-packet="${escapeHtml(readinessPacketRef)}">Verify Readiness Packet</button>` : ""}
    </div>
  `;
  const node = document.getElementById("model-auth-output");
  node.innerHTML = `
    <strong>${text(label)}</strong>
    ${modelAuthOutputSummary(payload)}
    ${commandActions ? `<div class="item-actions">${commandActions}</div>` : ""}
    ${readinessActions}
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const renderModelUsage = (payload) => {
  setList("model-usage-providers", payload.by_provider || [], (row) => ({
    title: row.key,
    detail: `${row.events} events · ${row.input_tokens} in · ${row.output_tokens} out`,
    meta: `$${Number(row.estimated_cost || 0).toFixed(6)} · latest ${row.latest_at || "n/a"}`,
  }), "No model usage by provider");
  setList("model-usage-models", payload.by_model || [], (row) => ({
    title: row.key,
    detail: `${row.events} events · ${row.input_tokens} in · ${row.output_tokens} out`,
    meta: `$${Number(row.estimated_cost || 0).toFixed(6)} · latest ${row.latest_at || "n/a"}`,
  }), "No model usage by model");
  setList("model-usage-events", payload.recent_events || [], (row) => ({
    title: `${row.provider}/${row.model}`,
    detail: `${row.input_tokens} in · ${row.output_tokens} out · ${row.created_at}`,
    meta: `${row.task_id ? `task ${shortId(row.task_id)}` : "no task"} · ${row.session_id ? `session ${shortId(row.session_id)}` : "no session"} · ${(row.metadata_keys || []).join(", ") || "no metadata"}`,
  }), "No recent model usage");
};

const syncPendingSkillEnableApprovals = (approvals) => {
  const next = {};
  approvals.forEach((approval) => {
    const payload = approval.payload || {};
    if (payload.kind === "skill_enable" && payload.skill_id && approval.id) {
      next[payload.skill_id] = { id: approval.id, status: approval.status || "pending" };
    }
  });
  state.pendingSkillEnable = next;
};

const renderTaskError = (message) => {
  const node = document.getElementById("task-output");
  const card = document.createElement("section");
  card.className = "task-card failed";
  card.innerHTML = `<div class="next-action">${text(message)}</div>`;
  node.replaceChildren(card);
};

const renderTaskNotice = (title, detail = "") => {
  const node = document.getElementById("task-output");
  const card = document.createElement("section");
  card.className = "task-card";
  card.innerHTML = `
    <div class="task-card-header">
      <div>
        <span class="status-chip">local</span>
        <h4>${text(title)}</h4>
      </div>
    </div>
    ${detail ? `<div class="next-action">${text(detail)}</div>` : ""}
  `;
  node.replaceChildren(card);
};

const selectedTaskId = () =>
  state.lastTask?.id || state.lastEvents?.task_id || state.lastEvidence?.task?.id || state.lastEvidence?.task_id || "";

const slashTaskId = (parsed) => String(parsed.request || "").trim().split(/\s+/, 1)[0] || selectedTaskId();

const slashApprovalId = (parsed) => String(parsed.request || "").trim().split(/\s+/, 1)[0];

const queueStatusTokens = new Set(["status", "show", "list", "active", "pending", "all", "session"]);

const executeQueueSlashCommand = async (parsed) => {
  const parts = String(parsed.request || "").trim().split(/\s+/).filter(Boolean);
  const action = parts[0] && !parts[0].startsWith("--") ? parts.shift().toLowerCase() : "status";
  if (action === "submit" || !queueStatusTokens.has(action)) {
    const request = action === "submit" ? parts.join(" ").trim() : String(parsed.request || "").trim();
    if (!request) {
      renderTaskNotice(parsed.label || "/queue", "Add a request after the queue command before sending.");
      return;
    }
    const path = document.getElementById("task-path").value || undefined;
    const result = await api("/tasks", { method: "POST", body: JSON.stringify({ request, path, session_id: state.activeSessionId }) });
    renderTaskResult(result);
    await refresh();
    renderTaskNotice(parsed.label || "/queue", `Queued task ${shortId(result.id)}.`);
    return;
  }
  state.activeSection = parsed.section || "activity";
  state.taskScope = action === "all" ? "all" : "session";
  if (action === "all") {
    state.inspectedTaskSessionId = null;
  } else if (action === "session" && parts[0]) {
    state.inspectedTaskSessionId = parts[0];
  }
  applySectionVisibility();
  await refresh();
  renderTaskNotice(parsed.label || "/queue", action === "all" ? "All-session task queue loaded." : "Active-session task queue loaded.");
};

const remoteControlSlashRequest = (request) => {
  const parts = String(request || "").trim().split(/\s+/).filter(Boolean);
  const action = (parts.shift() || "").toLowerCase();
  const options = {};
  const positionals = [];
  const query = new URLSearchParams();
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part.startsWith("--") && parts[index + 1] && !parts[index + 1].startsWith("--")) {
      options[part] = parts[index + 1];
      const queryKey = part.slice(2).replaceAll("-", "_");
      if (["pairing_id", "limit", "relay_url", "status"].includes(queryKey)) {
        query.set(queryKey, parts[index + 1]);
      }
      index += 1;
    } else if (!part.startsWith("--")) {
      positionals.push(part);
      if (action === "directory" && !query.has("pairing_id")) {
        query.set("pairing_id", part);
      }
    }
  }
  return { action, options, positionals, query: query.toString() };
};

const executeRemoteControlSlashCommand = async (parsed) => {
  const { action, options, positionals, query } = remoteControlSlashRequest(parsed.request);
  if (!action) return false;
  let path = "";
  if (action === "status") {
    path = "/remote-control/status";
  } else if (action === "directory") {
    path = `/remote-control/directory${query ? `?${query}` : ""}`;
  } else if (action === "relay") {
    path = `/remote-control/relay${query ? `?${query}` : ""}`;
  } else if (action === "relay-outbox") {
    path = `/remote-control/relay/outbox${query ? `?${query}` : ""}`;
  } else if (action === "pair") {
    const allowedActions = (options["--allowed-actions"] || document.getElementById("remote-control-actions").value)
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    const ttl = Number.parseInt(options["--expires-in-seconds"] || document.getElementById("remote-control-ttl").value || "600", 10);
    const payload = {
      label: options["--label"] || document.getElementById("remote-control-label").value || "web pairing",
      session_id: options["--session-id"] || document.getElementById("remote-control-session-id").value || undefined,
      task_id: options["--task-id"] || document.getElementById("remote-control-task-id").value || undefined,
      allowed_actions: allowedActions,
      expires_in_seconds: Number.isFinite(ttl) ? ttl : 600,
    };
    state.activeSection = "automation";
    applySectionVisibility();
    const payloadResult = await api("/remote-control/pair", { method: "POST", body: JSON.stringify(payload) });
    document.getElementById("remote-control-relay-outbox-id").value = payloadResult.outbox_id || "";
    renderRemoteControlOutput(payloadResult);
    await refresh();
    renderTaskNotice(parsed.label || "/remote-control", "Remote control pair created.");
    return true;
  } else if (action === "revoke") {
    const pairingId = options["--pairing-id"] || positionals[0] || document.getElementById("remote-control-relay-pairing-id").value.trim();
    if (!pairingId) {
      renderTaskNotice(parsed.label || "/remote-control", "Include a pairing id before revoking remote control.");
      return true;
    }
    state.activeSection = "automation";
    applySectionVisibility();
    const payloadResult = await api("/remote-control/revoke", { method: "POST", body: JSON.stringify({ pairing_id: pairingId }) });
    renderRemoteControlOutput(payloadResult);
    await refresh();
    renderTaskNotice(parsed.label || "/remote-control", `Remote control pairing ${pairingId} revoked.`);
    return true;
  } else {
    return false;
  }
  state.activeSection = "automation";
  applySectionVisibility();
  const payload = await api(path);
  if (action === "relay") renderRemoteControlRelay(payload);
  if (action === "relay-outbox") renderRemoteControlOutbox(payload);
  renderRemoteControlOutput(payload);
  renderTaskNotice(parsed.label || "/remote-control", `Remote control ${action} loaded.`);
  return true;
};

const executeLocalSlashCommand = async (parsed) => {
  if (parsed.kind === "queue-control") {
    await executeQueueSlashCommand(parsed);
    return;
  }
  if (parsed.kind === "approval-control") {
    const approvalId = slashApprovalId(parsed);
    const action = parsed.approvalAction || parsed.command;
    state.activeSection = "security";
    applySectionVisibility();
    if (!approvalId) {
      renderTaskNotice(`/${parsed.command || action}`, `Include an approval id, then run /${parsed.command || action} again.`);
      return;
    }
    if (action === "review") {
      await loadApprovalDetail(approvalId);
      renderTaskNotice(parsed.label || "/approval", `Approval ${approvalId} loaded.`);
    } else if (action === "approve" || action === "deny") {
      await api(`/approvals/${encodeURIComponent(approvalId)}/${action}`, { method: "POST", body: JSON.stringify(approvalDecisionPayload()) });
      document.getElementById("approval-detail").replaceChildren();
      await refresh();
      renderTaskNotice(`/${action}`, `Approval ${approvalId} ${action === "approve" ? "approved" : "denied"}.`);
    } else {
      renderTaskError(`unsupported approval action: ${action}`);
    }
    return;
  }
  if (parsed.kind === "task-control") {
    const taskId = slashTaskId(parsed);
    const action = parsed.taskAction || parsed.command;
    if (!taskId) {
      renderTaskNotice(`/${parsed.command || action}`, `Open a task or include a task id, then run /${parsed.command || action} again.`);
      return;
    }
    if (action === "resume") {
      await resumeTask(taskId);
    } else if (action === "pause") {
      await pauseTask(taskId);
    } else if (action === "cancel") {
      await cancelTask(taskId);
    } else {
      renderTaskError(`unsupported task action: ${action}`);
    }
    return;
  }
  if (parsed.kind === "task-inspection") {
    const taskId = slashTaskId(parsed);
    if (!taskId) {
      state.activeSection = parsed.taskView === "status" ? "activity" : "evidence";
      applySectionVisibility();
      renderTaskNotice(parsed.label || `/${parsed.command}`, "Open a task or include a task id, then run this command again.");
      return;
    }
    if (parsed.taskView === "status") {
      state.activeSection = "activity";
      applySectionVisibility();
      await loadTaskStatus(taskId);
      return;
    }
    if (parsed.taskView === "events") {
      await loadTaskEvents(taskId);
      return;
    }
    if (parsed.taskView === "timeline") {
      await loadTaskTimeline(taskId);
      return;
    }
    await loadTaskEvidence(taskId);
    return;
  }
  if (parsed.command === "remote-control") {
    if (String(parsed.request || "").trim() && await executeRemoteControlSlashCommand(parsed)) return;
    state.activeSection = parsed.section || "automation";
    applySectionVisibility();
    renderTaskNotice(parsed.label || "/remote-control", parsed.detail || "Open remote pairing and relay controls.");
    return;
  }
  if (parsed.kind === "section") {
    state.activeSection = parsed.section;
    applySectionVisibility();
    renderTaskNotice(parsed.label, parsed.detail);
    return;
  }
  if (parsed.kind === "palette") {
    renderSlashPalette();
    renderTaskNotice("/commands", "Type / plus a few letters, then use Tab or click a row to complete.");
    return;
  }
  renderTaskError(`unknown slash command: /${parsed.token || ""}`);
};

const renderBrowserOutput = (payload) => {
  const node = document.getElementById("browser-output");
  if (payload.status === "approval_required" && payload.approval_id && state.pendingBrowserAction) {
    state.pendingBrowserAction.approval_id = payload.approval_id;
  }
  const packet = payload.packet && typeof payload.packet === "object" ? payload.packet : {};
  const receipt = payload.receipt && typeof payload.receipt === "object" ? payload.receipt : {};
  const browserActivationPacketRef =
    (typeof payload.packet === "string" ? payload.packet : "") ||
    packet.packet_id ||
    receipt.packet_id ||
    payload.packet_id ||
    "";
  const interactiveElements = Array.isArray(payload.interactive_elements)
    ? payload.interactive_elements
    : Array.isArray(payload.session?.interactive_elements)
      ? payload.session.interactive_elements
      : [];
  const interactiveRows = interactiveElements.length
    ? `<div class="browser-elements">${interactiveElements
        .map((item) => {
          const selector = item.selector_hint || item.form_hint || item.tag || "";
          return `<button type="button" class="secondary browser-element" data-browser-selector="${escapeHtml(selector)}" data-browser-tag="${escapeHtml(item.tag || "")}" data-browser-label="${escapeHtml(item.label || "")}"><span>${text(item.tag || "element")}</span><strong>${text(item.label || selector || "element")}</strong><small>${text(selector)}</small></button>`;
        })
        .join("")}</div>`
    : "";
  const approvalAction =
    payload.status === "approval_required" && payload.approval_id
      ? `<div class="item-actions"><button type="button" class="secondary" data-browser-run-approved="${escapeHtml(payload.approval_id)}">Run Approved Action</button></div>`
      : "";
  const artifactLinks = [
    payload.artifact_url ? `<a class="button secondary" href="${escapeHtml(payload.artifact_url)}" target="_blank" rel="noopener">Open Snapshot</a>` : "",
    payload.metadata_url ? `<a class="button secondary" href="${escapeHtml(payload.metadata_url)}" target="_blank" rel="noopener">Open Metadata</a>` : "",
    payload.evidence_url ? `<a class="button secondary" href="${escapeHtml(payload.evidence_url)}" target="_blank" rel="noopener">Open Evidence</a>` : "",
  ].filter(Boolean).join("");
  const artifactActions = artifactLinks ? `<div class="item-actions">${artifactLinks}</div>` : "";
  const activationPacketActions = `
    <div class="item-actions">
      <button type="button" class="secondary" data-browser-live-activation-packet="1">Create Live Activation Packet</button>
      ${browserActivationPacketRef ? `<button type="button" class="secondary" data-browser-verify-activation-packet="${escapeHtml(browserActivationPacketRef)}">Verify Activation Packet</button>` : ""}
    </div>
  `;
  node.innerHTML = `
    <strong>${text(payload.ok ? "Browser Result" : payload.status || "Browser Notice")}</strong>
    <div class="muted">${text(payload.mode || "HTTP-content browser control; no rendered JavaScript DOM is available.")}</div>
    ${artifactActions}
    ${activationPacketActions}
    ${interactiveRows}
    <code>${text(JSON.stringify(payload, null, 2))}</code>
    ${approvalAction}
  `;
};

const renderToolRunOutput = (payload) => {
  const node = document.getElementById("tool-run-output");
  if (payload.status === "approval_required" && payload.approval_id && state.pendingToolRun) {
    state.pendingToolRun.approval_id = payload.approval_id;
  }
  const approvalAction =
    payload.status === "approval_required" && payload.approval_id
      ? `<div class="item-actions"><button type="button" class="secondary" data-tool-run-approved="${escapeHtml(payload.approval_id)}">Run Approved Tool</button></div>`
      : "";
  const artifactLinks = [
    payload.artifact_url ? `<a class="button secondary" href="${escapeHtml(payload.artifact_url)}" target="_blank" rel="noopener">Open Artifact</a>` : "",
    payload.metadata_url ? `<a class="button secondary" href="${escapeHtml(payload.metadata_url)}" target="_blank" rel="noopener">Open Metadata</a>` : "",
  ].filter(Boolean).join("");
  const artifactActions = artifactLinks ? `<div class="item-actions">${artifactLinks}</div>` : "";
  node.innerHTML = `
    <strong>${text(payload.status || (payload.ok === false ? "Tool Result" : "Tool Result"))}</strong>
    ${artifactActions}
    <code>${text(JSON.stringify(payload, null, 2))}</code>
    ${approvalAction}
  `;
};

const installToolRunPresets = () => {
  const node = document.getElementById("tool-run-presets");
  if (!node) return;
  node.replaceChildren(
    ...TOOL_RUN_PRESETS.map((preset) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "secondary";
      button.dataset.toolPreset = preset.name;
      button.textContent = preset.label;
      return button;
    })
  );
};

const renderMcpCallOutput = (payload) => {
  const node = document.getElementById("mcp-call-output");
  if (payload.status === "approval_required" && payload.approval_id && state.pendingMcpCall) {
    state.pendingMcpCall.approval_id = payload.approval_id;
  }
  const approvalAction =
    payload.status === "approval_required" && payload.approval_id
      ? `<div class="item-actions"><button type="button" class="secondary" data-mcp-run-approved="${escapeHtml(payload.approval_id)}">Run Approved MCP Call</button></div>`
      : "";
  node.innerHTML = `
    <strong>${text(payload.status || payload.tool || "MCP Result")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
    ${approvalAction}
  `;
};

const renderPluginOutput = (payload) => {
  if (payload.candidate_id) {
    state.pluginPreparedUpdateCandidateId = payload.candidate_id;
    const candidateInput = document.getElementById("plugin-prepared-candidate-id");
    if (candidateInput) candidateInput.value = payload.candidate_id;
  }
  const node = document.getElementById("plugin-output");
  node.innerHTML = `
    <strong>${text(payload.plugin?.name || payload.plugin?.id || payload.status || "Plugin")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const renderRemoteControlOutput = (payload) => {
  const node = document.getElementById("remote-control-output");
  node.innerHTML = `
    <strong>${text(payload.pairing?.label || payload.pairing?.id || payload.status || "Remote control")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const renderRemoteControlRelay = (payload = {}) => {
  const summary = document.getElementById("remote-control-relay-summary");
  summary.textContent = `${payload.status || "relay_preflight"} · outbound ${payload.outbound_relay_enabled ? "enabled" : "blocked"} · relay action ${payload.relay_action_proxy_enabled ? "enabled" : "blocked"} · target ${payload.relay_target || "not configured"}`;
  setList("remote-control-relay", payload.blockers || [], (x) => ({
    title: x.control,
    detail: x.detail,
    meta: payload.mode || "preflight_only",
    tone: "attention",
  }), "Relay preflight has no blockers");
};

const renderRemoteControlRelayPull = (payload = {}) => {
  const summary = document.getElementById("remote-control-relay-summary");
  const mode = payload.dry_run ? "preview" : "apply";
  summary.textContent = `${mode} · actions ${payload.action_count || 0} · executable ${payload.executable_action_count || 0} · executed ${payload.executed_action_count || 0} · target ${payload.relay_target || "not configured"}`;
  setList("remote-control-relay", payload.actions || [], (x) => ({
    title: `${x.action || "action"} · ${x.task_id || "no task"}`,
    detail: x.accepted ? "Accepted by local pairing scope" : x.rejection_reason || "Rejected by local pairing scope",
    meta: `${x.request_id || "no request id"} · ${payload.dry_run ? "preview only" : "apply requested"}`,
    tone: x.accepted ? "ready" : "attention",
  }), "Relay returned no queued actions");
  renderRemoteControlOutput(payload);
};

const renderRemoteControlOutbox = (payload = {}) => {
  const counts = payload.status_counts || {};
  const summary = Object.entries(counts)
    .map(([status, count]) => `${status}:${count}`)
    .join(" · ");
  setList("remote-control-relay-outbox", payload.items || [], (x) => ({
    title: x.event || x.id,
    detail: `Pairing ${x.pairing_id || "unknown"} · task ${x.task_id || "any"} · attempts ${x.attempt_count || 0}`,
    meta: `${x.status || "pending"} · ${x.updated_at || x.created_at || "not timestamped"}${summary ? ` · ${summary}` : ""}`,
    tone: x.status === "acknowledged" ? "ready" : "attention",
  }), "No relay notification outbox rows");
};

const renderChannelOutput = (payload) => {
  if (payload.receipt?.packet_id && String(payload.receipt?.receipt_schema || "").startsWith("aegis.channel.live_activation_packet")) {
    state.channelActivationPacketId = payload.receipt.packet_id;
  }
  const node = document.getElementById("channel-render-output");
  node.innerHTML = `
    <strong>${text(payload.status || "Channel Render")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const renderRepairAttemptOutput = (payload) => {
  const node = document.getElementById("repair-attempt-output");
  node.innerHTML = `
    <strong>${text(payload.status || payload.error || "Repair Attempt")}</strong>
    <code>${text(JSON.stringify(payload, null, 2))}</code>
  `;
};

const selectRepairProposal = (proposalId) => {
  state.selectedRepairProposalId = proposalId;
  document.getElementById("repair-proposal-id").value = proposalId;
  document.getElementById("repair-candidate-proposal-id").value = proposalId;
  document.getElementById("repair-apply-proposal-id").value = proposalId;
  document.getElementById("repair-review-proposal-id").value = proposalId;
  document.getElementById("repair-rollback-proposal-id").value = proposalId;
  state.activeSection = "evidence";
  applySectionVisibility();
};

const repairChangedFiles = () =>
  document
    .getElementById("repair-changed-files")
    .value.split(/[\n,]/)
    .map((value) => value.trim())
    .filter(Boolean);

const shortId = (value) => String(value || "").slice(0, 8);

const loadTaskStatus = async (taskId) => {
  const task = await api(`/tasks/${encodeURIComponent(taskId)}`);
  renderTaskResult(task);
  await refresh();
};

const loadTaskEvidence = async (taskId) => {
  const evidence = await api(`/tasks/${encodeURIComponent(taskId)}/evidence`);
  renderTaskEvidence(evidence);
  state.activeSection = "evidence";
  applySectionVisibility();
};

const loadTaskEventsSnapshot = async (taskId) => {
  const events = await api(`/tasks/${encodeURIComponent(taskId)}/events`);
  renderTaskEvents(events);
  state.activeSection = "evidence";
  applySectionVisibility();
};

const loadTaskEvents = async (taskId) => {
  try {
    await streamTaskEvents(taskId);
  } catch (error) {
    await loadTaskEventsSnapshot(taskId);
  }
};

const loadTaskTimeline = async (taskId) => {
  const timeline = await api(`/tasks/${encodeURIComponent(taskId)}/timeline`);
  renderTaskTimeline(timeline);
  state.activeSection = "evidence";
  applySectionVisibility();
};

const loadApprovalDetail = async (approvalId) => {
  const approval = await api(`/approvals/${encodeURIComponent(approvalId)}`);
  renderApprovalDetail(approval);
};

const openSession = async (sessionId) => {
  state.activeSessionId = sessionId;
  state.inspectedTaskSessionId = null;
  state.activeSection = "sessions";
  await refresh();
};

const resumeTask = async (taskId) => {
  const existingTask = await api(`/tasks/${encodeURIComponent(taskId)}`);
  const resumeSessionId = existingTask.session_id || state.activeSessionId || undefined;
  if (existingTask.session_id) {
    state.activeSessionId = existingTask.session_id;
  }
  const task = await api(`/tasks/${encodeURIComponent(taskId)}/resume`, {
    method: "POST",
    body: JSON.stringify({ session_id: resumeSessionId }),
  });
  renderTaskResult(task);
  await refresh();
};

const cancelTask = async (taskId) => {
  const existingTask = await api(`/tasks/${encodeURIComponent(taskId)}`);
  const cancelSessionId = existingTask.session_id || state.activeSessionId || undefined;
  if (existingTask.session_id) {
    state.activeSessionId = existingTask.session_id;
  }
  const task = await api(`/tasks/${encodeURIComponent(taskId)}/cancel`, {
    method: "POST",
    body: JSON.stringify({ session_id: cancelSessionId, reason: "Cancelled from web console" }),
  });
  renderTaskResult(task);
  await refresh();
};

const pauseTask = async (taskId) => {
  const existingTask = await api(`/tasks/${encodeURIComponent(taskId)}`);
  const pauseSessionId = existingTask.session_id || state.activeSessionId || undefined;
  if (existingTask.session_id) {
    state.activeSessionId = existingTask.session_id;
  }
  const task = await api(`/tasks/${encodeURIComponent(taskId)}/pause`, {
    method: "POST",
    body: JSON.stringify({ session_id: pauseSessionId, reason: "Paused from web console" }),
  });
  renderTaskResult(task);
  await refresh();
};

document.getElementById("refresh").addEventListener("click", refresh);

document.querySelector(".section-switcher").addEventListener("click", (event) => {
  const tab = event.target.dataset.sectionTab;
  if (!tab) return;
  state.activeSection = tab;
  applySectionVisibility();
});

const taskRequestInput = document.getElementById("task-request");

taskRequestInput.addEventListener("input", renderSlashPalette);

taskRequestInput.addEventListener("keydown", (event) => {
  const value = taskRequestInput.value.trimStart();
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    document.getElementById("task-form").requestSubmit();
    return;
  }
  if (!value.startsWith("/")) return;
  const matches = slashPaletteMatches(value).slice(0, 8);
  if (!matches.length) return;
  if (event.key === "ArrowDown") {
    event.preventDefault();
    state.slashSelectionIndex = (state.slashSelectionIndex + 1) % matches.length;
    renderSlashPalette();
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    state.slashSelectionIndex = (state.slashSelectionIndex + matches.length - 1) % matches.length;
    renderSlashPalette();
  } else if (event.key === "Tab") {
    event.preventDefault();
    applySlashCompletion(matches[state.slashSelectionIndex] || matches[0]);
  } else if (event.key === "Escape") {
    document.getElementById("slash-palette").hidden = true;
  }
});

document.getElementById("slash-palette").addEventListener("click", (event) => {
  const index = Number(event.target.closest("[data-slash-index]")?.dataset.slashIndex);
  const entry = Number.isInteger(index) ? state.slashPaletteEntries[index] : null;
  if (entry) {
    applySlashCompletion(entry);
  }
});

document.getElementById("task-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const input = document.getElementById("task-request");
    const parsed = parseTaskSlashCommand(input.value);
    if (!["task", "submit"].includes(parsed.kind)) {
      await executeLocalSlashCommand(parsed);
      return;
    }
    const request = (parsed.kind === "submit" ? parsed.request : input.value).trim() || (parsed.kind === "submit" ? "" : "Summarize my project safely");
    if (!request) {
      renderTaskNotice(parsed.label || "/submit", "Add a request after the slash command before sending.");
      return;
    }
    const path = document.getElementById("task-path").value || undefined;
    const result = await api("/tasks", { method: "POST", body: JSON.stringify({ request, path, session_id: state.activeSessionId }) });
    input.value = "";
    renderSlashPalette();
    renderTaskResult(result);
    await refresh();
  } catch (error) {
    renderTaskError(error.message);
  }
});

document.querySelectorAll("[data-task-scope]").forEach((button) => {
  button.addEventListener("click", async () => {
    state.taskScope = button.dataset.taskScope;
    await refresh();
  });
});

document.getElementById("session-message-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if (!state.activeSessionId) {
      const session = await api("/sessions", {
        method: "POST",
        body: JSON.stringify({ title: "Web session", channel: "web" }),
      });
      state.activeSessionId = session.id;
    }
    const content = document.getElementById("session-message-content").value.trim();
    if (!content) return;
    const message = await api(`/sessions/${encodeURIComponent(state.activeSessionId)}/messages`, {
      method: "POST",
      body: JSON.stringify({
        content,
        role: document.getElementById("session-message-role").value,
        trust_class: document.getElementById("session-message-trust").value,
        submit: false,
      }),
    });
    document.getElementById("session-message-content").value = "";
    renderSessionOutput(message);
    await refresh();
  } catch (error) {
    renderTaskError(error.message);
  }
});

document.getElementById("task-output").addEventListener("click", async (event) => {
  const statusId = event.target.dataset.taskStatus;
  const eventsId = event.target.dataset.taskEvents;
  const evidenceId = event.target.dataset.taskEvidence;
  const timelineId = event.target.dataset.taskTimeline;
  const resumeId = event.target.dataset.taskResume;
  const sessionId = event.target.dataset.taskSession;
  const pauseId = event.target.dataset.taskPause;
  const cancelId = event.target.dataset.taskCancel;
  const copyId = event.target.dataset.copyId;
  if (statusId) {
    await loadTaskStatus(statusId);
  }
  if (eventsId) {
    await loadTaskEvents(eventsId);
  }
  if (evidenceId) {
    await loadTaskEvidence(evidenceId);
  }
  if (timelineId) {
    await loadTaskTimeline(timelineId);
  }
  if (resumeId) {
    await resumeTask(resumeId);
  }
  if (sessionId) {
    await openSession(sessionId);
  }
  if (pauseId) {
    await pauseTask(pauseId);
  }
  if (cancelId) {
    await cancelTask(cancelId);
  }
  if (copyId && navigator.clipboard) {
    await navigator.clipboard.writeText(copyId);
  }
});

document.getElementById("tasks").addEventListener("click", async (event) => {
  const statusId = event.target.dataset.taskStatus;
  const eventsId = event.target.dataset.taskEvents;
  const evidenceId = event.target.dataset.taskEvidence;
  const timelineId = event.target.dataset.taskTimeline;
  const resumeId = event.target.dataset.taskResume;
  const sessionId = event.target.dataset.taskSession;
  const pauseId = event.target.dataset.taskPause;
  const cancelId = event.target.dataset.taskCancel;
  if (statusId) {
    await loadTaskStatus(statusId);
  }
  if (eventsId) {
    await loadTaskEvents(eventsId);
  }
  if (evidenceId) {
    await loadTaskEvidence(evidenceId);
  }
  if (timelineId) {
    await loadTaskTimeline(timelineId);
  }
  if (resumeId) {
    await resumeTask(resumeId);
  }
  if (sessionId) {
    await openSession(sessionId);
  }
  if (pauseId) {
    await pauseTask(pauseId);
  }
  if (cancelId) {
    await cancelTask(cancelId);
  }
});

document.getElementById("task-evidence").addEventListener("click", async (event) => {
  const sessionId = event.target.dataset.taskSession;
  if (sessionId) {
    await openSession(sessionId);
  }
  const copyId = event.target.dataset.copyId;
  if (copyId && navigator.clipboard) {
    await navigator.clipboard.writeText(copyId);
  }
});

document.getElementById("task-events").addEventListener("click", async (event) => {
  const sessionId = event.target.dataset.taskSession;
  if (sessionId) {
    await openSession(sessionId);
  }
});

document.getElementById("task-timeline").addEventListener("click", async (event) => {
  const sessionId = event.target.dataset.taskSession;
  if (sessionId) {
    await openSession(sessionId);
  }
});

document.getElementById("approvals").addEventListener("click", async (event) => {
  const review = event.target.dataset.approvalReview;
  const sessionId = event.target.dataset.approvalSession;
  const approve = event.target.dataset.approve;
  const deny = event.target.dataset.deny;
  if (review) {
    await loadApprovalDetail(review);
  }
  if (sessionId) {
    await openSession(sessionId);
  }
  if (approve) {
    await api(`/approvals/${approve}/approve`, { method: "POST", body: JSON.stringify(approvalDecisionPayload()) });
    document.getElementById("approval-detail").replaceChildren();
    await refresh();
  }
  if (deny) {
    await api(`/approvals/${deny}/deny`, { method: "POST", body: JSON.stringify(approvalDecisionPayload()) });
    document.getElementById("approval-detail").replaceChildren();
    await refresh();
  }
});

document.getElementById("approval-decisions").addEventListener("click", async (event) => {
  const review = event.target.dataset.approvalReview;
  const sessionId = event.target.dataset.approvalSession;
  if (review) {
    await loadApprovalDetail(review);
  }
  if (sessionId) {
    await openSession(sessionId);
  }
});

document.getElementById("channel-events").addEventListener("click", async (event) => {
  const eventId = event.target.dataset.channelIntentEvent;
  const approvalId = event.target.dataset.channelIntentApproval;
  if (!eventId || !approvalId) return;
  await api("/channels/approval-intent/resolve", {
    method: "POST",
    body: JSON.stringify({
      event_id: eventId,
      approval_id: approvalId,
      ...approvalDecisionPayload(),
    }),
  });
  await refresh();
});

document.getElementById("approval-detail").addEventListener("click", async (event) => {
  const evidenceId = event.target.dataset.taskEvidence;
  const sessionId = event.target.dataset.approvalSession;
  const approve = event.target.dataset.approve;
  const deny = event.target.dataset.deny;
  if (evidenceId) {
    await loadTaskEvidence(evidenceId);
  }
  if (sessionId) {
    await openSession(sessionId);
  }
  if (approve) {
    await api(`/approvals/${approve}/approve`, { method: "POST", body: JSON.stringify(approvalDecisionPayload()) });
    document.getElementById("approval-detail").replaceChildren();
    await refresh();
  }
  if (deny) {
    await api(`/approvals/${deny}/deny`, { method: "POST", body: JSON.stringify(approvalDecisionPayload()) });
    document.getElementById("approval-detail").replaceChildren();
    await refresh();
  }
});

document.getElementById("improvements").addEventListener("click", async (event) => {
  const selectId = event.target.dataset.improvementSelect;
  const proposalId = event.target.dataset.improvementReview;
  const approveId = event.target.dataset.improvementApprove;
  const implementId = event.target.dataset.improvementImplement;
  if (selectId) {
    selectRepairProposal(selectId);
  }
  if (proposalId) {
    await api(`/improvements/${proposalId}/status`, { method: "POST", body: JSON.stringify({ status: "reviewing" }) });
    await refresh();
  }
  if (approveId) {
    await api(`/improvements/${approveId}/status`, { method: "POST", body: JSON.stringify({ status: "approved" }) });
    await refresh();
  }
  if (implementId) {
    selectRepairProposal(implementId);
    document.getElementById("repair-outcome").focus();
  }
});

document.getElementById("repair-attempt-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const proposalId = document.getElementById("repair-proposal-id").value || state.selectedRepairProposalId;
  if (!proposalId) {
    renderRepairAttemptOutput({ status: "missing_proposal", reason: "Repair proposal id is required." });
    return;
  }
  const result = await api(`/improvements/${encodeURIComponent(proposalId)}/attempts`, {
    method: "POST",
    body: JSON.stringify({
      outcome: document.getElementById("repair-outcome").value || "Repair reviewed and verified from the web console.",
      status: "implemented",
      actor: "web-console",
      candidate_id: document.getElementById("repair-candidate-id").value || undefined,
      changed_files: repairChangedFiles(),
      test_command: document.getElementById("repair-test-command").value,
      test_result: document.getElementById("repair-test-result").value || "passed",
    }),
  });
  renderRepairAttemptOutput(result);
  await refresh();
});

document.getElementById("repair-candidate-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const proposalId = document.getElementById("repair-candidate-proposal-id").value || state.selectedRepairProposalId;
  if (!proposalId) {
    renderRepairAttemptOutput({ status: "missing_proposal", reason: "Repair proposal id is required." });
    return;
  }
  const result = await api(`/improvements/${encodeURIComponent(proposalId)}/candidates`, {
    method: "POST",
    body: JSON.stringify({
      summary: document.getElementById("repair-candidate-summary").value || "Repair candidate from web console.",
      actor: "web-console",
      changed_files: document.getElementById("repair-candidate-files").value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean),
      patch_plan: document.getElementById("repair-candidate-plan").value || "",
      unified_diff: document.getElementById("repair-candidate-diff").value || "",
    }),
  });
  const candidates = result.metadata?.repair_candidates || [];
  const candidate = candidates[candidates.length - 1];
  if (candidate?.id) {
    document.getElementById("repair-candidate-id").value = candidate.id;
    document.getElementById("repair-apply-candidate-id").value = candidate.id;
    document.getElementById("repair-review-candidate-id").value = candidate.id;
    document.getElementById("repair-rollback-candidate-id").value = candidate.id;
  }
  renderRepairAttemptOutput(result);
  await refresh();
});

document.getElementById("repair-generate-candidate").addEventListener("click", async () => {
  const proposalId = document.getElementById("repair-candidate-proposal-id").value || state.selectedRepairProposalId;
  if (!proposalId) {
    renderRepairAttemptOutput({ status: "missing_proposal", reason: "Repair proposal id is required." });
    return;
  }
  const result = await api(`/improvements/${encodeURIComponent(proposalId)}/candidates/generate`, {
    method: "POST",
    body: JSON.stringify({ actor: "web-console" }),
  });
  const candidates = result.metadata?.repair_candidates || [];
  const candidate = candidates[candidates.length - 1];
  if (candidate?.id) {
    document.getElementById("repair-candidate-id").value = candidate.id;
    document.getElementById("repair-apply-candidate-id").value = candidate.id;
    document.getElementById("repair-review-candidate-id").value = candidate.id;
    document.getElementById("repair-rollback-candidate-id").value = candidate.id;
  }
  renderRepairAttemptOutput(result);
  await refresh();
});

document.getElementById("repair-synthesis-prompt").addEventListener("click", async () => {
  const proposalId = document.getElementById("repair-candidate-proposal-id").value || state.selectedRepairProposalId;
  if (!proposalId) {
    renderRepairAttemptOutput({ status: "missing_proposal", reason: "Repair proposal id is required." });
    return;
  }
  const result = await api(`/improvements/${encodeURIComponent(proposalId)}/synthesis-prompt`, {
    method: "POST",
    body: JSON.stringify({ actor: "web-console" }),
  });
  if (result.prompt_id) {
    document.getElementById("repair-synthesis-prompt-id").value = result.prompt_id;
  }
  renderRepairAttemptOutput(result);
  await refresh();
});

document.getElementById("repair-synthesize-candidate").addEventListener("click", async () => {
  const proposalId = document.getElementById("repair-candidate-proposal-id").value || state.selectedRepairProposalId;
  if (!proposalId) {
    renderRepairAttemptOutput({ status: "missing_proposal", reason: "Repair proposal id is required." });
    return;
  }
  const result = await api(`/improvements/${encodeURIComponent(proposalId)}/candidates/synthesize`, {
    method: "POST",
    body: JSON.stringify({
      actor: "web-console",
      synthesis: {
        prompt_id: document.getElementById("repair-synthesis-prompt-id").value || undefined,
        summary: document.getElementById("repair-candidate-summary").value || "Synthesized repair candidate from web console.",
        patch_plan: document.getElementById("repair-candidate-plan").value || "Apply the provided unified diff after review.",
        changed_files: document.getElementById("repair-candidate-files").value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean),
        unified_diff: document.getElementById("repair-candidate-diff").value || "",
        source: "web-console",
      },
    }),
  });
  const candidates = result.metadata?.repair_candidates || [];
  const candidate = candidates[candidates.length - 1];
  if (candidate?.id) {
    document.getElementById("repair-candidate-id").value = candidate.id;
    document.getElementById("repair-apply-candidate-id").value = candidate.id;
    document.getElementById("repair-review-candidate-id").value = candidate.id;
    document.getElementById("repair-rollback-candidate-id").value = candidate.id;
  }
  renderRepairAttemptOutput(result);
  await refresh();
});

document.getElementById("repair-candidate-review-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const proposalId = document.getElementById("repair-review-proposal-id").value || document.getElementById("repair-apply-proposal-id").value || state.selectedRepairProposalId;
  const candidateId = document.getElementById("repair-review-candidate-id").value || document.getElementById("repair-apply-candidate-id").value || document.getElementById("repair-candidate-id").value;
  if (!proposalId || !candidateId) {
    renderRepairAttemptOutput({ status: "missing_candidate", reason: "Repair proposal id and candidate id are required." });
    return;
  }
  const result = await api(`/improvements/${encodeURIComponent(proposalId)}/candidates/${encodeURIComponent(candidateId)}/review`, {
    method: "POST",
    body: JSON.stringify({ actor: "web-console", status: document.getElementById("repair-review-status").value }),
  });
  renderRepairAttemptOutput(result);
  await refresh();
});

document.getElementById("repair-apply-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const proposalId = document.getElementById("repair-apply-proposal-id").value || state.selectedRepairProposalId;
  const candidateId = document.getElementById("repair-apply-candidate-id").value || document.getElementById("repair-candidate-id").value;
  if (!proposalId || !candidateId) {
    renderRepairAttemptOutput({ status: "missing_candidate", reason: "Repair proposal id and candidate id are required." });
    return;
  }
  const result = await api(`/improvements/${encodeURIComponent(proposalId)}/candidates/${encodeURIComponent(candidateId)}/apply`, {
    method: "POST",
    body: JSON.stringify({ actor: "web-console" }),
  });
  renderRepairAttemptOutput(result);
  await refresh();
});

document.getElementById("repair-rollback-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const proposalId = document.getElementById("repair-rollback-proposal-id").value || state.selectedRepairProposalId;
  const candidateId = document.getElementById("repair-rollback-candidate-id").value || document.getElementById("repair-candidate-id").value;
  if (!proposalId || !candidateId) {
    renderRepairAttemptOutput({ status: "missing_candidate", reason: "Repair proposal id and candidate id are required." });
    return;
  }
  const result = await api(`/improvements/${encodeURIComponent(proposalId)}/candidates/${encodeURIComponent(candidateId)}/rollback`, {
    method: "POST",
    body: JSON.stringify({ actor: "web-console" }),
  });
  renderRepairAttemptOutput(result);
  await refresh();
});

const localNoAuthModelProviders = new Set(["ollama", "lmstudio"]);

const syncModelAuthMethodForProvider = () => {
  const provider = document.getElementById("model-provider").value;
  const method = document.getElementById("model-auth-method");
  if (localNoAuthModelProviders.has(provider) && method.value === "api_key") {
    method.value = "none";
  } else if (!localNoAuthModelProviders.has(provider) && method.value === "none") {
    method.value = "api_key";
  }
};

document.getElementById("model-provider").addEventListener("change", syncModelAuthMethodForProvider);
syncModelAuthMethodForProvider();

document.getElementById("model-auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  syncModelAuthMethodForProvider();
  const provider = document.getElementById("model-provider").value;
  const method = document.getElementById("model-auth-method").value;
  const apiKey = document.getElementById("model-api-key").value;
  const payload = { provider, method };
  if (method === "none") {
    // Local providers should never send placeholder key material.
  } else if (method === "api_key") {
    payload.api_key = apiKey;
  } else {
    payload.verify_external = document.getElementById("model-auth-verify-external").checked;
    payload.run_external = document.getElementById("model-auth-run-external").checked;
  }
  const result = await api("/models/auth/login", { method: "POST", body: JSON.stringify(payload) });
  renderModelAuthOutput(result);
  document.getElementById("model-api-key").value = "";
  await refresh();
});

document.getElementById("model-auth-logout").addEventListener("click", async () => {
  const provider = document.getElementById("model-provider").value;
  const result = await api("/models/auth/logout", { method: "POST", body: JSON.stringify({ provider }) });
  renderModelAuthOutput(result);
  await refresh();
});

document.getElementById("model-auth-doctor-run").addEventListener("click", async () => {
  renderModelAuthOutput({ auth_doctor: await api("/models/auth/doctor") });
  await refresh();
});

document.getElementById("model-auth-readiness-packet").addEventListener("click", async () => {
  renderModelAuthOutput(await api("/models/auth/readiness-packet", { method: "POST", body: JSON.stringify({ actor: "web-operator" }) }));
  await refresh();
});

const copyModelAuthCommand = async (target) => {
  const command = target.closest("[data-copy-command]")?.dataset.copyCommand;
  if (!command) return false;
  if (navigator.clipboard) {
    await navigator.clipboard.writeText(command);
  }
  renderModelAuthOutput({
    status: "command_copied",
    command,
    note: "Run this command from a local terminal. The web console did not execute provider login.",
  });
  return true;
};

document.getElementById("model-auth-doctor").addEventListener("click", async (event) => {
  await copyModelAuthCommand(event.target);
});

document.getElementById("model-auth-output").addEventListener("click", async (event) => {
  if (await copyModelAuthCommand(event.target)) {
    return;
  }
  const createPacket = event.target.closest("[data-model-auth-readiness-packet]");
  if (createPacket) {
    renderModelAuthOutput(await api("/models/auth/readiness-packet", { method: "POST", body: JSON.stringify({ actor: "web-operator" }) }));
    await refresh();
    return;
  }
  const verifyPacket = event.target.closest("[data-model-auth-verify-readiness-packet]");
  if (verifyPacket) {
    renderModelAuthOutput(
      await api("/models/auth/verify-readiness-packet", {
        method: "POST",
        body: JSON.stringify({ packet: verifyPacket.dataset.modelAuthVerifyReadinessPacket, actor: "web-operator" }),
      })
    );
    await refresh();
  }
});

document.getElementById("model-route-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const identifier = document.getElementById("model-route-id").value || "alias/smart";
  renderModelRouteOutput(await api(`/models/route?identifier=${encodeURIComponent(identifier)}`));
  await refresh();
});

document.getElementById("model-alias-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/models/alias", {
    method: "POST",
    body: JSON.stringify({
      alias: document.getElementById("model-alias-name").value || "web",
      identifier: document.getElementById("model-alias-target").value || "ollama/llama3",
    }),
  });
  renderModelRouteOutput(result);
  await refresh();
});

document.getElementById("model-fallbacks-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const fallbacks = document
    .getElementById("model-fallbacks-list")
    .value.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const result = await api("/models/fallbacks", {
    method: "POST",
    body: JSON.stringify({
      identifier: document.getElementById("model-fallbacks-id").value || "ollama/llama3",
      fallbacks,
    }),
  });
  renderModelRouteOutput(result);
  await refresh();
});

document.getElementById("model-usage-refresh").addEventListener("click", async () => {
  const usage = await api("/model-usage");
  renderModelRouteOutput(usage);
  renderModelUsage(usage);
});

document.getElementById("channel-render-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/channels/render", {
    method: "POST",
    body: JSON.stringify({
      channel: document.getElementById("channel-render-name").value || "web",
      text: document.getElementById("channel-render-text").value || "",
      metadata: { session_id: state.activeSessionId || undefined },
    }),
  });
  renderChannelOutput(result);
  await refresh();
});

document.getElementById("channel-receive-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/channels/receive", {
    method: "POST",
    body: JSON.stringify({
      channel: document.getElementById("channel-receive-name").value || "web",
      text: document.getElementById("channel-receive-text").value || "",
      sender: "web-user",
      session_id: state.activeSessionId || undefined,
    }),
  });
  renderChannelOutput(result);
  await refresh();
});

document.getElementById("channel-webhook-send-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/channels/webhook/send", {
    method: "POST",
    body: JSON.stringify({
      text: document.getElementById("channel-webhook-send-text").value || "",
      approved: document.getElementById("channel-webhook-send-approved").checked,
      session_id: state.activeSessionId || undefined,
    }),
  });
  renderChannelOutput(result);
  await refresh();
});

document.getElementById("channel-chat-webhook-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/channels/chat-webhook/send", {
    method: "POST",
    body: JSON.stringify({
      text: document.getElementById("channel-chat-webhook-text").value || "",
      approved: document.getElementById("channel-chat-webhook-approved").checked,
      session_id: state.activeSessionId || undefined,
    }),
  });
  renderChannelOutput(result);
  await refresh();
});

document.getElementById("channel-email-send-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/channels/email/send", {
    method: "POST",
    body: JSON.stringify({
      subject: document.getElementById("channel-email-send-subject").value || "Aegis update",
      text: document.getElementById("channel-email-send-text").value || "",
      approved: document.getElementById("channel-email-send-approved").checked,
      session_id: state.activeSessionId || undefined,
    }),
  });
  renderChannelOutput(result);
  await refresh();
});

document.getElementById("channel-live-activation-packet").addEventListener("click", async () => {
  const result = await api("/channels/live-activation-packet", {
    method: "POST",
    body: JSON.stringify({ actor: "web-operator" }),
  });
  renderChannelOutput(result);
});

document.getElementById("channel-verify-activation-packet").addEventListener("click", async () => {
  const activationPacket = state.channelActivationPacketId;
  const result = await api("/channels/verify-activation-packet", {
    method: "POST",
    body: JSON.stringify({ packet: activationPacket, actor: "web-operator" }),
  });
  renderChannelOutput(result);
});

document.getElementById("policy-evaluate-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const scopes = document.getElementById("policy-scopes").value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const targetDomain = document.getElementById("policy-domain").value.trim();
  const payload = {
    operation: document.getElementById("policy-operation").value || "read",
    risk_level: document.getElementById("policy-risk").value,
    requested_scopes: scopes,
    target_domain: targetDomain || undefined,
  };
  renderPolicyOutput(await api("/policy/evaluate", { method: "POST", body: JSON.stringify(payload) }));
});

document.getElementById("policy-bundles").addEventListener("click", async (event) => {
  const diffSource = event.target.dataset.policyDiff;
  if (diffSource) {
    renderPolicyOutput(await api("/policy/diff-bundle", { method: "POST", body: JSON.stringify({ source: diffSource }) }));
    return;
  }
  const source = event.target.dataset.policyApply;
  if (!source) return;
  renderPolicyOutput(await api("/policy/apply-bundle", { method: "POST", body: JSON.stringify({ source, approved: true }) }));
  await refresh();
});

document.getElementById("policy-rollback").addEventListener("click", async () => {
  renderPolicyOutput(await api("/policy/rollback-bundle", { method: "POST", body: JSON.stringify({ approved: true }) }));
  await refresh();
});

document.getElementById("policy-schedule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    source: document.getElementById("policy-schedule-source").value || "strict-local",
    activate_at: document.getElementById("policy-schedule-activate-at").value,
    environment: document.getElementById("policy-schedule-environment").value || "local",
    approved: document.getElementById("policy-schedule-approved").checked,
  };
  renderPolicyOutput(await api("/policy/schedule-bundle", { method: "POST", body: JSON.stringify(payload) }));
  await refresh();
});

document.getElementById("policy-promote-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    source: document.getElementById("policy-promote-source").value || "strict-local",
    from_environment: document.getElementById("policy-promote-from").value || "staging",
    to_environment: document.getElementById("policy-promote-to").value || "production",
    approved: document.getElementById("policy-promote-approved").checked,
    require_clean_evaluation: document.getElementById("policy-promote-clean-evaluation").checked,
    require_live_parity: document.getElementById("policy-promote-live-parity").checked,
    baseline_report_id: document.getElementById("policy-promote-baseline").value || undefined,
    candidate_report_id: document.getElementById("policy-promote-candidate").value || undefined,
    deferred_live_gap_areas: document.getElementById("policy-promote-defer-live-gap").value.split(",").map((area) => area.trim()).filter(Boolean),
    live_gap_deferral_reason: document.getElementById("policy-promote-deferral-reason").value || undefined,
  };
  renderPolicyOutput(await api("/policy/promote-bundle", { method: "POST", body: JSON.stringify(payload) }));
  await refresh();
});

document.getElementById("policy-rollouts").addEventListener("click", async () => {
  renderPolicyOutput(await api("/policy/rollouts"));
});

document.getElementById("policy-promotions").addEventListener("click", async () => {
  renderPolicyOutput(await api("/policy/promotions"));
});

document.getElementById("policy-activate-due").addEventListener("click", async () => {
  renderPolicyOutput(await api("/policy/activate-due", { method: "POST", body: JSON.stringify({}) }));
  await refresh();
});

document.getElementById("remote-control-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const allowedActions = document.getElementById("remote-control-actions").value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const ttl = Number.parseInt(document.getElementById("remote-control-ttl").value || "600", 10);
  const result = await api("/remote-control/pair", {
    method: "POST",
    body: JSON.stringify({
      label: document.getElementById("remote-control-label").value || "web pairing",
      session_id: document.getElementById("remote-control-session-id").value || undefined,
      task_id: document.getElementById("remote-control-task-id").value || undefined,
      allowed_actions: allowedActions,
      expires_in_seconds: Number.isFinite(ttl) ? ttl : 600,
    }),
  });
  document.getElementById("remote-control-relay-outbox-id").value = result.outbox_id || "";
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("remote-control-relay-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const relayUrl = document.getElementById("remote-control-relay-url").value.trim();
  const approved = document.getElementById("remote-control-relay-approved").checked;
  let result;
  if (approved) {
    result = await api("/remote-control/relay", {
      method: "POST",
      body: JSON.stringify({
        relay_url: relayUrl,
        pairing_id: document.getElementById("remote-control-relay-pairing-id").value.trim(),
        relay_auth_secret: document.getElementById("remote-control-relay-secret").value.trim(),
        approved: true,
      }),
    });
  } else {
    result = await api(`/remote-control/relay${relayUrl ? `?relay_url=${encodeURIComponent(relayUrl)}` : ""}`);
  }
  renderRemoteControlRelay(result);
  renderRemoteControlOutput(result);
});

const remoteControlRelayBody = () => ({
  pairing_id: document.getElementById("remote-control-relay-pairing-id").value.trim(),
  relay_auth_secret: document.getElementById("remote-control-relay-secret").value.trim(),
  approved: document.getElementById("remote-control-relay-approved").checked,
});

const remoteControlPushBody = () => ({
  label: document.getElementById("remote-control-push-label").value.trim() || "native push",
  target_id: document.getElementById("remote-control-push-target-id").value.trim() || undefined,
  provider: document.getElementById("remote-control-push-provider").value,
  push_auth_secret: document.getElementById("remote-control-push-secret").value.trim(),
  device_token_secret: document.getElementById("remote-control-device-secret").value.trim(),
  approved: document.getElementById("remote-control-push-approved").checked,
  apns_topic: document.getElementById("remote-control-apns-topic").value.trim() || undefined,
  fcm_project_id: document.getElementById("remote-control-fcm-project").value.trim() || undefined,
});

document.getElementById("remote-control-relay-directory").addEventListener("click", async () => {
  const result = await api("/remote-control/relay/directory", {
    method: "POST",
    body: JSON.stringify({
      ...remoteControlRelayBody(),
      limit: 12,
    }),
  });
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("remote-control-relay-notify").addEventListener("click", async () => {
  const taskId = document.getElementById("remote-control-relay-task-id").value.trim();
  const result = await api("/remote-control/relay/notify", {
    method: "POST",
    body: JSON.stringify({
      ...remoteControlRelayBody(),
      event: document.getElementById("remote-control-relay-event").value.trim() || "directory-updated",
      task_id: taskId || undefined,
    }),
  });
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("remote-control-push-register").addEventListener("click", async () => {
  const result = await api("/remote-control/push/register", {
    method: "POST",
    body: JSON.stringify(remoteControlPushBody()),
  });
  document.getElementById("remote-control-push-target-id").value = result.target?.id || "";
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("remote-control-push-rotate").addEventListener("click", async () => {
  const pushBody = remoteControlPushBody();
  const result = await api("/remote-control/push/rotate", {
    method: "POST",
    body: JSON.stringify({
      target_id: pushBody.target_id,
      push_auth_secret: pushBody.push_auth_secret || undefined,
      device_token_secret: pushBody.device_token_secret || undefined,
      approved: pushBody.approved,
      apns_topic: pushBody.apns_topic,
      fcm_project_id: pushBody.fcm_project_id,
    }),
  });
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("remote-control-push-disable").addEventListener("click", async () => {
  const result = await api("/remote-control/push/disable", {
    method: "POST",
    body: JSON.stringify({
      target_id: document.getElementById("remote-control-push-target-id").value.trim(),
      approved: document.getElementById("remote-control-push-approved").checked,
    }),
  });
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("remote-control-native-push").addEventListener("click", async () => {
  const taskId = document.getElementById("remote-control-relay-task-id").value.trim();
  const pushBody = remoteControlPushBody();
  const result = await api("/remote-control/push", {
    method: "POST",
    body: JSON.stringify({
      pairing_id: document.getElementById("remote-control-relay-pairing-id").value.trim(),
      target_id: pushBody.target_id,
      provider: pushBody.provider,
      push_auth_secret: pushBody.push_auth_secret,
      device_token_secret: pushBody.device_token_secret,
      approved: pushBody.approved,
      event: document.getElementById("remote-control-relay-event").value.trim() || "directory-updated",
      task_id: taskId || undefined,
      apns_topic: pushBody.apns_topic,
      fcm_project_id: pushBody.fcm_project_id,
    }),
  });
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("remote-control-relay-outbox-refresh").addEventListener("click", async () => {
  const result = await api("/remote-control/relay/outbox");
  renderRemoteControlOutbox(result);
  renderRemoteControlOutput(result);
});

document.getElementById("remote-control-relay-retry").addEventListener("click", async () => {
  const result = await api("/remote-control/relay/retry", {
    method: "POST",
    body: JSON.stringify({
      ...remoteControlRelayBody(),
      limit: 10,
    }),
  });
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("remote-control-relay-confirm").addEventListener("click", async () => {
  const result = await api("/remote-control/relay/confirm", {
    method: "POST",
    body: JSON.stringify({
      ...remoteControlRelayBody(),
      outbox_id: document.getElementById("remote-control-relay-outbox-id").value.trim(),
    }),
  });
  renderRemoteControlOutput(result);
  await refresh();
});

const pullRemoteControlRelayActions = async ({ dryRun }) => {
  const result = await api("/remote-control/relay/pull", {
    method: "POST",
    body: JSON.stringify({
      ...remoteControlRelayBody(),
      dry_run: dryRun,
      limit: 10,
    }),
  });
  document.getElementById("remote-control-relay-dry-run").checked = dryRun;
  await refresh();
  renderRemoteControlRelayPull(result);
};

document.getElementById("remote-control-relay-preview").addEventListener("click", async () => {
  await pullRemoteControlRelayActions({ dryRun: true });
});

document.getElementById("remote-control-relay-apply").addEventListener("click", async () => {
  await pullRemoteControlRelayActions({ dryRun: false });
});

document.getElementById("remote-control-directory").addEventListener("click", async () => {
  const pairingId = document.getElementById("remote-control-relay-pairing-id").value.trim();
  const result = await api(`/remote-control/directory?pairing_id=${encodeURIComponent(pairingId)}&limit=12`);
  renderRemoteControlOutput(result);
});

document.getElementById("remote-control-pairings").addEventListener("click", async (event) => {
  const directoryId = event.target.dataset.remoteControlDirectory;
  if (directoryId) {
    const result = await api(`/remote-control/directory?pairing_id=${encodeURIComponent(directoryId)}&limit=12`);
    renderRemoteControlOutput(result);
    return;
  }
  const pairingId = event.target.dataset.remoteControlRevoke;
  if (!pairingId) return;
  const result = await api("/remote-control/revoke", {
    method: "POST",
    body: JSON.stringify({ pairing_id: pairingId }),
  });
  renderRemoteControlOutput(result);
  await refresh();
});

document.getElementById("mcp-server-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const tools = document
    .getElementById("mcp-server-tools")
    .value.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  await api("/mcp/servers", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("mcp-server-name").value || "local-mcp",
      command: document.getElementById("mcp-server-command").value,
      transport: document.getElementById("mcp-server-transport").value,
      token_secret: document.getElementById("mcp-server-token-secret").value || undefined,
      allowed_tools: tools,
      enabled: false,
      approval_required: true,
    }),
  });
  await refresh();
});

document.getElementById("skill-hub-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.skillHubQuery = document.getElementById("skill-hub-query").value || "";
  await refresh();
});

document.getElementById("installed-skills").addEventListener("click", async (event) => {
  const disableId = event.target.dataset.skillDisable;
  const enableId = event.target.dataset.skillEnable;
  if (!disableId && !enableId) return;
  const action = disableId ? "disable" : "enable";
  const skillId = disableId || enableId;
  const body = {};
  if (action === "enable" && state.pendingSkillEnable[skillId]) {
    body.approval_id = state.pendingSkillEnable[skillId].id || state.pendingSkillEnable[skillId];
  }
  const result = await api(`/skills/${encodeURIComponent(skillId)}/${action}`, { method: "POST", body: JSON.stringify(body) });
  if (result.status === "approval_required" && result.approval_id) {
    state.pendingSkillEnable[skillId] = { id: result.approval_id, status: "pending" };
  } else if (result.ok && action === "enable") {
    delete state.pendingSkillEnable[skillId];
  }
  await refresh();
});

document.getElementById("plugin-install-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const manifestPath = document.getElementById("plugin-manifest-path").value;
  const result = await api("/plugins", {
    method: "POST",
    body: JSON.stringify({
      manifest_path: manifestPath,
      enable: document.getElementById("plugin-install-enable").checked,
      unsigned_local: document.getElementById("plugin-install-unsigned").checked,
    }),
  });
  renderPluginOutput(result);
  await refresh();
});

document.getElementById("plugin-reload").addEventListener("click", async () => {
  const result = await api("/plugins/reload", { method: "POST", body: JSON.stringify({}) });
  renderPluginOutput(result);
  await refresh();
});

document.getElementById("plugin-marketplace-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.pluginMarketplaceQuery = document.getElementById("plugin-marketplace-query").value || "";
  state.pluginMarketplaceCatalogPath = document.getElementById("plugin-marketplace-catalog").value || "";
  await refresh();
});

document.getElementById("plugin-marketplace").addEventListener("click", async (event) => {
  const manifestPluginId = event.target.dataset.pluginMarketplaceFetchManifest;
  const bundlePluginId = event.target.dataset.pluginMarketplaceFetchBundle;
  const bundleInstallPluginId = event.target.dataset.pluginMarketplaceInstallBundle;
  const pluginId = manifestPluginId || bundlePluginId || bundleInstallPluginId || event.target.dataset.pluginMarketplaceInstall;
  if (!pluginId) return;
  if (manifestPluginId) {
    const result = await api("/plugins/marketplace/fetch-manifest", {
      method: "POST",
      body: JSON.stringify({
        plugin_id: manifestPluginId,
        catalog_path: state.pluginMarketplaceCatalogPath || undefined,
      }),
    });
    renderPluginOutput(result);
    await refresh();
    return;
  }
  if (bundlePluginId) {
    const result = await api("/plugins/marketplace/fetch-bundle", {
      method: "POST",
      body: JSON.stringify({
        plugin_id: bundlePluginId,
        catalog_path: state.pluginMarketplaceCatalogPath || undefined,
      }),
    });
    renderPluginOutput(result);
    await refresh();
    return;
  }
  if (bundleInstallPluginId) {
    const result = await api("/plugins/marketplace/install-bundle", {
      method: "POST",
      body: JSON.stringify({
        plugin_id: bundleInstallPluginId,
        catalog_path: state.pluginMarketplaceCatalogPath || undefined,
      }),
    });
    renderPluginOutput(result);
    await refresh();
    return;
  }
  const result = await api("/plugins/marketplace/install", {
    method: "POST",
    body: JSON.stringify({
      plugin_id: pluginId,
      catalog_path: state.pluginMarketplaceCatalogPath || undefined,
    }),
  });
  renderPluginOutput(result);
  await refresh();
});

document.getElementById("plugin-updates").addEventListener("click", async (event) => {
  const preparePluginId = event.target.dataset.pluginMarketplacePrepareUpdate;
  const pluginId = preparePluginId || event.target.dataset.pluginMarketplaceUpdate;
  if (!pluginId) return;
  if (preparePluginId) {
    const result = await api("/plugins/marketplace/prepare-update", {
      method: "POST",
      body: JSON.stringify({
        plugin_id: preparePluginId,
        catalog_path: state.pluginMarketplaceCatalogPath || undefined,
      }),
    });
    renderPluginOutput(result);
    await refresh();
    return;
  }
  const result = await api("/plugins/marketplace/update", {
    method: "POST",
    body: JSON.stringify({
      plugin_id: pluginId,
      approved: true,
      catalog_path: state.pluginMarketplaceCatalogPath || undefined,
    }),
  });
  renderPluginOutput(result);
  await refresh();
});

document.getElementById("plugin-prepared-update-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const candidateId = document.getElementById("plugin-prepared-candidate-id").value || state.pluginPreparedUpdateCandidateId;
  const disable = document.getElementById("plugin-prepared-update-disable").checked;
  const enable = document.getElementById("plugin-prepared-update-enable").checked && !disable;
  const result = await api("/plugins/marketplace/apply-prepared-update", {
    method: "POST",
    body: JSON.stringify({
      candidate_id: candidateId,
      approved: document.getElementById("plugin-prepared-update-approved").checked,
      enable: disable ? false : enable ? true : undefined,
    }),
  });
  renderPluginOutput(result);
  await refresh();
});

document.getElementById("installed-plugins").addEventListener("click", async (event) => {
  const enableId = event.target.dataset.pluginEnable;
  const disableId = event.target.dataset.pluginDisable;
  const removeId = event.target.dataset.pluginRemove;
  const pluginId = enableId || disableId || removeId;
  if (!pluginId) return;
  const action = enableId ? "enable" : disableId ? "disable" : "remove";
  const result = await api(`/plugins/${encodeURIComponent(pluginId)}/${action}`, { method: "POST", body: JSON.stringify({}) });
  renderPluginOutput(result);
  await refresh();
});

document.getElementById("mcp-call-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  let argumentsPayload = {};
  try {
    argumentsPayload = JSON.parse(document.getElementById("mcp-call-arguments").value || "{}");
  } catch (error) {
    renderMcpCallOutput({ status: "bad_arguments", reason: "MCP arguments must be a JSON object." });
    return;
  }
  if (!argumentsPayload || Array.isArray(argumentsPayload) || typeof argumentsPayload !== "object") {
    renderMcpCallOutput({ status: "bad_arguments", reason: "MCP arguments must be a JSON object." });
    return;
  }
  const server = document.getElementById("mcp-call-server").value || "local-mcp";
  const tool = document.getElementById("mcp-call-tool").value || "echo";
  state.pendingMcpCall = { server, tool, arguments: argumentsPayload };
  const result = await api("/mcp/call", {
    method: "POST",
    body: JSON.stringify({ server, tool, arguments: argumentsPayload }),
  });
  renderMcpCallOutput(result);
  await refresh();
});

document.getElementById("mcp-call-output").addEventListener("click", async (event) => {
  const approvalId = event.target.dataset.mcpRunApproved;
  if (!approvalId || !state.pendingMcpCall || state.pendingMcpCall.approval_id !== approvalId) return;
  const result = await api("/mcp/call", {
    method: "POST",
    body: JSON.stringify({ ...state.pendingMcpCall, approval_id: approvalId }),
  });
  if (result.status !== "approval_required") {
    state.pendingMcpCall = null;
  }
  renderMcpCallOutput(result);
  await refresh();
});

document.getElementById("tool-run-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  let params = {};
  try {
    params = JSON.parse(document.getElementById("tool-run-params").value || "{}");
  } catch (error) {
    renderToolRunOutput({ status: "bad_params", reason: "Tool params must be a JSON object." });
    return;
  }
  if (!params || Array.isArray(params) || typeof params !== "object") {
    renderToolRunOutput({ status: "bad_params", reason: "Tool params must be a JSON object." });
    return;
  }
  const name = document.getElementById("tool-run-name").value || "calculator";
  state.pendingToolRun = { name, params };
  const result = await api("/tools/run", {
    method: "POST",
    body: JSON.stringify({ name, params }),
  });
  renderToolRunOutput(result);
  await refresh();
});

document.getElementById("tool-run-presets").addEventListener("click", (event) => {
  const presetName = event.target.dataset.toolPreset;
  if (!presetName) return;
  const preset = TOOL_RUN_PRESETS.find((item) => item.name === presetName);
  if (!preset) return;
  document.getElementById("tool-run-name").value = preset.name;
  document.getElementById("tool-run-params").value = JSON.stringify(preset.params, null, 2);
  renderToolRunOutput({ status: "preset_loaded", tool: preset.name, params: preset.params });
});

document.getElementById("tool-run-output").addEventListener("click", async (event) => {
  const approvalId = event.target.dataset.toolRunApproved;
  if (!approvalId || !state.pendingToolRun || state.pendingToolRun.approval_id !== approvalId) return;
  const result = await api("/tools/run", {
    method: "POST",
    body: JSON.stringify({ ...state.pendingToolRun, approval_id: approvalId }),
  });
  if (result.status !== "approval_required") {
    state.pendingToolRun = null;
  }
  renderToolRunOutput(result);
  await refresh();
});

document.getElementById("browser-new-session").addEventListener("click", async () => {
  const session = await api("/browser/sessions", { method: "POST", body: JSON.stringify({ label: "Web control" }) });
  state.browserSessionId = session.id;
  renderBrowserOutput(session);
  await refresh();
});

document.getElementById("browser-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.browserSessionId) {
    const session = await api("/browser/sessions", { method: "POST", body: JSON.stringify({ label: "Web control" }) });
    state.browserSessionId = session.id;
  }
  const result = await api("/browser/navigate", {
    method: "POST",
    body: JSON.stringify({ session_id: state.browserSessionId, url: document.getElementById("browser-url").value || "https://example.com" }),
  });
  renderBrowserOutput(result);
  await refresh();
});

document.getElementById("browser-extract").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  renderBrowserOutput(await api("/browser/extract", { method: "POST", body: JSON.stringify({ session_id: state.browserSessionId }) }));
});

document.getElementById("browser-inspect").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  renderBrowserOutput(await api("/browser/inspect", { method: "POST", body: JSON.stringify({ session_id: state.browserSessionId }) }));
});

document.getElementById("browser-live-navigate").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    const session = await api("/browser/sessions", { method: "POST", body: JSON.stringify({ label: "Web live browser" }) });
    state.browserSessionId = session.id;
  }
  const url = document.getElementById("browser-url").value || "https://example.com";
  state.pendingBrowserAction = { action: "live_navigate", session_id: state.browserSessionId, url };
  renderBrowserOutput(
    await api("/browser/live-navigate", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, url }),
    })
  );
  await refresh();
});

document.getElementById("browser-dom-snapshot").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const selector = document.getElementById("browser-selector").value.trim();
  renderBrowserOutput(await api("/browser/dom-snapshot", { method: "POST", body: JSON.stringify({ session_id: state.browserSessionId, selector: selector || undefined }) }));
});

document.getElementById("browser-table").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const selector = document.getElementById("browser-selector").value.trim();
  renderBrowserOutput(await api("/browser/table", { method: "POST", body: JSON.stringify({ session_id: state.browserSessionId, selector: selector || undefined }) }));
});

document.getElementById("browser-screenshot").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  renderBrowserOutput(await api("/browser/screenshot", { method: "POST", body: JSON.stringify({ session_id: state.browserSessionId }) }));
  await refresh();
});

document.getElementById("browser-render-screenshot").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  renderBrowserOutput(await api("/browser/render-screenshot", { method: "POST", body: JSON.stringify({ session_id: state.browserSessionId }) }));
  await refresh();
});

document.getElementById("browser-live-screenshot").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  state.pendingBrowserAction = { action: "live_screenshot", session_id: state.browserSessionId };
  renderBrowserOutput(await api("/browser/live-screenshot", { method: "POST", body: JSON.stringify({ session_id: state.browserSessionId }) }));
  await refresh();
});

document.getElementById("browser-click").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const selector = document.getElementById("browser-selector").value || "body";
  state.pendingBrowserAction = { action: "click", session_id: state.browserSessionId, selector };
  renderBrowserOutput(
    await api("/browser/click", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, selector }),
    })
  );
  await refresh();
});

document.getElementById("browser-live-click").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const selector = document.getElementById("browser-selector").value || "body";
  state.pendingBrowserAction = { action: "live_click", session_id: state.browserSessionId, selector };
  renderBrowserOutput(
    await api("/browser/click", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, selector, live: true }),
    })
  );
  await refresh();
});

document.getElementById("browser-fill").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  let fields = {};
  try {
    fields = JSON.parse(document.getElementById("browser-fill-fields").value || "{}");
  } catch (error) {
    renderBrowserOutput({ status: "bad_fields", reason: "Fill fields must be a JSON object." });
    return;
  }
  state.pendingBrowserAction = { action: "fill", session_id: state.browserSessionId, fields };
  renderBrowserOutput(
    await api("/browser/fill", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, fields }),
    })
  );
  await refresh();
});

document.getElementById("browser-live-fill").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  let fields = {};
  try {
    fields = JSON.parse(document.getElementById("browser-fill-fields").value || "{}");
  } catch (error) {
    renderBrowserOutput({ status: "bad_fields", reason: "Fill fields must be a JSON object." });
    return;
  }
  state.pendingBrowserAction = { action: "live_fill", session_id: state.browserSessionId, fields };
  renderBrowserOutput(
    await api("/browser/fill", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, fields, live: true }),
    })
  );
  await refresh();
});

document.getElementById("browser-submit").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const selector = document.getElementById("browser-selector").value.trim();
  state.pendingBrowserAction = { action: "submit", session_id: state.browserSessionId, selector: selector || undefined };
  renderBrowserOutput(
    await api("/browser/submit", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, selector: selector || undefined }),
    })
  );
  await refresh();
});

document.getElementById("browser-live-submit").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const selector = document.getElementById("browser-selector").value.trim();
  state.pendingBrowserAction = { action: "live_submit", session_id: state.browserSessionId, selector: selector || undefined };
  renderBrowserOutput(
    await api("/browser/submit", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, selector: selector || undefined, live: true }),
    })
  );
  await refresh();
});

document.getElementById("browser-live-download").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const selector = document.getElementById("browser-selector").value || "a";
  state.pendingBrowserAction = { action: "live_download", session_id: state.browserSessionId, selector };
  renderBrowserOutput(
    await api("/browser/download", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, selector }),
    })
  );
  await refresh();
});

document.getElementById("browser-live-upload").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const selector = document.getElementById("browser-selector").value || "input[type=file]";
  const filePath = document.getElementById("browser-upload-path").value.trim();
  state.pendingBrowserAction = { action: "live_upload", session_id: state.browserSessionId, selector, file_path: filePath };
  renderBrowserOutput(
    await api("/browser/upload", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, selector, file_path: filePath }),
    })
  );
  await refresh();
});

document.getElementById("browser-live-evaluate").addEventListener("click", async () => {
  if (!state.browserSessionId) {
    renderBrowserOutput({ status: "no_session", reason: "Create or open a browser session first." });
    return;
  }
  const script = document.getElementById("browser-evaluate-script").value || "return document.title";
  state.pendingBrowserAction = { action: "live_evaluate", session_id: state.browserSessionId, script };
  renderBrowserOutput(
    await api("/browser/evaluate", {
      method: "POST",
      body: JSON.stringify({ session_id: state.browserSessionId, script }),
    })
  );
  await refresh();
});

document.getElementById("browser-output").addEventListener("click", async (event) => {
  const createActivationPacket = event.target.closest("[data-browser-live-activation-packet]");
  if (createActivationPacket) {
    renderBrowserOutput(await api("/browser/live-activation-packet", { method: "POST", body: JSON.stringify({ actor: "web-operator" }) }));
    await refresh();
    return;
  }
  const verifyActivationPacket = event.target.closest("[data-browser-verify-activation-packet]");
  if (verifyActivationPacket) {
    const activationPacket = verifyActivationPacket.dataset.browserVerifyActivationPacket;
    renderBrowserOutput(
      await api("/browser/verify-activation-packet", {
        method: "POST",
        body: JSON.stringify({ packet: activationPacket, actor: "web-operator" }),
      })
    );
    await refresh();
    return;
  }
  const elementButton = event.target.closest("[data-browser-selector]");
  if (elementButton) {
    const selector = elementButton.dataset.browserSelector || "";
    document.getElementById("browser-selector").value = selector;
    if (["input", "textarea", "select"].includes(elementButton.dataset.browserTag || "")) {
      document.getElementById("browser-fill-fields").value = JSON.stringify({ [selector]: "" }, null, 2);
    }
    return;
  }
  const approvalId = event.target.dataset.browserRunApproved;
  if (!approvalId || !state.pendingBrowserAction || state.pendingBrowserAction.approval_id !== approvalId) return;
  const action = state.pendingBrowserAction;
  const path =
    action.action === "fill" || action.action === "live_fill"
      ? "/browser/fill"
      : action.action === "submit" || action.action === "live_submit"
        ? "/browser/submit"
        : action.action === "live_download"
          ? "/browser/download"
        : action.action === "live_upload"
          ? "/browser/upload"
        : action.action === "live_evaluate"
          ? "/browser/evaluate"
        : action.action === "live_navigate"
          ? "/browser/live-navigate"
          : action.action === "live_screenshot"
            ? "/browser/live-screenshot"
            : "/browser/click";
  const body =
    action.action === "fill" || action.action === "live_fill"
      ? { session_id: action.session_id, fields: action.fields, approval_id: approvalId, live: action.action === "live_fill" }
      : action.action === "submit" || action.action === "live_submit"
        ? { session_id: action.session_id, selector: action.selector, approval_id: approvalId, live: action.action === "live_submit" }
        : action.action === "live_download"
          ? { session_id: action.session_id, selector: action.selector, approval_id: approvalId }
        : action.action === "live_upload"
          ? { session_id: action.session_id, selector: action.selector, file_path: action.file_path, approval_id: approvalId }
        : action.action === "live_evaluate"
          ? { session_id: action.session_id, script: action.script, approval_id: approvalId }
        : action.action === "live_navigate"
          ? { session_id: action.session_id, url: action.url, approval_id: approvalId }
          : action.action === "live_screenshot"
            ? { session_id: action.session_id, approval_id: approvalId }
            : { session_id: action.session_id, selector: action.selector, approval_id: approvalId, live: action.action === "live_click" };
  const result = await api(path, { method: "POST", body: JSON.stringify(body) });
  if (result.ok) {
    state.pendingBrowserAction = null;
  }
  renderBrowserOutput(result);
  await refresh();
});

document.getElementById("browser-sessions").addEventListener("click", async (event) => {
  const closeId = event.target.dataset.browserClose;
  if (closeId) {
    const result = await api(`/browser/sessions/${encodeURIComponent(closeId)}/close`, { method: "POST", body: JSON.stringify({}) });
    if (state.browserSessionId === closeId) {
      state.browserSessionId = null;
    }
    renderBrowserOutput(result);
    await refresh();
    return;
  }
  const sessionId = event.target.dataset.browserSession;
  if (!sessionId) return;
  state.browserSessionId = sessionId;
  renderBrowserOutput({ ok: true, session_id: sessionId, status: "selected" });
  await refresh();
});

document.getElementById("memory-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.memoryQuery = document.getElementById("memory-query").value || "";
  const payload = await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`);
  renderMemories(payload);
});

document.getElementById("memory-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const tags = document
    .getElementById("memory-tags")
    .value.split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const confidence = Number.parseFloat(document.getElementById("memory-confidence").value || "0.8");
  const ttlDays = Number.parseInt(document.getElementById("memory-ttl-days").value || "", 10);
  const created = await api("/memory", {
    method: "POST",
    body: JSON.stringify({
      type: document.getElementById("memory-type").value,
      content: document.getElementById("memory-content").value || "",
      confidence: Number.isFinite(confidence) ? confidence : 0.8,
      tags,
      confirmed: document.getElementById("memory-confirmed").checked,
      ttl_days: Number.isFinite(ttlDays) ? ttlDays : undefined,
    }),
  });
  renderMemoryOutput(created);
  state.memoryQuery = document.getElementById("memory-query").value || document.getElementById("memory-content").value || "";
  document.getElementById("memory-query").value = state.memoryQuery;
  renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
  await refresh();
});

document.getElementById("memory-update-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const memoryId = document.getElementById("memory-update-id").value || "";
  const confidenceText = document.getElementById("memory-update-confidence").value;
  const confidence = Number.parseFloat(confidenceText || "");
  const body = {
    content: document.getElementById("memory-update-content").value || undefined,
    confirmed: document.getElementById("memory-update-confirmed").checked,
  };
  if (Number.isFinite(confidence)) {
    body.confidence = confidence;
  }
  const updated = await api(`/memory/${encodeURIComponent(memoryId)}/update`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  renderMemoryOutput(updated);
  state.memoryQuery = document.getElementById("memory-query").value || updated.content || state.memoryQuery;
  document.getElementById("memory-query").value = state.memoryQuery;
  renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
  await refresh();
});

document.getElementById("memory-merge-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const merged = await api("/memory/merge", {
    method: "POST",
    body: JSON.stringify({
      primary_id: document.getElementById("memory-merge-primary").value || "",
      duplicate_id: document.getElementById("memory-merge-duplicate").value || "",
    }),
  });
  renderMemoryOutput(merged);
  state.memoryQuery = document.getElementById("memory-query").value || merged.content || state.memoryQuery;
  document.getElementById("memory-query").value = state.memoryQuery;
  renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
  await refresh();
});

document.getElementById("memory-resolve-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const resolved = await api("/memory/resolve-conflict", {
    method: "POST",
    body: JSON.stringify({
      primary_id: document.getElementById("memory-resolve-primary").value || "",
      conflicting_id: document.getElementById("memory-resolve-conflicting").value || "",
      strategy: document.getElementById("memory-resolve-strategy").value || "keep_primary",
      rationale: document.getElementById("memory-resolve-rationale").value || "Reviewed from the web console.",
    }),
  });
  renderMemoryOutput(resolved);
  state.memoryQuery = document.getElementById("memory-query").value || state.memoryQuery;
  renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
  await refresh();
});

document.getElementById("memory-export").addEventListener("click", async () => {
  state.memoryQuery = document.getElementById("memory-query").value || state.memoryQuery;
  renderMemoryOutput(await api(`/memory/export?q=${encodeURIComponent(state.memoryQuery)}`));
});

document.getElementById("memory-review-queue").addEventListener("click", async () => {
  renderMemoryOutput(await api("/memory/review-queue"));
});

document.getElementById("memory-review-digest").addEventListener("click", async () => {
  renderMemoryOutput(await api("/memory/review-digest"));
});

document.getElementById("memory-review-escalation").addEventListener("click", async () => {
  renderMemoryOutput(await api("/memory/review-escalation"));
});

document.getElementById("memory-session-preview").addEventListener("click", async () => {
  if (!state.activeSessionId) {
    renderMemoryOutput({ status: "No active session for memory preview" });
    return;
  }
  renderMemoryOutput(await api(`/sessions/${encodeURIComponent(state.activeSessionId)}/memory-preview?owner=local-user&scope=workspace`));
});

document.getElementById("memory-session-commit").addEventListener("click", async () => {
  if (!state.activeSessionId) {
    renderMemoryOutput({ status: "No active session for memory commit" });
    return;
  }
  const candidateIds = selectedMemoryCandidateIds();
  const body = { owner: "local-user", scope: "workspace" };
  if (candidateIds !== null) {
    body.candidate_ids = candidateIds;
  }
  const result = await api(`/sessions/${encodeURIComponent(state.activeSessionId)}/memory-commit`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  renderMemoryOutput(result);
  const firstMemory = result.memories?.[0];
  state.memoryQuery = firstMemory?.content || document.getElementById("memory-query").value || state.memoryQuery;
  document.getElementById("memory-query").value = state.memoryQuery;
  renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
  await refresh();
});

document.getElementById("migration-memory-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitter = event.submitter;
  const action = submitter?.dataset.migrationMemoryAction || "preview";
  const platform = document.getElementById("migration-memory-platform").value;
  const path = document.getElementById("migration-memory-path").value || "";
  const owner = document.getElementById("migration-memory-owner").value || "local-user";
  const scope = document.getElementById("migration-memory-scope").value || "workspace";
  if (action === "commit") {
    const candidateIds = selectedMemoryCandidateIds();
    const body = {
      platform,
      path,
      owner,
      scope,
      confirmed: document.getElementById("migration-memory-confirmed").checked,
      reviewer: "web-console",
    };
    if (candidateIds !== null) {
      body.candidate_ids = candidateIds;
    }
    const result = await api("/migration/memory-commit", {
      method: "POST",
      body: JSON.stringify(body),
    });
    renderMemoryOutput(result);
    const firstMemory = result.memories?.[0];
    state.memoryQuery = firstMemory?.content || document.getElementById("memory-query").value || state.memoryQuery;
    document.getElementById("memory-query").value = state.memoryQuery;
    renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
    await refresh();
    return;
  }
  renderMemoryOutput(
    await api(
      `/migration/memory-preview?platform=${encodeURIComponent(platform)}&path=${encodeURIComponent(path)}&owner=${encodeURIComponent(owner)}&scope=${encodeURIComponent(scope)}`
    )
  );
});

document.getElementById("memory-recertify-preview").addEventListener("click", async () => {
  renderMemoryOutput(await api("/memory/recertify", { method: "POST", body: JSON.stringify({ dry_run: true, limit: 50 }) }));
});

document.getElementById("memory-recertify-mark").addEventListener("click", async () => {
  renderMemoryOutput(await api("/memory/recertify", { method: "POST", body: JSON.stringify({ dry_run: false, limit: 50 }) }));
  await refresh();
});

document.getElementById("memory-cleanup-expired").addEventListener("click", async () => {
  state.memoryQuery = document.getElementById("memory-query").value || state.memoryQuery;
  renderMemoryOutput(await api("/memory/cleanup-expired", { method: "POST", body: JSON.stringify({}) }));
  renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
  await refresh();
});

document.getElementById("memory-output").addEventListener("click", async (event) => {
  const batchAction = event.target.dataset.memoryReviewBatch;
  if (batchAction) {
    const memoryIds = Array.from(document.querySelectorAll("#memory-output [data-memory-review-select]:checked"))
      .map((input) => input.dataset.memoryReviewSelect)
      .filter(Boolean);
    if (!memoryIds.length) {
      renderMemoryOutput({ status: "No selected memory review items", selected: [] });
      return;
    }
    renderMemoryOutput(
      await api("/memory/review-batch", {
        method: "POST",
        body: JSON.stringify({
          memory_ids: memoryIds,
          action: batchAction,
          rationale: `${batchAction === "confirm" ? "Confirmed" : "Deleted"} from the web review queue batch action.`,
        }),
      })
    );
    await refresh();
    return;
  }
  const confirmId = event.target.dataset.memoryReviewConfirm;
  if (confirmId) {
    renderMemoryOutput(
      await api("/memory/review-action", {
        method: "POST",
        body: JSON.stringify({ memory_id: confirmId, action: "confirm", rationale: "Confirmed from the web review queue." }),
      })
    );
    await refresh();
    return;
  }
  const deleteId = event.target.dataset.memoryReviewDelete;
  if (deleteId) {
    renderMemoryOutput(
      await api("/memory/review-action", {
        method: "POST",
        body: JSON.stringify({ memory_id: deleteId, action: "delete", rationale: "Deleted from the web review queue." }),
      })
    );
    await refresh();
    return;
  }
  const primaryId = event.target.dataset.memoryReviewResolvePrimary;
  const conflictingId = event.target.dataset.memoryReviewResolveConflicting;
  if (primaryId && conflictingId) {
    document.getElementById("memory-resolve-primary").value = primaryId;
    document.getElementById("memory-resolve-conflicting").value = conflictingId;
  }
});

document.getElementById("memories").addEventListener("click", async (event) => {
  const editId = event.target.dataset.memoryEdit;
  if (editId) {
    document.getElementById("memory-update-id").value = editId;
    document.getElementById("memory-update-content").value = event.target.dataset.memoryContent || "";
    document.getElementById("memory-update-confidence").value = event.target.dataset.memoryConfidence || "";
    return;
  }
  const primaryId = event.target.dataset.memoryMergePrimary;
  if (primaryId) {
    document.getElementById("memory-merge-primary").value = primaryId;
    return;
  }
  const duplicateId = event.target.dataset.memoryMergeDuplicate;
  if (duplicateId) {
    document.getElementById("memory-merge-duplicate").value = duplicateId;
    return;
  }
  const resolvePrimaryId = event.target.dataset.memoryResolvePrimary;
  if (resolvePrimaryId) {
    document.getElementById("memory-resolve-primary").value = resolvePrimaryId;
    return;
  }
  const resolveConflictingId = event.target.dataset.memoryResolveConflicting;
  if (resolveConflictingId) {
    document.getElementById("memory-resolve-conflicting").value = resolveConflictingId;
    return;
  }
  const explainId = event.target.dataset.memoryExplain;
  if (explainId) {
    state.memoryQuery = document.getElementById("memory-query").value || state.memoryQuery;
    renderMemoryOutput(await api(`/memory/${encodeURIComponent(explainId)}/explain?q=${encodeURIComponent(state.memoryQuery)}`));
    return;
  }
  const expireId = event.target.dataset.memoryExpire;
  if (expireId) {
    renderMemoryOutput(await api(`/memory/${encodeURIComponent(expireId)}/expire`, { method: "POST", body: JSON.stringify({}) }));
    renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
    await refresh();
    return;
  }
  const deleteId = event.target.dataset.memoryDelete;
  if (!deleteId) return;
  renderMemoryOutput(await api(`/memory/${encodeURIComponent(deleteId)}/delete`, { method: "POST", body: JSON.stringify({}) }));
  renderMemories(await api(`/memory?q=${encodeURIComponent(state.memoryQuery)}`));
  await refresh();
});

document.getElementById("schedule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/schedules", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("schedule-name").value || "Scheduled task",
      cron: document.getElementById("schedule-cron").value || "@daily",
      task_request: document.getElementById("schedule-task").value || "Summarize my project",
      channel: "web",
      context_from: fieldList("schedule-context-from"),
      delivery_targets: fieldList("schedule-deliver-to"),
    }),
  });
  renderScheduleOutput(result);
  await refresh();
});

document.getElementById("schedule-script-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const command = JSON.parse(document.getElementById("schedule-script-command").value || '["python3","-c","print(\\"ok\\")"]');
  const result = await api("/schedules/script", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("schedule-name").value || "No-agent script",
      cron: document.getElementById("schedule-cron").value || "@daily",
      command,
      channel: "web",
      context_from: fieldList("schedule-context-from"),
      delivery_targets: fieldList("schedule-deliver-to"),
    }),
  });
  renderScheduleOutput(result);
  await refresh();
});

document.getElementById("schedule-memory-digest").addEventListener("click", async () => {
  const result = await api("/schedules/memory-review-digest", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("schedule-name").value || "Memory review digest",
      cron: document.getElementById("schedule-cron").value || "@daily",
      channel: "web",
      limit: 10,
      scope: "workspace",
    }),
  });
  renderScheduleOutput(result);
  await refresh();
});

document.getElementById("schedule-memory-escalation").addEventListener("click", async () => {
  const result = await api("/schedules/memory-review-escalation", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("schedule-name").value || "Memory review escalation",
      cron: document.getElementById("schedule-cron").value || "@daily",
      channel: "web",
      max_age_days: 7,
      limit: 10,
      scope: "workspace",
      route: "operator",
    }),
  });
  renderScheduleOutput(result);
  await refresh();
});

document.getElementById("schedule-evaluation-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const steps = document.getElementById("schedule-evaluation-steps").value
    .split(",")
    .map((step) => step.trim())
    .filter(Boolean);
  const result = await api("/schedules/evaluation-run", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("schedule-name").value || "Evaluation run",
      cron: document.getElementById("schedule-cron").value || "@daily",
      scenario: document.getElementById("schedule-evaluation-scenario").value || "policy regression",
      steps: steps.length ? steps : ["seed", "run gates", "review digest"],
      channel: "web",
      reviewer: document.getElementById("schedule-evaluation-reviewer").value || "scheduler",
    }),
  });
  renderScheduleOutput(result);
  await refresh();
});

document.getElementById("schedule-evaluation-suite-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = await api("/schedules/evaluation-suite", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("schedule-name").value || "Evaluation suite",
      cron: document.getElementById("schedule-cron").value || "@daily",
      suite: document.getElementById("schedule-evaluation-suite").value || "security",
      scenario_ids: [],
      channel: "web",
      reviewer: document.getElementById("schedule-evaluation-reviewer").value || "scheduler",
    }),
  });
  renderScheduleOutput(result);
  await refresh();
});

document.getElementById("run-due-schedules").addEventListener("click", async () => {
  const result = await api("/schedules/run-due", { method: "POST", body: "{}" });
  if (result.results?.[0]?.task_id) {
    await loadTaskStatus(result.results[0].task_id);
  } else if (result.ran) {
    renderScheduleOutput(result);
    await refresh();
  } else {
    renderTaskError("No active schedules are due.");
    await refresh();
  }
});

document.getElementById("evaluation-review-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const reportId = document.getElementById("evaluation-report-id").value.trim();
  if (!reportId) {
    renderEvaluationOutput({ status: "missing_report_id" });
    return;
  }
  const result = await api(`/evaluation/reports/${encodeURIComponent(reportId)}/review`, {
    method: "POST",
    body: JSON.stringify({
      status: document.getElementById("evaluation-review-status").value,
      reviewer: document.getElementById("evaluation-reviewer").value || "local",
      notes: document.getElementById("evaluation-review-notes").value || "",
    }),
  });
  renderEvaluationOutput(result);
  await refresh();
});

document.getElementById("evaluation-queue").addEventListener("click", (event) => {
  const reportId = event.target.dataset.evaluationReport;
  if (!reportId) return;
  document.getElementById("evaluation-report-id").value = reportId;
});

document.getElementById("schedules").addEventListener("click", async (event) => {
  const activate = event.target.dataset.scheduleActivate;
  const approve = event.target.dataset.scheduleApprove;
  const pause = event.target.dataset.schedulePause;
  try {
    if (approve) {
      await api(`/schedules/${approve}/approve`, { method: "POST", body: "{}" });
      await refresh();
    }
    if (activate) {
      await api(`/schedules/${activate}/activate`, { method: "POST", body: "{}" });
      await refresh();
    }
    if (pause) {
      await api(`/schedules/${pause}/pause`, { method: "POST", body: "{}" });
      await refresh();
    }
  } catch (error) {
    renderTaskError(error.message);
    await refresh();
  }
});

document.getElementById("session-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const session = await api("/sessions", {
    method: "POST",
    body: JSON.stringify({ title: document.getElementById("session-title").value || "Web session", channel: "web" }),
  });
  state.activeSessionId = session.id;
  renderSessionOutput(session);
  await refresh();
});

document.getElementById("session-update-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.activeSessionId) return;
  const session = await api(`/sessions/${encodeURIComponent(state.activeSessionId)}/update`, {
    method: "POST",
    body: JSON.stringify({
      title: document.getElementById("session-update-title").value,
      model: document.getElementById("session-update-model").value,
      personality: document.getElementById("session-update-personality").value,
      status: document.getElementById("session-update-status").value,
    }),
  });
  state.activeSessionId = session.id;
  renderSessionOutput(session);
  await refresh();
});

document.getElementById("session-compact-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.activeSessionId) return;
  const keepLast = Number.parseInt(document.getElementById("session-compact-keep").value || "20", 10);
  const result = await api(`/sessions/${encodeURIComponent(state.activeSessionId)}/compact`, {
    method: "POST",
    body: JSON.stringify({ keep_last: keepLast }),
  });
  renderSessionOutput(result);
  await refresh();
});

document.getElementById("session-transcript").addEventListener("click", async (event) => {
  const statusId = event.target.dataset.transcriptTaskStatus;
  const eventsId = event.target.dataset.transcriptTaskEvents;
  const timelineId = event.target.dataset.transcriptTaskTimeline;
  const resumeId = event.target.dataset.transcriptTaskResume;
  const approvalId = event.target.dataset.transcriptApprovalReview;
  const approveId = event.target.dataset.transcriptApprovalApprove;
  const denyId = event.target.dataset.transcriptApprovalDeny;
  if (statusId) {
    await loadTaskStatus(statusId);
  }
  if (eventsId) {
    await loadTaskEvents(eventsId);
  }
  if (timelineId) {
    await loadTaskTimeline(timelineId);
  }
  if (resumeId) {
    await resumeTask(resumeId);
  }
  if (approvalId) {
    await loadApprovalDetail(approvalId);
  }
  if (approveId) {
    await api(`/approvals/${approveId}/approve`, { method: "POST", body: JSON.stringify(approvalDecisionPayload()) });
    document.getElementById("approval-detail").replaceChildren();
    await refresh();
  }
  if (denyId) {
    await api(`/approvals/${denyId}/deny`, { method: "POST", body: JSON.stringify(approvalDecisionPayload()) });
    document.getElementById("approval-detail").replaceChildren();
    await refresh();
  }
});

document.getElementById("sessions").addEventListener("click", async (event) => {
  const taskSession = event.target.dataset.sessionTasks;
  if (taskSession) {
    state.inspectedTaskSessionId = taskSession;
    state.taskScope = "session";
    await refresh();
    return;
  }
  const selected = event.target.dataset.sessionSelect || event.target.closest("[data-session]")?.dataset.session;
  if (!selected) return;
  state.activeSessionId = selected;
  state.inspectedTaskSessionId = null;
  await refresh();
});

document.getElementById("board-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const board = await api("/kanban/boards", {
    method: "POST",
    body: JSON.stringify({ name: document.getElementById("board-name").value || "Work board" }),
  });
  state.selectedBoardId = board.id;
  await refresh();
});

document.getElementById("card-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const boardId = document.getElementById("card-board").value || state.selectedBoardId;
  if (!boardId) return;
  await api(`/kanban/boards/${boardId}/cards`, {
    method: "POST",
    body: JSON.stringify({
      title: document.getElementById("card-title").value || "New card",
      description: document.getElementById("card-description").value || "",
      lane: "backlog",
    }),
  });
  state.selectedBoardId = boardId;
  await refresh();
});

document.getElementById("subagent-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    role: document.getElementById("subagent-role").value || "Researcher",
    task: document.getElementById("subagent-task").value || "Review the current work queue.",
  };
  state.pendingSubagentDelegation = payload;
  const result = await api("/subagents/delegate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  renderSubagentOutput(result);
  renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
  await refresh();
});

document.getElementById("subagent-output").addEventListener("click", async (event) => {
  const approvalId = event.target.dataset.subagentApproved;
  if (!approvalId || !state.pendingSubagentDelegation) return;
  const result = await api("/subagents/delegate", {
    method: "POST",
    body: JSON.stringify({ ...state.pendingSubagentDelegation, approval_id: approvalId }),
  });
  state.pendingSubagentDelegation = null;
  renderSubagentOutput(result);
  renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
  await refresh();
});

document.getElementById("subagent-cards").addEventListener("click", async (event) => {
  const verifyPacket = event.target.dataset.subagentVerifyPacket;
  if (verifyPacket) {
    const result = await api("/subagents/verify-packet", {
      method: "POST",
      body: JSON.stringify({ packet: verifyPacket, actor: "web-operator" }),
    });
    renderSubagentOutput(result);
    renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
    await refresh();
    return;
  }
  const reviewPacketCard = event.target.dataset.subagentReviewPacket;
  if (reviewPacketCard) {
    const result = await api("/subagents/review-packet", {
      method: "POST",
      body: JSON.stringify({ card_id: reviewPacketCard, actor: "web-operator" }),
    });
    renderSubagentOutput(result);
    renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
    await refresh();
    return;
  }
  const modelReviewCard = event.target.dataset.subagentModelReview;
  if (modelReviewCard) {
    const result = await api("/subagents/model-review", {
      method: "POST",
      body: JSON.stringify({ card_id: modelReviewCard, actor: "web-operator", approved: true, limit: 12 }),
    });
    renderSubagentOutput(result);
    renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
    await refresh();
    return;
  }
  const runCard = event.target.dataset.subagentRun;
  if (runCard) {
    const result = await api("/subagents/run", {
      method: "POST",
      body: JSON.stringify({ card_id: runCard, actor: "web-operator", approved: true }),
    });
    renderSubagentOutput(result);
    renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
    await refresh();
    return;
  }
  const card = event.target.dataset.subagentCard;
  const lane = event.target.dataset.subagentLane;
  if (!card || !lane) return;
  const result = await api("/subagents/handoff", {
    method: "POST",
    body: JSON.stringify({ card_id: card, lane, actor: "web-operator" }),
  });
  renderSubagentOutput(result);
  renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
  await refresh();
});

document.getElementById("subagent-run-batch").addEventListener("click", async () => {
  const result = await api("/subagents/run-batch", {
    method: "POST",
    body: JSON.stringify({ actor: "web-operator", approved: true, run_limit: 5, limit: 12 }),
  });
  renderSubagentOutput(result);
  renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
  await refresh();
});

document.getElementById("subagent-autonomy-preflight").addEventListener("click", async () => {
  const result = await api("/subagents/autonomy-preflight?limit=12&actor=web-operator");
  renderSubagentOutput(result);
  renderSubagents(result.subagents || await api("/subagents/status?limit=12"));
  await refresh();
});

document.getElementById("card-board").addEventListener("change", async (event) => {
  state.selectedBoardId = event.target.value;
  await renderCards();
});

document.getElementById("boards").addEventListener("click", async (event) => {
  const row = event.target.closest("[data-board]");
  if (!row) return;
  state.selectedBoardId = row.dataset.board;
  document.getElementById("card-board").value = state.selectedBoardId;
  renderBoards();
  await renderCards();
});

document.getElementById("cards").addEventListener("click", async (event) => {
  const card = event.target.dataset.card;
  const lane = event.target.dataset.lane;
  if (!card || !lane) return;
  await api(`/kanban/cards/${card}/move`, { method: "POST", body: JSON.stringify({ lane }) });
  await renderCards();
});

bootstrapAuth()
  .then(() => {
    installToolRunPresets();
    return refresh();
  })
  .catch((error) => {
    document.getElementById("app-status").textContent = "Auth Error";
    document.getElementById("app-status").className = "status-pill bad";
    renderTaskError(error.message);
  });
