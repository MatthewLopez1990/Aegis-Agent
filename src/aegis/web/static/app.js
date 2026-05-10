const state = {
  boards: [],
  selectedBoardId: null,
};

const api = async (url, options = {}) => {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `Request failed: ${response.status}`);
  }
  return payload;
};

const escapeHtml = (value) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const text = (value) => escapeHtml(Array.isArray(value) ? value.join(", ") : value);

const item = ({ title, detail = "", meta = "", tone = "", actions = "" }) => {
  const node = document.createElement("div");
  node.className = `item ${tone}`.trim();
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
      connectors,
      channels,
      models,
      modelProviders,
      tools,
      backends,
      skillHub,
      schedules,
      sessions,
      audit,
      tasks,
      approvals,
      boards,
    ] = await Promise.all([
      api("/dashboard"),
      api("/connectors"),
      api("/channels"),
      api("/models"),
      api("/model-providers"),
      api("/tools"),
      api("/backends"),
      api("/skill-hub"),
      api("/schedules"),
      api("/sessions"),
      api("/audit?limit=40"),
      api("/tasks?limit=12"),
      api("/approvals?status=pending"),
      api("/kanban/boards"),
    ]);

    renderMetrics(dashboard);
    setFeatureGrid("security-controls", dashboard.security_controls, (x) => ({
      title: x.name,
      detail: x.detail,
      meta: x.state,
    }));
    setFeatureGrid("capability-groups", dashboard.capability_groups, (x) => ({
      title: x.name,
      detail: x.detail,
      meta: `${x.state} · ${x.coverage}`,
    }));
    setList("competitor-targets", dashboard.competitive_targets, (x) => ({
      title: x.platform,
      detail: x.security_delta,
      meta: `Covered: ${x.covered.slice(0, 5).join(", ")}`,
      tone: "highlight",
    }));

    setList("connectors", connectors.connectors, (x) => ({
      title: x.name,
      detail: `${x.default_mode} · ${x.supported_operations.join(", ")}`,
      meta: x.auth_type,
    }));
    setList("channels", channels.channels.slice(0, 30), (x) => ({
      title: x.name,
      detail: `${x.rich_messages.join(", ")}`,
      meta: `${x.difficulty} · ${x.auth_type}`,
    }));
    setList(
      "model-providers",
      modelProviders.providers,
      (x) => ({
        title: x.provider,
        detail: x.local ? "Local provider" : x.auth_configured ? `Auth configured via ${x.auth_source}` : "Auth missing",
        meta: `${x.models.length} models · tools ${formatBool(x.supports_tools)}`,
        tone: x.local || x.auth_configured ? "ready" : "attention",
      })
    );
    setList("models", models.models.slice(0, 24), (x) => ({
      title: x.identifier,
      detail: x.local ? "local" : x.auth_configured ? "cloud · auth configured" : "cloud · auth missing",
      meta: `${x.supports_tools ? "tools" : "chat"}${x.supports_vision ? " · vision" : ""}${x.supports_audio ? " · audio" : ""}`,
    }));
    setList("tools", tools.tools, (x) => ({
      title: x.name,
      detail: x.description,
      meta: `${x.risk_level} · ${x.approval_required ? "approval required" : x.permission}`,
      tone: x.approval_required ? "attention" : "",
    }));
    setList("backends", backends.backends, (x) => ({
      title: x.name,
      detail: x.description,
      meta: `${x.risk_level} · ${x.enabled ? "enabled" : "disabled"}`,
      tone: x.enabled ? "ready" : "",
    }));
    setList("skill-hub", skillHub.entries, (x) => ({
      title: x.name,
      detail: x.description,
      meta: `${x.category} · ${x.install_mode}`,
    }));
    setList("schedules", schedules.schedules, (x) => ({
      title: x.name,
      detail: x.task_request,
      meta: `${x.status} · ${x.cron} · next ${x.next_run_at}`,
      tone: "attention",
    }));
    setList("sessions", sessions.sessions, (x) => ({
      title: x.title,
      detail: `${x.channel} · ${x.status}`,
      meta: x.updated_at,
    }));
    setList("audit", audit.events, (x) => ({
      title: x.event_type,
      detail: x.task_id || "runtime",
      meta: x.timestamp,
    }));
    setList("tasks", tasks.tasks, (x) => ({
      title: x.user_request,
      detail: x.interpretation,
      meta: `${x.status} · ${x.risk_level}`,
      tone: x.status === "waiting_approval" ? "attention" : x.status === "completed" ? "ready" : "",
    }));
    setList("approvals", approvals.approvals, (x) => ({
      title: x.reason,
      detail: x.task_id || "runtime approval",
      meta: `${x.risk_level} · ${x.created_at}`,
      tone: "attention",
      actions: `
        <button type="button" data-approve="${escapeHtml(x.id)}">Approve</button>
        <button type="button" class="secondary" data-deny="${escapeHtml(x.id)}">Deny</button>
      `,
    }), "No pending approvals");

    state.boards = boards.boards;
    if (!state.selectedBoardId && state.boards.length) {
      state.selectedBoardId = state.boards[0].id;
    }
    renderBoards();
    await renderCards();
  } catch (error) {
    document.getElementById("app-status").textContent = "Error";
    document.getElementById("app-status").className = "status-pill bad";
    document.getElementById("task-output").textContent = error.message;
  }
};

const renderBoards = () => {
  setList("boards", state.boards, (x) => ({
    title: x.name,
    detail: x.id,
    meta: x.updated_at,
    tone: x.id === state.selectedBoardId ? "highlight" : "",
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

document.getElementById("refresh").addEventListener("click", refresh);

document.getElementById("task-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const request = document.getElementById("task-request").value || "Summarize my project safely";
  const path = document.getElementById("task-path").value || undefined;
  const result = await api("/tasks", { method: "POST", body: JSON.stringify({ request, path }) });
  document.getElementById("task-output").textContent = JSON.stringify(result, null, 2);
  await refresh();
});

document.getElementById("approvals").addEventListener("click", async (event) => {
  const approve = event.target.dataset.approve;
  const deny = event.target.dataset.deny;
  if (approve) {
    await api(`/approvals/${approve}/approve`, { method: "POST", body: "{}" });
    await refresh();
  }
  if (deny) {
    await api(`/approvals/${deny}/deny`, { method: "POST", body: "{}" });
    await refresh();
  }
});

document.getElementById("model-auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const provider = document.getElementById("model-provider").value;
  const apiKey = document.getElementById("model-api-key").value;
  await api("/models/auth/login", { method: "POST", body: JSON.stringify({ provider, api_key: apiKey }) });
  document.getElementById("model-api-key").value = "";
  await refresh();
});

document.getElementById("model-auth-logout").addEventListener("click", async () => {
  const provider = document.getElementById("model-provider").value;
  await api("/models/auth/logout", { method: "POST", body: JSON.stringify({ provider }) });
  await refresh();
});

document.getElementById("schedule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await api("/schedules", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("schedule-name").value || "Scheduled task",
      cron: document.getElementById("schedule-cron").value || "@daily",
      task_request: document.getElementById("schedule-task").value || "Summarize my project",
      channel: "web",
    }),
  });
  await refresh();
});

document.getElementById("session-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await api("/sessions", {
    method: "POST",
    body: JSON.stringify({ title: document.getElementById("session-title").value || "Web session", channel: "web" }),
  });
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

document.getElementById("card-board").addEventListener("change", async (event) => {
  state.selectedBoardId = event.target.value;
  await renderCards();
});

document.getElementById("cards").addEventListener("click", async (event) => {
  const card = event.target.dataset.card;
  const lane = event.target.dataset.lane;
  if (!card || !lane) return;
  await api(`/kanban/cards/${card}/move`, { method: "POST", body: JSON.stringify({ lane }) });
  await renderCards();
});

refresh();
