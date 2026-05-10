const json = async (url, options = {}) => {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  return response.json();
};

const item = (title, detail = "") => {
  const node = document.createElement("div");
  node.className = "item";
  node.innerHTML = `<strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span>`;
  return node;
};

const setList = (id, rows, titleFn, detailFn) => {
  const node = document.getElementById(id);
  node.replaceChildren(...rows.map((row) => item(titleFn(row), detailFn(row))));
};

const setStats = (data) => {
  const node = document.getElementById("health");
  const stats = [
    ["Audit", data.audit_chain_ok ? "verified" : "failed"],
    ["Connectors", String(data.connectors.length)],
    ["Channels", String(data.channels.length)],
    ["Status", data.ok ? "healthy" : "degraded"],
  ];
  node.replaceChildren(
    ...stats.map(([label, value]) => {
      const stat = document.createElement("div");
      stat.className = "stat";
      stat.innerHTML = `<strong>${escapeHtml(value)}</strong><span>${escapeHtml(label)}</span>`;
      return stat;
    })
  );
};

const refresh = async () => {
  const [health, connectors, channels, models, modelProviders, tools, backends, skillHub, schedules, sessions, audit] = await Promise.all([
    json("/health"),
    json("/connectors"),
    json("/channels"),
    json("/models"),
    json("/model-providers"),
    json("/tools"),
    json("/backends"),
    json("/skill-hub"),
    json("/schedules"),
    json("/sessions"),
    json("/audit"),
  ]);
  setStats(health);
  setList("connectors", connectors.connectors, (x) => x.name, (x) => `${x.default_mode} · ${x.supported_operations.join(", ")}`);
  setList("channels", channels.channels, (x) => x.name, (x) => `${x.difficulty} · ${x.rich_messages.join(", ")}`);
  setList(
    "model-providers",
    modelProviders.providers.filter((x) => ["openai", "openrouter"].includes(x.provider)),
    (x) => x.provider,
    (x) => x.auth_configured ? `auth configured via ${x.auth_source}` : "auth missing"
  );
  setList("models", models.models.slice(0, 24), (x) => x.identifier, (x) => x.local ? "local" : (x.auth_configured ? "cloud · auth configured" : "cloud · auth missing"));
  setList("tools", tools.tools, (x) => x.name, (x) => `${x.risk_level} · ${x.permission}`);
  setList("backends", backends.backends, (x) => x.name, (x) => `${x.risk_level} · ${x.enabled ? "enabled" : "disabled"}`);
  setList("skill-hub", skillHub.entries, (x) => x.name, (x) => `${x.category} · ${x.install_mode}`);
  setList("schedules", schedules.schedules, (x) => x.name, (x) => `${x.status} · ${x.cron}`);
  setList("sessions", sessions.sessions, (x) => x.title, (x) => `${x.channel} · ${x.status}`);
  setList("audit", audit.events, (x) => x.event_type, (x) => x.timestamp);
};

document.getElementById("refresh").addEventListener("click", refresh);

document.getElementById("model-auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const provider = document.getElementById("model-provider").value;
  const apiKey = document.getElementById("model-api-key").value;
  await json("/models/auth/login", { method: "POST", body: JSON.stringify({ provider, api_key: apiKey }) });
  document.getElementById("model-api-key").value = "";
  refresh();
});

document.getElementById("model-auth-logout").addEventListener("click", async () => {
  const provider = document.getElementById("model-provider").value;
  await json("/models/auth/logout", { method: "POST", body: JSON.stringify({ provider }) });
  refresh();
});

document.getElementById("task-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const request = document.getElementById("task-request").value || "Summarize my project safely";
  const path = document.getElementById("task-path").value || undefined;
  const result = await json("/tasks", { method: "POST", body: JSON.stringify({ request, path }) });
  document.getElementById("task-output").textContent = JSON.stringify(result, null, 2);
  refresh();
});

document.getElementById("schedule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await json("/schedules", {
    method: "POST",
    body: JSON.stringify({
      name: document.getElementById("schedule-name").value,
      cron: document.getElementById("schedule-cron").value || "@daily",
      task_request: document.getElementById("schedule-task").value,
      channel: "web",
    }),
  });
  refresh();
});

document.getElementById("session-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await json("/sessions", {
    method: "POST",
    body: JSON.stringify({ title: document.getElementById("session-title").value || "Web session", channel: "web" }),
  });
  refresh();
});

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

refresh();
