# TUI and Web GUI

## Terminal UI

Run:

```bash
PYTHONPATH=src python3 -m aegis.cli.main tui
```

Commands:

- `dashboard`
- `submit <request>`
- `status [task_id]`
- `resume [task_id]`
- `tasks`
- `approvals`
- `approve <approval_id>`
- `deny <approval_id>`
- `connectors`
- `channels`
- `models`
- `tools`
- `skills`
- `sessions`
- `schedules`
- `boards`
- `backends`
- `security`
- `capabilities`
- `audit`
- `exit`

The TUI uses the same orchestrator, policy gate, approval queue, audit logger, and context firewall as the CLI/API.
It starts with a product command deck that summarizes runtime counts, security controls, and parity-oriented capability groups. Plain text submits a task, and slash aliases such as `/tasks` work for chat-style operation.

## Web GUI

Run:

```bash
PYTHONPATH=src python3 -m aegis.cli.main serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/`.

The GUI is static HTML/CSS/JavaScript served by the local API. It exposes task submission, the approval queue, recent tasks, runtime health, security controls, parity targets, connectors, channels, models, tools, schedules, sessions, work boards, and audit logs.
It also surfaces execution backend definitions and the virtual skill hub.

## API Endpoints

- `GET /`
- `GET /dashboard`
- `GET /health`
- `GET /connectors`
- `GET /channels`
- `GET /channel-events`
- `GET /models`
- `GET /model-providers`
- `GET /tools`
- `GET /backends`
- `GET /skill-hub`
- `GET /schedules`
- `GET /sessions`
- `GET /tasks`
- `GET /approvals`
- `GET /memory?q=...`
- `GET /audit`
- `POST /tasks`
- `GET /tasks/{task_id}`
- `POST /tasks/{task_id}/resume`
- `POST /approvals/{approval_id}/approve`
- `POST /approvals/{approval_id}/deny`
- `POST /sessions`
- `POST /schedules`
- `GET /kanban/boards`
- `POST /kanban/boards`
- `GET /kanban/boards/{board_id}/cards`
- `POST /kanban/boards/{board_id}/cards`
- `POST /kanban/cards/{card_id}/move`
