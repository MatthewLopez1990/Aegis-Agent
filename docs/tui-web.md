# TUI and Web GUI

## Terminal UI

Run:

```bash
PYTHONPATH=src python3 -m aegis.cli.main tui
```

Commands:

- `submit <request>`
- `status [task_id]`
- `resume [task_id]`
- `approvals`
- `approve <approval_id>`
- `connectors`
- `channels`
- `models`
- `tools`
- `sessions`
- `audit`
- `exit`

The TUI uses the same orchestrator, policy gate, approval queue, audit logger, and context firewall as the CLI/API.

## Web GUI

Run:

```bash
PYTHONPATH=src python3 -m aegis.cli.main serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/`.

The GUI is static HTML/CSS/JavaScript served by the local API. It exposes task submission and read-only panels for runtime health, connectors, channels, models, tools, schedules, sessions, and audit logs.
It also surfaces execution backend definitions and the virtual skill hub.

## API Endpoints

- `GET /`
- `GET /health`
- `GET /connectors`
- `GET /channels`
- `GET /models`
- `GET /tools`
- `GET /backends`
- `GET /skill-hub`
- `GET /schedules`
- `GET /sessions`
- `GET /audit`
- `POST /tasks`
- `GET /tasks/{task_id}`
- `POST /tasks/{task_id}/resume`
- `POST /sessions`
- `POST /schedules`
- `GET /kanban/boards`
- `POST /kanban/boards`
- `POST /kanban/boards/{board_id}/cards`
