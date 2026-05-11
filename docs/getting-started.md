# Getting Started

## Install

On Linux or macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/MatthewLopez1990/Aegis-Agent/main/install.sh | sh
```

From a repository checkout:

```bash
./install.sh
```

Then verify:

```bash
aegis --help
```

## Initialize

```bash
PYTHONPATH=src python3 -m aegis.cli.main init
```

This creates `.aegis/config.toml`, `.aegis/aegis.db`, and `.aegis/audit.jsonl`.

Check the local schema migration status:

```bash
PYTHONPATH=src python3 -m aegis.cli.main migrate schema
```

## Submit a Safe Task

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "Summarize my project safely" --path .
```

The runtime creates a durable task record, reads the scoped filesystem through the connector, labels tool output as untrusted, writes an audit log, and returns a receipt.

## Submit a High-Risk Task

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "send message hello"
PYTHONPATH=src python3 -m aegis.cli.main approval list --status pending
PYTHONPATH=src python3 -m aegis.cli.main approval approve APPROVAL_ID --actor local-user --reason "reviewed payload"
PYTHONPATH=src python3 -m aegis.cli.main task resume TASK_ID
```

The task pauses until approval is recorded.
If a policy profile returns `require_admin_approval`, approve with `--admin`; a regular approval records reviewer evidence but will not unblock that gate.

## Run Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Run Local API

```bash
PYTHONPATH=src python3 -m aegis.cli.main serve --host 127.0.0.1 --port 8765
```

Endpoints:

- `GET /health`
- `GET /connectors`
- `POST /tasks`
- `GET /tasks/{task_id}`
- `POST /tasks/{task_id}/resume`
- `POST /tasks/{task_id}/pause`
- `POST /tasks/{task_id}/cancel`

Task status and pause/resume/cancel responses include the linked session snapshot when the task was submitted inside a conversation session.

## Run TUI

```bash
PYTHONPATH=src python3 -m aegis.cli.main tui
```
