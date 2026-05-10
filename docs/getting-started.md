# Getting Started

## Install

From the repository root on Linux or macOS:

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

## Submit a Safe Task

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "Summarize my project safely" --path .
```

The runtime creates a durable task record, reads the scoped filesystem through the connector, labels tool output as untrusted, writes an audit log, and returns a receipt.

## Submit a High-Risk Task

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "send message hello"
PYTHONPATH=src python3 -m aegis.cli.main approval list --status pending
PYTHONPATH=src python3 -m aegis.cli.main approval approve APPROVAL_ID
PYTHONPATH=src python3 -m aegis.cli.main task resume TASK_ID
```

The task pauses until approval is recorded.

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

## Run TUI

```bash
PYTHONPATH=src python3 -m aegis.cli.main tui
```
