# Aegis Agent

Aegis Agent is a local-first, governed AI agent runtime. It focuses on durable tasks, scoped connectors, memory with provenance, governed skills, policy gates, human approvals, context isolation, and append-only audit receipts.

The product direction is parity with modern personal-agent platforms while keeping Aegis stricter by default: external content is tainted, risky tools pause for approval, secrets stay brokered, and every action produces auditable evidence.

## Install

Linux and macOS:

```bash
./install.sh
```

After install:

```bash
aegis --help
aegis dashboard
aegis tui
aegis serve --host 127.0.0.1 --port 8765
```

See `docs/install.md` for one-line archive/Git install commands.

## Run From Source

```bash
PYTHONPATH=src python3 -m aegis.cli.main init
PYTHONPATH=src python3 -m aegis.cli.main dashboard
PYTHONPATH=src python3 -m aegis.cli.main task submit "Summarize my project safely" --path .
PYTHONPATH=src python3 -m aegis.cli.main connector list
PYTHONPATH=src python3 -m aegis.cli.main audit verify
```

Optional local API:

```bash
PYTHONPATH=src python3 -m aegis.cli.main serve --host 127.0.0.1 --port 8765
```

Terminal UI:

```bash
PYTHONPATH=src python3 -m aegis.cli.main tui
```

High-risk actions pause for approval:

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "send message hello"
PYTHONPATH=src python3 -m aegis.cli.main approval list --status pending
PYTHONPATH=src python3 -m aegis.cli.main approval approve APPROVAL_ID
PYTHONPATH=src python3 -m aegis.cli.main task resume TASK_ID
```

## Test

This environment does not include pytest, so the suite uses `unittest` while remaining pytest-discoverable:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## What Is Implemented

- CLI task submission, status, resume, evidence, approvals, memory, skills, connectors, and audit commands.
- Dependency-free local API server for the product dashboard, health checks, connector listing, task submission, status, approvals, schedules, boards, and resume.
- Dependency-free TUI command deck and browser GUI for runtime control, security posture, approvals, recent tasks, models, channels, tools, schedules, work boards, and audit evidence.
- Durable SQLite task, memory, skill, and approval records in `.aegis/aegis.db`.
- Append-only JSONL audit log with secret redaction and hash-chain verification.
- Context firewall that labels trust classes and quarantines prompt-injection patterns in untrusted content.
- Policy engine that can allow, deny, and require approval.
- Read-only filesystem connector, shell connector with allowlist, HTTP allowlist stub, GitHub stub, generic REST stub, mock Microsoft Graph, mock ServiceNow, and mock messaging connectors.
- Channel gateway registry with 50+ safe mock adapters.
- Model provider abstraction for cloud, local, and custom providers with aliases, fallbacks, secret handles, and usage tracking.
- OpenAI and OpenRouter model auth login through the local secrets broker.
- Scheduler, session history, Kanban work boards, MCP registry, SOUL/context-file loader, and dry-run migration inspection.
- Built-in governed tool catalog with 47+ tools covering browser, web, files, shell, memory, media, voice, subagent, research, and MCP capabilities.
- Seven execution backend definitions: local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox.
- Virtual skill hub facade representing large external registries without auto-downloading untrusted code.
- Governed skill manifests and runtime permission enforcement.
- Built-in safe project summary skill and disabled workflow candidate builder.
- Memory CRUD with provenance, confidence, sensitivity, deletion, and secret-like content refusal.
- Action receipts for task execution.

## Important Limits

- No real model provider invocation is connected yet.
- Channel adapters are safe mock adapters until credentials and approval flows are configured.
- HTTP is mock-mode by default.
- Connectors that need real credentials are mock or placeholder implementations.
- Filesystem writes and shell execution are intentionally constrained.
- Live third-party integrations still need per-provider credential flows, webhook verification, rate limiting, sandbox hardening, rollback logic, and tests before they should be enabled broadly.

See `docs/getting-started.md`, `docs/security.md`, and `docs/architecture.md` for details.
