# Aegis Agent

Aegis Agent is a local-first, governed AI agent runtime. It focuses on durable tasks, scoped connectors, memory with provenance, governed skills, policy gates, human approvals, context isolation, and append-only audit receipts.

The product direction is parity with modern personal-agent platforms while keeping Aegis stricter by default: external content is tainted, risky tools pause for approval, secrets stay brokered, and every action produces auditable evidence.

## Install

Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/MatthewLopez1990/Aegis-Agent/main/install.sh | sh
```

After install:

```bash
aegis --help
aegis dashboard
aegis tui
aegis serve --host 127.0.0.1 --port 8765
```

From a local checkout, run `./install.sh`. See `docs/install.md` for archive/Git variants and custom install locations.

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
- Dependency-free TUI command deck with an Aegis ASCII identity banner, grouped command palette, and browser GUI for runtime control, task resume/cancel, security posture, approvals, recent tasks, session-linked task recovery, models, channels, tools, schedules, work boards, and audit evidence.
- Durable SQLite task, memory, skill, and approval records in `.aegis/aegis.db`.
- Append-only JSONL audit log with secret redaction and hash-chain verification.
- Context firewall that labels trust classes and quarantines prompt-injection patterns in untrusted content.
- Policy engine that can allow, deny, and require approval.
- TOML policy profiles for admin-controlled defaults, network allowlists, shell allowlists, and immutable secret-deny controls.
- Read-only filesystem connector, shell connector with allowlist, HTTP allowlist connector with opt-in live reads, GitHub and GitLab stubs, generic REST stub, mock Microsoft Graph, mock ServiceNow, and mock messaging connectors with optional governed live writes where configured.
- Channel gateway registry with 50+ safe mock adapters plus opt-in signed webhook, chat webhook, and SMTP email delivery slices.
- Model provider abstraction for cloud, local, and custom providers with aliases, fallbacks, secret handles, and usage tracking.
- Live OpenAI, Anthropic, Mistral, Cohere, OpenRouter, Ollama, LM Studio, and custom OpenAI-compatible model invocation through the local secrets broker, plus model auth login.
- Scheduler with review activation and governed run-due execution, session history, Kanban work boards, governed stdio MCP calls, SOUL/context-file loader, and dry-run migration inspection.
- Built-in governed tool catalog with 69 policy-visible tools covering browser, web, files, shell, memory, media, voice, subagent, research, and MCP capabilities.
- Browser and media artifact flows now emit private local artifacts, SHA-256 receipts, sandbox metadata, redacted artifact-facing session fields, explicit browser automation boundary receipts, subprocess-isolated local media artifacts with POSIX resource limits where supported, and opt-in provider-backed media artifacts through allowlisted HTTPS APIs with brokered tokens; the dashboard separates completed browser/media hardening controls from deeper work such as live browser automation adapters and provider-specific media adapters with stricter platform sandboxing.
- Seven execution backend definitions: local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox. Docker, SSH, and hosted sandbox submissions are opt-in; approved runs emit activation, execution, and cleanup receipts, with Docker enforcing container limits, SSH requiring allowlisted hosts plus brokered private-key handles, and hosted sandbox calls requiring allowlisted HTTPS APIs plus brokered tokens. The dashboard separates enabled remote adapters from disabled-but-implemented opt-in adapters so operators can distinguish configuration work from missing backend implementation.
- Virtual skill hub facade representing large external registries without auto-downloading untrusted code.
- Governed skill manifests, signed external skill manifests, and runtime permission enforcement.
- Built-in safe project summary skill and disabled workflow candidate builder.
- Memory CRUD with provenance, confidence, sensitivity, deletion, and secret-like content refusal.
- Action receipts for task execution.

## Important Limits

- OpenAI, Anthropic, Google Gemini, Mistral, Cohere, OpenRouter, Ollama, LM Studio, and configured custom OpenAI-compatible invocation are connected through governed model adapters.
- Model-provider egress, including local endpoints with a base URL, must pass the configured policy network allowlist.
- Channel adapters are safe mock adapters until credentials and approval flows are configured; live webhook, chat webhook, and SMTP email slices are opt-in and store sanitized receipts when enabled.
- HTTP is mock-mode by default and requires `live_http_reads = true` plus an allowlisted domain for live reads; redirects are not followed by the governed connector.
- Connectors that need real credentials are mock or placeholder implementations.
- Filesystem writes and shell execution are intentionally constrained.
- Browser rendering is limited to sanitized HTTP-content snapshots with private, redacted evidence artifacts and explicit cookie, storage, script, subresource, network, and mutation boundary receipts; Aegis still does not execute arbitrary page JavaScript or preserve cookies.
- Hosted remote execution uses a guarded generic submission adapter today; deeper provider-specific lifecycle controls and rollback APIs still need to be implemented before broad production rollout.
- Live third-party integrations still need per-provider credential flows, rate limiting, sandbox hardening, rollback logic, and tests before they should be enabled broadly.

See `docs/getting-started.md`, `docs/security.md`, and `docs/architecture.md` for details.
