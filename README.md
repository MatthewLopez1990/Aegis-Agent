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
- Dependency-free TUI command deck with a compact startup surface, animated multi-frame Aegis Shield ASCII identity banner, Codex-style `/` command palette, nested `menu operate|govern|build|explore` views, and browser GUI with shield-branded runtime control, task resume/cancel, security posture, approvals, recent tasks, session-linked task recovery, models, channels, tools, schedules, work boards, and audit evidence.
- Approval responses include portable action hints and chat-style utterances such as `approve`, `yes proceed`, `deny`, `no do not do that`, and `let's revert`; inbound channel events can record those replies as approval intents, and an explicit event-id plus approval-id resolver lets future Slack/Discord adapters keep payload-matched safeguards while making operator decisions quick.
- Durable SQLite task, memory, skill, and approval records in `.aegis/aegis.db`.
- Append-only JSONL audit log with secret redaction and hash-chain verification.
- Context firewall that labels trust classes and quarantines prompt-injection patterns in untrusted content.
- Policy engine that can allow, deny, and require approval.
- TOML policy profiles for admin-controlled defaults, network allowlists, shell allowlists, and immutable secret-deny controls.
- Read-only filesystem connector, shell connector with allowlist, HTTP allowlist connector with opt-in live reads, GitHub and GitLab stubs, generic REST stub, mock Microsoft Graph, mock ServiceNow, and mock messaging connectors with optional governed live writes where configured.
- Channel gateway registry with 50+ safe mock adapters plus opt-in signed webhook, chat webhook, and SMTP email delivery slices.
- Model provider abstraction for cloud, local, and custom providers with aliases, fallbacks, secret handles, and usage tracking.
- Live OpenAI, Anthropic, Google Gemini, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax, Z.AI, Qwen, Ollama, LM Studio, and custom OpenAI-compatible model invocation through the local secrets broker, plus model auth login, guarded provider-native handoff targets, and a verified OpenAI/Codex subscription CLI bridge that avoids token import.
- Scheduler with review activation and governed run-due execution, session history, Kanban work boards, governed stdio MCP calls, SOUL/context-file loader, and dry-run migration inspection.
- Built-in governed tool catalog with 69 policy-visible tools covering browser, web, files, shell, memory, media, voice, subagent, research, and MCP capabilities.
- Enterprise readiness snapshots through `aegis enterprise-readiness`, dashboard `enterprise_readiness`, memory health scoring, self-improvement readiness blockers, and a TUI command deck with rotating five-frame shield animation plus active audit/session/approval/model/workspace flags.
- Memory health reports score provenance, confirmation freshness, duplicates, conflicts, recertification, and scoped recall without sending embeddings or content to external services.
- Self-improvement is governed as a state machine: failed task, proposal, sandbox plan, repair candidate, candidate review, apply or rollback, verification receipt, and learned procedural memory.
- Browser and media artifact flows now emit private local artifacts, SHA-256 receipts, sandbox metadata, redacted artifact-facing session fields, selector inspection inventories, explicit browser automation boundary receipts, fail-closed live browser automation preflights, subprocess-isolated local media artifacts with POSIX resource limits where supported, and opt-in provider-backed media artifacts through allowlisted HTTPS APIs with brokered tokens; the dashboard separates completed browser/media hardening controls from deeper work such as live browser automation adapters and provider-specific media adapters with stricter platform sandboxing.
- Browser and media promotion is tracked with a dashboard and TUI readiness checklist covering boundary receipts, taint preservation, artifact hashing, human approval, secret-capture boundaries, media worker sandboxing, live browser automation status, provider media depth, and platform media sandbox profiles.
- Live connector promotion is tracked with a dashboard and TUI readiness checklist covering credential handles, network allowlists, explicit live-enable flags, human approval, receipt redaction, mock fallback, read-surface inventory, point-of-use activation preflight blockers, and promotion scope before real service writes are enabled.
- Remote backend promotion is tracked with a dashboard and TUI readiness checklist covering explicit backend enablement, brokered backend auth, scope limits, resource limits, rollback/cleanup receipts, disabled-backend denial, and provider lifecycle depth.
- Seven execution backend definitions: local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox. Docker, SSH, and hosted sandbox submissions are opt-in; denied backend-gated tool calls expose activation preflight blockers, while approved runs emit activation, execution, and cleanup receipts. Docker enforces container limits, SSH requires allowlisted hosts plus brokered private-key handles, and hosted sandbox calls require allowlisted HTTPS APIs plus brokered tokens. The dashboard separates enabled remote adapters from disabled-but-implemented opt-in adapters so operators can distinguish configuration work from missing backend implementation.
- Virtual skill hub facade representing large external registries without auto-downloading untrusted code.
- Governed skill manifests, signed external skill manifests, and runtime permission enforcement.
- Built-in safe project summary skill and disabled workflow candidate builder.
- Memory CRUD with provenance, confidence, sensitivity, deletion, and secret-like content refusal.
- Action receipts for task execution.

## Important Limits

- OpenAI, Anthropic, Google Gemini, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax, Z.AI, Qwen, Ollama, LM Studio, and configured custom OpenAI-compatible invocation are connected through governed model adapters.
- OpenAI can use a verified local `codex login` subscription through isolated `codex exec` when no OpenAI API key is configured; other provider-native subscription/OAuth/cloud-identity flows remain guarded handoff/status surfaces until scoped bridges are implemented.
- Model-provider egress, including local endpoints with a base URL, must pass the configured policy network allowlist.
- Channel adapters are safe mock adapters until credentials and approval flows are configured; live webhook, chat webhook, and SMTP email slices are opt-in and store sanitized receipts when enabled.
- HTTP is mock-mode by default and requires `live_http_reads = true` plus an allowlisted domain for live reads; redirects are not followed by the governed connector.
- Connectors that need real credentials are mock or placeholder implementations.
- Filesystem writes and shell execution are intentionally constrained.
- Browser rendering is limited to sanitized HTTP-content snapshots with private, redacted evidence artifacts and explicit cookie, storage, script, subresource, network, and mutation boundary receipts; explicit live browser automation requests fail closed with activation blockers, and Aegis still does not execute arbitrary page JavaScript or preserve cookies.
- Hosted remote execution uses a guarded generic submission adapter today; deeper provider-specific lifecycle controls and rollback APIs still need to be implemented before broad production rollout.
- Live third-party integrations still need per-provider credential flows, rate limiting, sandbox hardening, rollback logic, and tests before they should be enabled broadly.

See `docs/getting-started.md`, `docs/security.md`, and `docs/architecture.md` for details.
