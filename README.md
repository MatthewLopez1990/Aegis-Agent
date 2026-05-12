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
- Live OpenAI, Anthropic, Google Gemini API key or configured Vertex AI cloud identity, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax, Z.AI, Qwen API key or verified Qwen Code Coding Plan subscription, GitHub Copilot through verified Copilot CLI login, AWS Bedrock through verified AWS CLI cloud identity, Ollama, LM Studio, configured Azure Foundry/OpenAI v1 through API key or verified Azure CLI cloud identity, and custom OpenAI-compatible model invocation through the local secrets broker, plus model auth login and verified Codex/Claude Code/Qwen Code/Copilot CLI bridges that avoid token import.
- Scheduler with review activation and governed run-due execution, session history, Kanban work boards, approval-gated subagent delegation queue/status surfaces, governed stdio MCP calls, local lifecycle hooks with approval defaults and redacted receipts, governed local plugin lifecycle for skills/MCP/hooks, SOUL/context-file loader, and dry-run migration inspection.
- Built-in governed tool catalog with 69 policy-visible tools covering browser, web, files, shell, memory, media, voice, subagent, research, and MCP capabilities.
- Enterprise readiness snapshots through `aegis enterprise-readiness`, dashboard `enterprise_readiness`, memory health scoring, self-improvement readiness blockers, and a TUI command deck with rotating five-frame shield animation plus active audit/session/approval/model/workspace flags.
- Memory health reports score provenance, confirmation freshness, duplicates, conflicts, recertification, and scoped recall without sending embeddings or content to external services.
- Self-improvement is governed as a state machine: failed task, proposal, sandbox plan, repair candidate, candidate review, apply or rollback, verification receipt, and learned procedural memory.
- Browser and media artifact flows now emit private local artifacts, SHA-256 receipts, sandbox metadata, redacted artifact-facing session fields, selector inspection inventories, explicit browser automation boundary receipts, fail-closed live browser automation preflights, subprocess-isolated local media artifacts with POSIX resource limits where supported, and opt-in provider-backed media artifacts through allowlisted HTTPS APIs with brokered tokens; the dashboard separates completed browser/media hardening controls from deeper work such as live browser automation adapters and provider-specific media adapters with stricter platform sandboxing.
- Browser and media promotion is tracked with a dashboard and TUI readiness checklist covering boundary receipts, taint preservation, artifact hashing, human approval, secret-capture boundaries, media worker sandboxing, live browser automation status, provider media depth, and platform media sandbox profiles.
- Live connector promotion is tracked with a dashboard and TUI readiness checklist covering credential handles, network allowlists, explicit live-enable flags, human approval, receipt redaction, mock fallback, read-surface inventory, point-of-use activation preflight blockers, and promotion scope before real service writes are enabled.
- Remote backend promotion is tracked with a dashboard and TUI readiness checklist covering explicit backend enablement, brokered backend auth, scope limits, resource limits, rollback/cleanup receipts, disabled-backend denial, and provider lifecycle depth.
- Local remote-control pairings can be created and revoked from CLI/TUI or the web API. Pairing tokens are returned once, stored only as hashes in `.aegis/remote_control_pairings.json`, scoped to remote task-control endpoints, and audited without raw token capture.
- Seven execution backend definitions: local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox. Docker, SSH, and hosted sandbox submissions are opt-in; denied backend-gated tool calls expose activation preflight blockers, while approved runs emit activation, execution, and cleanup receipts. Docker enforces container limits, SSH requires allowlisted hosts plus brokered private-key handles, and hosted sandbox calls require allowlisted HTTPS APIs plus brokered tokens. The dashboard separates enabled remote adapters from disabled-but-implemented opt-in adapters so operators can distinguish configuration work from missing backend implementation.
- Virtual skill hub facade representing large external registries without auto-downloading untrusted code.
- Governed skill manifests, signed external skill manifests, and runtime permission enforcement.
- Built-in safe project summary skill and disabled workflow candidate builder.
- Memory CRUD with provenance, confidence, sensitivity, deletion, and secret-like content refusal.
- Action receipts for task execution.

## Important Limits

- OpenAI, Anthropic, Google Gemini API key or configured Vertex AI cloud identity, Mistral, Cohere, OpenRouter, Nous, DeepSeek, xAI, Kimi, MiniMax, Z.AI, Qwen API key or verified Qwen Code Coding Plan subscription, GitHub Copilot through verified Copilot CLI login, AWS Bedrock through verified AWS CLI cloud identity, Ollama, LM Studio, configured Azure Foundry/OpenAI v1 through API key or verified Azure CLI cloud identity, and configured custom OpenAI-compatible invocation are connected through governed model adapters.
- OpenAI and Anthropic can use verified local Codex/Claude Code subscriptions through isolated official CLI invocation when no API key is configured; Qwen can use a verified official Qwen Code Coding Plan subscription through headless JSON mode; Copilot can use verified official `copilot -p` JSON mode with remote/repo-hooks/workspace-MCP disabled; Google Vertex AI can use verified gcloud identity through the REST `generateContent` endpoint; AWS Bedrock can use verified AWS CLI SSO/IAM identity through `bedrock-runtime converse`; configured Azure Foundry can use verified Azure CLI identity through `az rest`; other provider-native subscription/OAuth/cloud-identity flows remain guarded handoff/status surfaces until scoped bridges are implemented.
- Model-provider egress, including local endpoints with a base URL, must pass the configured policy network allowlist.
- Channel adapters are safe mock adapters until credentials and approval flows are configured; live webhook, chat webhook, and SMTP email slices are opt-in and store sanitized receipts when enabled.
- HTTP is mock-mode by default and requires `live_http_reads = true` plus an allowlisted domain for live reads; redirects are not followed by the governed connector.
- Connectors that need real credentials are mock or placeholder implementations.
- Filesystem writes and shell execution are intentionally constrained.
- Browser rendering is limited to sanitized HTTP-content snapshots with private, redacted evidence artifacts and explicit cookie, storage, script, subresource, network, and mutation boundary receipts; explicit live browser automation requests fail closed with activation blockers, and Aegis still does not execute arbitrary page JavaScript or preserve cookies.
- Off-device remote-control relay, mobile push delivery, and cloud session directory remain blocked until explicit relay transport, brokered relay auth, origin allowlists, revocation propagation, and redacted relay receipts are implemented.
- Hosted remote execution uses a guarded generic submission adapter today; deeper provider-specific lifecycle controls and rollback APIs still need to be implemented before broad production rollout.
- Live third-party integrations still need per-provider credential flows, rate limiting, sandbox hardening, rollback logic, and tests before they should be enabled broadly.

See `docs/getting-started.md`, `docs/security.md`, and `docs/architecture.md` for details.
