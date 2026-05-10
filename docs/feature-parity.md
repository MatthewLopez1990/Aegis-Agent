# Feature Parity Plan

This document maps the public Hermes Agent and OpenClaw feature surface into Aegis Agent capabilities while preserving Aegis security controls. The goal is support parity through safe interfaces first, then selectively enable live integrations behind permissions, approvals, taint tracking, and audit receipts.

## Current Public Feature Surface

Evidence used for the May 2026 pass:

- Hermes README describes a self-improving agent with model switching, full TUI, messaging gateway, closed learning loop, scheduler, subagents, multiple terminal backends, and research tooling.
- Hermes v0.13 release notes emphasize durable Kanban, checkpoints, gateway auto-resume, watchdog scheduling, default redaction, role allowlists, stranger rejection, and OAuth TOCTOU fixes.
- OpenClaw docs describe a single Gateway, built-in and plugin channels, multi-agent routing with isolated sessions, streaming and chunking, 35+ providers, media, Web Control UI, mobile nodes, browser automation, web search, cron jobs, skills, plugins, and workflow pipelines.
- OpenClaw TUI docs describe local and gateway mode, header/status/footer, chat log with tool cards, autocomplete, slash commands, local shell commands, history, streaming, and connection repair.

## Implemented Support

### Memory and Self-Improvement

- Governed memory records with provenance, confidence, sensitivity, confirmation, deletion, conflict detection, merging, expiration, search, and audit.
- Skill manifests with permissions, risk classification, tests, evals, rollback, sandbox profile, enable/disable controls, and runtime permission enforcement.
- Workflow candidate skill and skill template generation keep generated procedures disabled or approval-required until reviewed.

### TUI and Web GUI

- `aegis tui` provides a terminal command deck with task submission, status, recent tasks, approvals, security posture, capability groups, connectors, channels, models, tools, skills, schedules, sessions, work boards, backends, and audit commands.
- `aegis serve` provides a browser GUI with task submission plus panels for runtime health, security controls, competitive parity targets, connectors, channels, models, tools, schedules, sessions, work boards, approvals, recent tasks, and audit logs.
- `aegis dashboard` and `GET /dashboard` expose live runtime counts, security controls, capability groups, and parity targets without exposing raw secrets or payloads.

### Channels and Gateway

- Channel registry supports 50+ safe mock adapters, including terminal, web, API, Telegram, Discord, Slack, WhatsApp, Signal, Matrix, Email, Microsoft Teams, Google Chat, Feishu/Lark, WeChat, iMessage, SMS, Mattermost, Home Assistant, DingTalk, WeCom, BlueBubbles, issue trackers, service desks, social platforms, webhooks, RSS, and event buses.
- Inbound content is normalized and processed as untrusted chat content through the context firewall.
- Outbound channel rendering is marked pending approval by default.

### Tools and Connectors

- Tool catalog covers 47+ governed tools across calculator, web search/extraction, HTTP/REST/webhooks, browser actions, file read/write, shell/code/container execution, memory, vision, image generation/editing, TTS, voice/video, calendars, email, contacts, documents, spreadsheets, Git/GitHub, databases, RSS, weather/maps, translation, scheduling, Kanban, research trajectories, subagent delegation, and MCP calls.
- Connectors include local filesystem, shell, HTTP, GitHub, generic REST, Microsoft Graph, ServiceNow, and messaging.
- Dangerous tools and writes require scoped permissions and approval.

### Models

- Model registry supports OpenAI, Anthropic, Google, Mistral, Cohere, OpenRouter, Ollama, LM Studio, and custom endpoints.
- Aliases, fallback routes, usage tracking, cost estimation, and secret handles are implemented without exposing raw secrets to model-facing code.

### Scheduling and Work Orchestration

- Schedule manager creates paused schedules with cron-like metadata and next-run estimates.
- Kanban manager provides durable boards and cards for multi-agent-style work coordination.
- Sessions and message history are persisted and compactable.
- Seven execution backends are represented as policy-visible capabilities: local, Docker, SSH, Singularity, Modal, Daytona, and Vercel Sandbox.
- The virtual Skill Hub facade represents 5,700+ potential skills without auto-downloading untrusted code.

### MCP and Migration

- MCP server registry stores disabled-by-default server definitions with allowed tool lists and approval requirements.
- OpenClaw/Hermes migration inspection is dry-run only and blocks direct secret import by default.

## Safety Delta Over Hermes/OpenClaw Defaults

- External content never becomes instructions; connector, channel, tool, and skill outputs are tainted.
- Receipts omit raw untrusted blobs and retain sanitized summaries.
- Secrets use brokered handles and are redacted from logs.
- High-risk tools, connector writes, message sends, shell execution, MCP calls, and generated skills require approval.
- Mock adapters are the default for high-blast-radius capabilities until a scoped live connector is explicitly configured.

## Remaining Live-Integration Work

Aegis now supports the feature categories through secure interfaces, but most third-party services are intentionally mock/stub mode. Live parity requires per-provider credential flows, webhook verification, rate limiting, sandbox hardening, rollback logic, and tests before enabling each adapter.
