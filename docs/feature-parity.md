# Feature Parity Plan

This document maps the public Hermes Agent and OpenClaw feature surface into Aegis Agent capabilities while preserving Aegis security controls. The goal is support parity through safe interfaces first, then selectively enable live integrations behind permissions, approvals, taint tracking, and audit receipts.

## Current Public Feature Surface

Evidence used for this pass:

- Hermes README describes a self-improving agent with model switching, full TUI, messaging gateway, closed learning loop, scheduler, subagents, multiple terminal backends, and research tooling.
- Hermes community Web UI describes layered local memory, automatic skills, scheduling, multi-surface access, 47 tools, MCP, voice mode, terminal backends, personalities, agent orchestration, and a three-panel browser UI.
- OpenClaw docs describe agents as model, memory, tool, and channel layers with persistent memory, 5,700+ skills, 50+ channels, multi-step planning, and proactive scheduling.
- OpenClaw channel docs describe adapter responsibilities: inbound normalization, outbound rendering, auth/webhooks, rich messages, and multi-channel deployment.
- OpenClaw tool docs identify web search, calculator, file read/write, HTTP request, shell, memory store, and memory recall with risk levels.
- OpenClaw model docs describe model-agnostic routing, local Ollama models, cloud providers, aliases, fallbacks, usage and cost controls.

## Implemented Support

### Memory and Self-Improvement

- Governed memory records with provenance, confidence, sensitivity, confirmation, deletion, conflict detection, merging, expiration, search, and audit.
- Skill manifests with permissions, risk classification, tests, evals, rollback, sandbox profile, enable/disable controls, and runtime permission enforcement.
- Workflow candidate skill and skill template generation keep generated procedures disabled or approval-required until reviewed.

### TUI and Web GUI

- `aegis tui` provides a terminal agent interface with task submission, status, approvals, connectors, channels, models, tools, sessions, and audit commands.
- `aegis serve` provides a browser GUI with task submission plus panels for runtime health, connectors, channels, models, tools, schedules, sessions, and audit logs.

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
