# Architecture

Aegis Agent is organized around explicit runtime boundaries:

- `AgentOrchestrator`: receives user requests, creates durable tasks, invokes planning, policy, execution, receipts, and evidence.
- `TaskPlanner`: plans from trusted user directives only.
- `TaskStateMachine`: keeps tasks resumable across `planned`, `running`, `waiting_approval`, `completed`, `failed`, and `blocked`.
- `ExecutionEngine`: routes plan steps and labels connector output before use.
- `PolicyGate`: audits policy decisions.
- `ToolRouter`: calls scoped connectors.
- `ContextFirewall`: labels trust classes and prevents untrusted content from becoming instructions.
- `MemoryManager`: handles governed memory records.
- `SkillRuntime` and `SkillRegistry`: validate manifests and enforce declared permissions.
- `ConnectorRegistry`: exposes scoped connectors.
- `ApprovalManager`: records human approval decisions.
- `AuditLogger`: writes redacted hash-chained JSONL logs.
- `EvidenceBundleBuilder`: assembles task state plus task-specific audit events, so evidence/timeline views remain complete even after unrelated audit activity.

## Comparable Platform Weaknesses Addressed

- Prompt injection through untrusted content: untrusted classes are labeled and suspicious instructions are quarantined before model-context construction.
- Unsafe community skills: every skill needs a manifest, risk level, sandbox profile, permissions, tests, evals, rollback text, and validation.
- Excessive permission blast radius: connectors declare scopes and high-risk operations require approval.
- Exposed local gateways: network is allowlist-controlled and mock-mode by default.
- Weak multi-agent isolation: approved subagent work is visible through durable delegation cards with tainted-instruction metadata, durable profile and budget snapshots, sanitized handoff receipts, deterministic isolated worker-run receipts, model-ready review packets, approved sanitized model-review receipts, approved scoped autonomy step-plan receipts, and approved isolated autonomy loop rehearsal receipts, but the current runtime does not implement recursive autonomous model-loop subagents; the model is a controlled root orchestrator design.
- Stale or unsafe memory: memory carries source, provenance, confidence, sensitivity, confirmation timestamps, and deletion state.
- Missing audit trails: tasks, policies, connectors, approvals, skills, memories, and receipts are logged.
- Fragile long-running task execution: task state is durable in SQLite and approval-blocked work can resume.

## Data Flow

1. The CLI submits a trusted user directive.
2. The context firewall labels the directive.
3. The planner creates deterministic steps.
4. The policy gate evaluates each step.
5. High-risk work enters the approval queue.
6. Allowed work routes through scoped connectors.
7. Connector output is tainted as tool output and sanitized.
8. The orchestrator writes a receipt and evidence bundle.

## Storage

The current runtime uses local SQLite for tasks, memory, skills, approvals, schedules, sessions, channels, model usage, Kanban, and MCP registrations. Schema changes run through a forward-only `schema_migrations` table with checksums so drift is detected at startup. Audit events are append-only JSONL with a hash chain. This keeps the runtime local-first while leaving a migration path to Postgres and external observability sinks.
