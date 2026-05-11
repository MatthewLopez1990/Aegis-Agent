# TUI and Web GUI

## Terminal UI

Run:

```bash
PYTHONPATH=src python3 -m aegis.cli.main tui
```

Commands:

- `dashboard`
- `submit <request>`
- `status [task_id]`
- `resume [task_id]`
- `cancel [task_id] [reason]`
- `tasks [all|session <session_id>] [--limit N]`
- CLI `task list [--session-id <session_id>] [--limit N]`
- `approvals`
- `approve <approval_id> [--actor name] [--reason text] [--admin]`
- `deny <approval_id> [--actor name] [--reason text] [--admin]`
- `connectors`
- `channels`
- `channel render <channel> <text>`
- `channel receive <channel> <text>`
- `channel send-webhook <text> --approved`
- `channel send-email <subject> <text> --approved`
- `channel send-chat-webhook <text> --approved`
- `channel events [limit]`
- `events [task_id]`
- `models`
- `models list`
- `models route <identifier>`
- `models alias <alias> <identifier>`
- `models fallbacks <identifier> <fallback> [fallback...]`
- `models usage`
- `models auth [provider]`
- `models auth login <provider>`
- `models auth logout <provider>`
- `tools`
- `skills [hub query|disable skill_id|enable skill_id]`
- `memory search <query>`
- `memory session-preview <session_id> [--owner name] [--scope scope]`
- `memory create <type> <content> [--confidence N] [--tag tag] [--ttl-days N] [--confirmed]`
- `memory review-queue [limit|--limit N] [--scope scope]`
- `memory review-digest [limit|--limit N] [--scope scope]`
- `memory review-escalation [--max-age-days N] [--limit N] [--scope scope] [--route name]`
- `memory recertify [--max-age-days N] [--limit N] [--scope scope] [--dry-run]`
- `memory update <memory_id> [--content text] [--confidence N] [--confirmed]`
- `memory merge <primary_id> <duplicate_id>`
- `memory expire <memory_id>`
- `memory cleanup-expired`
- `memory explain <memory_id> <query>`
- `memory export [query]`
- `memory delete <memory_id>`
- `migrate openclaw|hermes|openclaw-memory-preview|hermes-memory-preview|openclaw-memory-commit|hermes-memory-commit <path> [--owner USER] [--scope SCOPE]`
- `mcp list|register <name> <command> <tool,tool>|call <server> <tool> <json> [--approved]`
- `session [new <title>|open <session_id>|rename <title>|set-model <model>|set-personality <name>|activate|archive|pause|append <content> [--role user|assistant] [--trust-class CLASS]|history [session_id] [--limit N]|tasks [--limit N]|compact [keep_last]]`
- `sessions [--limit N]`
- `schedules`
- `schedule create <name> <cron> <task_request> [--natural-language text] [--channel name]`
- `schedule memory-review-digest <name> <cron> [--channel name] [--limit N] [--scope scope]`
- `schedule memory-review-escalation <name> <cron> [--channel name] [--max-age-days N] [--limit N] [--scope scope] [--route name]`
- `schedule evaluation-run <name> <cron> <scenario> [steps...] [--channel name] [--reviewer name]`
- `schedule evaluation-suite <name> <cron> [--suite name] [--scenario-id id] [--channel name] [--reviewer name]`
- `schedule due`
- `schedule approve|activate|pause <id>`
- `schedule run-due`
- `evaluation queue [--reviewer name] [--limit N]`
- `evaluation review <report-id> <reviewed_passed|reviewed_failed|needs_followup|dismissed> [--reviewer name] [--notes text]`
- `evaluation trends [--limit N]`
- `evaluation delta [--baseline-report-id id --candidate-report-id id] [--scenario name]`
- `evaluation readiness [--baseline-report-id id --candidate-report-id id] [--scenario name] [--reviewer name] [--limit N]`
- `browser session|sessions|close [session_id]|navigate <url>`
- `browser extract|inspect|table [selector]|screenshot|render|click <selector> [--approval-id id]|fill <json> [--approval-id id]`
- `boards`
- `backends`
- `security [profile|evaluate <operation> <risk> <scopes> [target_domain]]`
- `capabilities` shows capability groups plus implementation-readiness buckets.
- `audit [export-siem [limit]]`
- `exit`

The TUI uses the same orchestrator, policy gate, approval queue, audit logger, and context firewall as the CLI/API.
Policies can require admin approval; use `approve <approval_id> --admin` for those gates.
It starts with a product command deck that summarizes runtime counts, security controls, parity-oriented capability groups, and implementation-readiness buckets for ready, facade, mock/placeholder, and backend-gated tools. Plain text submits a task, slash aliases such as `/tasks` work for chat-style operation, tab completion covers top-level commands plus common subcommands, and local readline history persists in `.aegis/tui_history` with private file permissions.
Task lists, task cards, evidence, and timeline views show the linked session when a task belongs to a conversation.
Resume attempts write explicit audit events with redacted session ids plus readable context refs, so evidence and timeline views can show which original context was used after approval without weakening audit redaction. Distinct resume outcomes, including intermediate `waiting_approval`, approved, and denied states, are appended back to the original session transcript. When a TUI resume command targets a task from another active conversation, the TUI switches its active session back to that originating transcript after the resume result is recorded.
Approval queues and approval details also show linked session context for task-bound approvals and direct runtime session ids for browser approvals. In the TUI, approval rows and detail views include copyable next steps plus chat-style phrases such as `approve`, `yes proceed`, `deny`, `no do not do that`, and `let's revert` when those intents are safe for the current approval state. The web approval detail card collects actor, reason, and admin-decision metadata before approving or denying, the same decision payload is used by inline transcript approval actions, and the approval panel keeps a bounded recent decision history for approved and denied gates.
CLI and API approval list/approve/deny responses include the same linked session fields for task-bound approvals plus machine-readable `action_hints` for approval review, approve, deny, reject/revert intent, `session show`, `session history`, and approved task resume follow-up commands. These hints are designed for terminal use and future Slack/Discord adapters while preserving exact approval-payload matching before execution.
Inbound channel receive commands can recognize those same short Slack/Discord-style replies as `approval_intent` metadata on the stored channel event. The intent is deliberately non-executing: it records `auto_execute: false` and requires a client to match the current approval id and call the normal approval action before any state changes.
Browser commands use the dependency-light HTTP-content sandbox. It does not run page JavaScript, maintain cookies, perform real selector clicks, or capture the original live page DOM. Table extraction supports a conservative table selector subset (`table`, `#id`, `.class`, `table#id`, and `table.class`), unsupported selectors are reported truthfully, screenshot actions write deterministic local PNG session snapshots plus redacted text sidecars and structured JSON evidence artifacts, and render actions can create a sanitized Chrome-rendered PNG from stored HTTP text/table state without preserving original scripts, styles, iframes, forms, cookies, or remote subresources. Browser artifact files and sidecars are written with private file permissions under the private browser artifact directory, and artifact-facing URL, title, selector, virtual state, and persisted session fields pass through the secret redactor. The API returns authenticated `/browser-artifacts/...` links for the GUI to open those artifacts without exposing arbitrary filesystem paths. Approved click/fill commands record virtual interaction state. Navigation responses include a bounded static `interactive_elements` index for links, buttons, inputs, textareas, and selects; `browser inspect` and `POST /browser/inspect` expose the same redacted selector inventory with supported virtual actions, approval requirements, unsupported live actions, readiness status, and automation-boundary receipts. The GUI renders those entries as selectable rows that populate the selector and fill-field controls without executing page code. Browser action responses include auditable evidence metadata with URL-before/after, bounded redacted content hashes, content-changed status, DOM-mutated status, click count, form-field count, sandbox receipts, and SHA-256 hashes for the emitted PNG, metadata, and evidence artifacts. Snapshot evidence JSON records the non-rendered capture surface, content hash, static interactive-element count, parser-derived table counts, redacted virtual click/fill state, artifact hashes, sandbox boundaries, and explicit limitations; render evidence JSON records the sanitized render surface and renderer receipt. Both evidence formats now include a `browser_automation_boundaries_v1` block covering navigation network, remote subresources, page script execution, cookies, cookie jars, local/session storage, selector-event dispatch, page mutation, virtual-only interactions, and the safety controls required before a live browser automation adapter can be enabled. Browser sessions persist redacted, bounded snapshots under `.aegis/browser/sessions.json`, so the GUI can recover navigation, table extraction, and virtual interaction state after a server restart without storing raw secret-shaped values. Browser click and fill commands create approval records first; after approving with `approve <approval_id>`, rerun the same browser command with `--approval-id <approval_id>`.

Tool commands use JSON parameters and the same approval semantics as the governed tool catalog:

```text
tool run calculator '{"expression":"2+2"}'
tools run service_ticket_read '{"query":"incident"}'
tools run service_ticket_write '{"operation":"close","ticket":{"id":"INC000001"}}' --approved
```

## Web GUI

Run:

```bash
PYTHONPATH=src python3 -m aegis.cli.main serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/`.

The CLI, TUI, and GUI all expose the governed tool catalog plus a conservative tool runner. The TUI dashboard opens with a stable Aegis ASCII identity banner and grouped command palette, and the `menu` command renders a polished grouped command view before operators drill into competitive parity targets with their remaining live-integration gaps plus the structured live-gap backlog, including the controls and verification gates needed before each gap can be closed. The TUI capabilities view and GUI live-gap cards also expose the browser/media readiness checklist for boundary receipts, taint preservation, artifact hashing, approval, secret-capture boundaries, media sandboxing, live automation status, and provider depth; live connector readiness for credential handles, allowlists, enablement flags, approval, redaction, mock fallback, read inventory, and promotion scope; plus remote backend readiness for explicit enablement, brokered auth, scope/resource limits, rollback receipts, disabled-backend denial, and lifecycle depth. The GUI parity cards render the same gap metadata. The GUI is static HTML/CSS/JavaScript served by the local API. It exposes task submission, the approval queue, recent tasks, a dedicated session-linked task recovery feed, runtime health, security controls, parity targets, connectors with operation risk/scope/sensitivity metadata, channels, outbound channel rendering, channel events, governed memory create/search/update/explain/export/delete controls, session memory preview and commit controls, Hermes/OpenClaw memory migration preview and commit controls, models with provider/model usage telemetry, tools, installed governed skill inventory, virtual Skill Hub search, a conservative tool runner, browser sandbox actions, schedules, scheduled evaluation runs, evaluation review queues, trend dashboards, regression deltas, release readiness summaries, session create/update controls, work boards, verified repair attempts, audit logs, and normalized SIEM JSONL audit export.
When a task belongs to a session, GUI resume first reloads the task and resumes it against that original session context, even if another session is currently selected.
Recent task rows, task result cards, and task evidence cards show the linked session id or title so resumed work remains visibly tied to its original conversation. Task result and evidence cards also expose an Open Session action that switches the browser transcript back to that originating session.
Session transcript bubbles show message source, task id, resume status, and checkpoint approval id metadata when present, so resume results in the original conversation are distinguishable from ordinary assistant turns.
The `/sessions/{id}/messages` API includes current task and approval status plus `action_hints` for task-linked and checkpoint-approval-linked transcript entries, including `resume <task>` for waiting or paused task results. TUI `session history` exposes those hints as copyable next-step commands for terminal transcript review, while the web transcript renders the same task and approval review/approve/deny actions inline.
The `/tasks`, `/sessions/{id}/tasks`, `/approvals`, and `/approvals/{id}` API responses also include session `action_hints` for linked tasks and approvals, so API clients can discover the exact session show/history commands before approving or resuming work.
The browser smoke test exercises the full API-to-DOM path for a session-bound approval resume and verifies the transcript renders the resume metadata.
Approval rows and approval detail cards show linked session context for task-bound approvals and direct runtime session ids for browser approvals, with an Open Session action when a safe session id is available.
The Recent Tasks panel can switch between the active session and all tasks, matching the TUI `tasks all|session` workflow. TUI task-list rows include copyable status/events/timeline commands plus session open/history commands for session-bound tasks. TUI session-list rows include copyable session open/history commands and a task-history command when tasks exist. Session rows in the GUI also expose a separate `Tasks` action so operators can inspect another session's task history without changing the active transcript used for new submissions or context appends.
Task timeline, run-event snapshots, run-event cards, and run-event stream headers also include the linked session snapshot when one exists. Run-event snapshots expose aggregate progress metrics such as step totals, completed/waiting/failed step counts, event totals, latest sequence, event counts by kind/status, and sanitized provider/tool substep counts by kind/status; the TUI `events [task_id]` command renders those progress metrics with grouped step and provider substep tables, and the GUI renders the same metrics above grouped step cards and provider substep cards. The event stream supports a bounded follow mode with task-status and heartbeat frames that include the same progress block, so the web console can show live progress without keeping an unbounded server connection open. The GUI re-renders status-only heartbeat/task-status frames as visible progress cards even before run-event rows arrive. Stream clients can pass `since=<sequence>` or `Last-Event-ID: <task_id>:<sequence>` to resume incrementally without replaying older run events. The GUI uses authenticated fetch streaming with `live=1`, bounded server timeouts, and cursor-based reconnects while a task remains nonterminal, giving long-running executions continuous visible progress without moving the API token into an `EventSource` URL. Non-terminal tasks can be cancelled from CLI, TUI, API, or GUI; cancellation records a receipt, denies any pending task approval, and appends the result to the original session transcript.
Evidence bundles, task timelines, and run-event snapshots include the same session show/history action hints as task status payloads, and the GUI renders those hints as Open Session actions so post-resume audit views remain linked back to the originating transcript.
Run-event summaries call out resume requested/result/rejected context refs directly, which makes original-session continuity visible without expanding raw audit payloads.
Browser click and fill actions create approval records and can only be completed by replaying the same action with the matching approved `approval_id`; client-supplied `approved` booleans are ignored. These actions record virtual state and before/after evidence hashes for audit and extraction output; they do not mutate a rendered page.
The conservative tool runner follows the same pattern for approval-required tools: the first run creates an approval with a hash of the parameters, and the approved replay must match that tool name and parameter hash.
The TUI and repair panel can select an improvement proposal, view repair readiness blockers, generate an isolated no-mutation repair plan sandbox with a verifier receipt, create a redacted synthesis prompt packet for a model or operator, synthesize a model-style patch candidate from JSON into a preflighted workspace-scoped unified diff, create a pending repair candidate with planned files, a patch plan, and an optional unified diff, approve or reject the candidate review decision, apply an approved candidate patch, roll back an applied candidate before verification, and record an implemented repair attempt with changed-file evidence plus a verification command/result. Candidate diffs are preflighted with `git apply --check` before storage, synthesis JSON can echo `prompt_id` to bind the candidate back to the private prompt artifact and checksum sidecar, workspace mutation is blocked until the candidate itself has `review_status=approved`, linked prompt lineage is rechecked before application, candidate-linked verification requires the exact candidate to be applied and pending verification, and passing verification marks the candidate `verified` with the redacted verification receipt attached.
It also surfaces execution backend definitions and the virtual skill hub.

The API is a local control plane and does not implement user authentication. Bind it to `127.0.0.1` unless it is placed behind a trusted local access layer.

## API Endpoints

- `GET /`
- `GET /dashboard`
- `GET /health`
- `GET /connectors`
- `GET /channels`
- `GET /channel-events`
- `GET /policy`
- `GET /policy/rollouts`
- `GET /policy/promotions`
- `POST /policy/evaluate`
- `POST /policy/schedule-bundle`
- `POST /policy/promote-bundle` with optional clean evaluation and live parity gate fields, including named live-gap deferrals with an operator reason
- `POST /policy/activate-due`
- `POST /policy/promote-bundle`
- `POST /channels/render`
- `POST /channels/receive`
- `POST /channels/webhook`
- `POST /channels/webhook/send`
- `POST /channels/email/send`
- `POST /channels/chat-webhook/send`
- `GET /models`
- `GET /model-providers`
- `GET /models/route?identifier=...`
- `POST /models/alias`
- `POST /models/fallbacks`
- `GET /model-usage`
- `POST /models/auth/login`
- `POST /models/auth/logout`
- `GET /tools`
- `POST /tools/run`
- `GET /backends`
- `GET /skill-hub?q=query`
- `GET /skills`
- `POST /skills/{skill_id}/disable`
- `POST /skills/{skill_id}/enable`
- `GET /mcp/servers`
- `POST /mcp/servers`
- `GET /schedules`
- `GET /schedules/due`
- `POST /schedules/memory-review-digest`
- `POST /schedules/memory-review-escalation`
- `POST /schedules/evaluation-run`
- `POST /schedules/evaluation-suite`
- `GET /evaluation/queue`
- `GET /evaluation/trends`
- `GET /evaluation/delta`
- `GET /evaluation/readiness`
- `POST /evaluation/reports/:id/review`
- `POST /schedules/:id/approve`
- `POST /schedules/:id/activate`
- `POST /schedules/:id/pause`
- `POST /schedules/run-due`
- `GET /sessions`
- `GET /sessions/{session_id}/messages`
- `GET /sessions/{session_id}/tasks`
- `GET /tasks`
- `GET /approvals`
- `GET /approvals/{approval_id}`
- `GET /memory?q=...`
- `GET /sessions/:id/memory-preview`
- `POST /memory`
- `POST /memory/:id/update`
- `GET /memory/review-queue`
- `GET /memory/review-digest`
- `GET /memory/review-escalation`
- `POST /memory/review-action`
- `POST /memory/review-batch`
- `POST /memory/recertify` accepts `dry_run: true` to preview stale confirmed records before tagging them for review.
- `POST /memory/merge`
- `POST /memory/:id/expire`
- `POST /memory/cleanup-expired`
- `GET /memory/export?q=...`
- `GET /memory/:id/explain?q=...`
- `POST /memory/:id/delete`
- `GET /audit`
- `GET /audit/export-siem?limit=...&task_id=...&event_type=...`
- `POST /tasks`
- CLI `task submit`, `task status`, `task resume`, `task pause`, and `task cancel` include the linked session snapshot when a task belongs to a session. `submit` accepts `--session-id`, and pause/resume/cancel fall back to the task's original session when `--session-id` is omitted so command-line controls preserve conversation, model, and personality context. TUI task status/control cards render the same session hints as copyable `session open` and `session history` next actions, and TUI resume switches back to the task's original session when the active conversation differs. `task list --session-id` filters recent tasks to one conversation, while omitting it shows global recent tasks; linked task-list rows include machine-readable session show/history action hints. `session history --limit` returns the latest transcript messages in chronological order, with current task and approval status plus state-aware action hints for scriptable resume audits.
- Direct task status and task-control responses also include machine-readable session show/history action hints, plus a resume hint when the task is waiting for approval or paused.
- `GET /tasks/{task_id}`
- `GET /tasks/{task_id}/evidence`
- `GET /tasks/{task_id}/timeline`
- `GET /tasks/{task_id}/events`
- `GET /tasks/{task_id}/events/stream`
- CLI `task timeline <task_id>`, CLI `task events <task_id>`, TUI `evidence [task_id]`, TUI `timeline [task_id]`, and TUI `events [task_id]` expose the same session-aware evidence, timeline, and run-event snapshots as the API/GUI, including copyable session next actions and per-step progress groups for the browser run view.
- `POST /tasks/{task_id}/resume`
- `POST /tasks/{task_id}/pause`
- `POST /tasks/{task_id}/cancel`
- `POST /approvals/{approval_id}/approve` with optional `actor`, `reason`, and `admin`
- `POST /approvals/{approval_id}/deny` with optional `actor`, `reason`, and `admin`
- `POST /sessions`
- `POST /sessions/{session_id}/update`
- `POST /sessions/{session_id}/compact`
- `POST /sessions/{session_id}/messages` accepts `submit: true` to run a task or `submit: false` to append session context only. Non-submitting messages may include a `trust_class` such as `USER_DIRECTIVE`, `CHAT_CONTENT`, `WEB_CONTENT`, `DOCUMENT_CONTENT`, `TOOL_OUTPUT`, or `UNKNOWN_UNTRUSTED`.
- CLI `session show`, `session update`, `session append`, and `session compact` expose the same session lifecycle controls as the TUI and GUI. TUI and CLI `session append` mirror the GUI's non-submitting context append path with explicit trust labels. Session compaction treats `keep_last=0` as compacting all current transcript messages and rejects negative keep counts.
- `GET /browser/sessions`
- `POST /browser/sessions`
- `POST /browser/sessions/{session_id}/close`
- `POST /browser/navigate`
- `POST /browser/extract`
- `POST /browser/inspect`
- `POST /browser/table`
- `POST /browser/screenshot`
- `POST /browser/render-screenshot`
- `POST /browser/click`
- `POST /browser/fill`
- `GET /improvements`
- `GET /improvements/{proposal_id}`
- `POST /improvements/{proposal_id}/status`
- `POST /improvements/{proposal_id}/candidates`
- `POST /improvements/{proposal_id}/candidates/generate`
- `POST /improvements/{proposal_id}/synthesis-prompt`
- `POST /improvements/{proposal_id}/candidates/synthesize`
- `POST /improvements/{proposal_id}/candidates/{candidate_id}/review`
- `POST /improvements/{proposal_id}/candidates/{candidate_id}/apply`
- `POST /improvements/{proposal_id}/candidates/{candidate_id}/rollback`
- `POST /improvements/{proposal_id}/attempts`
- `POST /schedules`
- `GET /kanban/boards`
- `POST /kanban/boards`
- `GET /kanban/boards/{board_id}/cards`
- `POST /kanban/boards/{board_id}/cards`
- `POST /kanban/cards/{card_id}/move`
