# TUI and Web GUI

## Terminal UI

Run:

```bash
PYTHONPATH=src python3 -m aegis.cli.main tui
PYTHONPATH=src python3 -m aegis.cli.main tui --classic
```

Shell completion scripts can be generated with `aegis completion bash`, `aegis completion zsh`, or `aegis completion fish`; the scripts are built from the current CLI parser and include top-level commands plus first-level subcommands/options.

By default, `aegis tui` opens a curses-backed prompt-first terminal surface with the Aegis shield identity in the header. It follows the Hermes interaction model: same sessions, same slash commands, and the same governed command dispatcher, with the UI kept out of the way until it is useful. Type a plain request and press Enter to submit it, type `/` to open the live slash-command palette, use Up/Down to move through palette rows or command history, Tab to accept a highlighted slash command, and Esc to clear the composer or exit. Non-interactive shells or `--classic` fall back to the line-oriented command deck.

Commands:

- `dashboard`
- `submit <request>`
- `status [task_id]`
- `resume [task_id]`
- `cancel [task_id] [reason]`
- `task status|resume|pause|cancel|events|timeline|submit|list [args]`
- `tasks [all|session <session_id>] [--limit N]`
- `new [title]`, `reset [title]`, `clear`
- `add-dir <path>`
- `history [session_id] [--limit N]`, `title [name]`, `topic [off|help|session_id]`, `compress|compact [keep_last]`
- `background <request>` / `bg <request>` / `btw <request>`
- `fast [request]`, `goal`, `batch`, `queue [status|all|session|submit|request]` / `q [...]`, `loop` / `proactive`, `plan`, `ultraplan [prompt]`, `branch`, `fork`, `context`, `recap`, `copy`, `export`, `rename [title]`, `save`, `prompt`, `steer [instruction]`, `stop [task_id]`, `continue [task_id]`, `checkpoint`, `rewind`, `retry`, `undo`, `snapshot`, `snap`
- `remote-control [name|pair|directory|revoke|relay|relay-directory|relay-notify|push-targets|push-register|push-disable|push-rotate|push|relay-outbox|relay-retry|relay-confirm|relay-pull|relay-action]` / `rc [name|pair|directory|revoke|relay|relay-directory|relay-notify|push-targets|push-register|push-disable|push-rotate|push|relay-outbox|relay-retry|relay-confirm|relay-pull|relay-action]`, including `directory --pairing-id <id>` for a sanitized scoped task/session snapshot, `relay-directory --pairing-id <id> --relay-auth-secret <name> --approved` for a one-shot sanitized relay directory publish, `relay-notify --pairing-id <id> --relay-auth-secret <name> --approved` for a one-shot metadata-only mobile/gateway relay notification, `relay-confirm --pairing-id <id> --outbox-id <id> --relay-auth-secret <name> --approved` for one approved delivery confirmation, `push-register --provider apns|fcm --push-auth-secret <name> --device-token-secret <name> --approved` for a reusable brokered target record, `push-rotate --target-id <id> --approved [--push-auth-secret <name>] [--device-token-secret <name>]` for approved credential-reference rotation, `push --pairing-id <id> --target-id <id> --approved` for a one-shot brokered native notification, `relay-outbox [--status failed]` for durable relay-notification delivery state, `relay-retry --pairing-id <id> --relay-auth-secret <name> --approved` for approved retry, `revoke <pairing-id> [--relay-auth-secret name --approved]` for approved relay revocation propagation, and `relay-pull --pairing-id <id> --relay-auth-secret <name> --approved [--dry-run]` for approved relay action polling; `handoff [platform]`, `remote-env`, `teleport`, `tp`, `mobile`, `ios`, `android`, `desktop`, `app`, `web-setup`
- `agents [status|autonomy-preflight|autonomy-step <card-id> --approved [--max-steps n]|autonomy-run <card-id> --approved [--max-steps n]|profiles|profile-create <name>|profile-disable <id>|delegate <role> <task> [--approved]|delegate-child <parent-card-id> <role> <task> --approved|handoff <card-id> <lane> [reason]|run <card-id> --approved|run-batch --approved [--limit n] [--card-id id]|review-packet <card-id>|verify-packet <packet-id-or-path>|model-review <card-id> --approved]`
- CLI `task list [--session-id <session_id>] [--limit N]`
- `approvals`
- `approve <approval_id> [--actor name] [--reason text] [--admin]`
- `deny <approval_id> [--actor name] [--reason text] [--admin]`
- `commands [prefix]`, `doctor`, `debug`, `details`, `config`, `settings`, `profile`, `init`
- `permissions`, `privacy-settings`, `security-review`, `simplify [focus]`, `ultrareview [PR]`, `bug|feedback <summary>`, `hooks list|add|enable|disable|remove|run`
- `connectors`, `gateway`, `platforms`
- `pr_comments`, `autofix-pr [prompt]`
- `channels`
- `channel render <channel> <text>`
- `channel receive <channel> <text>`
- `channel resolve-approval <event_id> <approval_id> [--actor name] [--reason text] [--admin]`
- `channel send-webhook <text> [--approval-id <id>]`
- `channel send-email <subject> <text> [--approval-id <id>]`
- `channel send-chat-webhook <text> [--approval-id <id>]`
- `channel activation-packet`
- `channel verify-activation-packet <packet-id-or-path>`
- `channel activate-packet <packet-id-or-path> --approved`
- `channel events [limit]`
- `events [task_id]`
- `models`
- `model [identifier|args]`
- `login [provider [subscription]]`, `setup-bedrock`, `setup-vertex`, `upgrade`
- `logout <provider>`
- `effort|reasoning [level]`, `cost`, `stats`, `insights [days]`, `statusbar|statusline|sb`, `footer`, `busy [status|queue|steer|interrupt|pause|resume]`, `queue [status|all|session|submit]`, `indicator`, `theme`, `skin`, `color`, `verbose`; UI preferences persist as active-session metadata
- `models list`
- `models route <identifier>`
- `models alias <alias> <identifier>`
- `models fallbacks <identifier> <fallback> [fallback...]`
- `models usage`
- `kanban`, `boards`
- `models auth [provider]`
- `models auth login <provider>`
- `models auth login <provider> subscription`
- `models auth login <provider> subscription --run-external`
- `models auth login openai subscription --verify-external`
- `models auth login anthropic subscription --verify-external`
- `models auth login github-copilot oauth-device --run-external`
- `models auth login google cloud-identity --run-external`
- `models auth login google cloud-identity --verify-external`
- `models auth login qwen subscription --run-external`
- `models auth login qwen subscription --verify-external`
- `models auth login google subscription --run-external`
- `models auth login aws-bedrock cloud-identity --run-external`
- `models auth login aws-bedrock cloud-identity --verify-external`
- `models auth login azure-foundry cloud-identity --run-external`
- `models auth login azure-foundry cloud-identity --verify-external`
- `models auth methods [provider]`
- `models auth targets`
- `models auth doctor`
- `models auth readiness-packet`
- `models auth verify-readiness-packet <packet-id-or-path>`
- `models auth logout <provider>`
- `provider`, `usage`, `insights [days]`
- `tools [list|run|enable|disable]`, `allowed-tools`, `bashes|processes [list|start|input|resize|stop|logs]`
- `toolsets`
- `skills [hub|search|browse query|inspect skill_id|install skill_id|disable skill_id|enable skill_id]`
- Enabled installed skills are also exposed as dynamic slash commands such as `/aegis-project-summary`; pass a JSON object for structured inputs.
- Configured `[quick_commands.<name>]` entries expose local slash shortcuts. `type = "alias"` forwards to another slash command, while `type = "exec"` runs the configured command through the governed shell tool and still requires `--approved`.
- `curator [status|run [--dry-run]|draft <skill_id> --name <name> --description <description>|verify-draft <candidate_id>|install-draft <candidate_id> --approved|pin <skill_id>|unpin <skill_id>|archive <skill_id>|restore <skill_id>|pause|resume]`
- `plugins list|install|enable|disable|remove|reload|marketplace|updates|fetch-manifest|fetch-bundle|install-bundle|install-marketplace|update-marketplace --approved|prepare-update|apply-prepared-update --approved`, `plugin`, `reload`, `reload-plugins`, `reload-skills`, `reload_skills`
- `memory search <query>`
- `memory health [--limit N] [--owner owner] [--scope scope]`
- `memory session-preview <session_id> [--owner name] [--scope scope]`
- `memory session-commit <session_id> [--owner name] [--scope scope] [--candidate-id id] [--confirmed]`
- `memory create <type> <content> [--confidence N] [--tag tag] [--ttl-days N] [--confirmed]`
- `memory review-queue [limit|--limit N] [--scope scope]`
- `memory review-digest [limit|--limit N] [--scope scope]`
- `memory review-escalation [--max-age-days N] [--limit N] [--scope scope] [--route name]`
- `memory recertify [--max-age-days N] [--limit N] [--scope scope] [--dry-run]`
- `memory update <memory_id> [--content text] [--confidence N] [--confirmed]`
- `memory merge <primary_id> <duplicate_id>`
- `memory resolve-conflict <primary_id> <conflicting_id> <keep_primary|keep_conflicting|synthesize|keep_both> <rationale>`
- `memory expire <memory_id>`
- `memory cleanup-expired`
- `memory explain <memory_id> <query>`
- `memory export [query]`
- `memory delete <memory_id>`
- `migrate openclaw|hermes|openclaw-memory-preview|hermes-memory-preview|openclaw-memory-commit|hermes-memory-commit <path> [--owner USER] [--scope SCOPE]`
- `migrate openclaw|hermes` renders a metadata-only inventory for config, context, memory, sessions, skills, plugins, schedules, and process files without raw content or content hashes.
- `mcp list|register <name> <command-or-endpoint> <tool,tool>|register <name> <command-or-endpoint> --discover [--transport stdio|streamable-http] [--token-secret name] [--tool name] [--exclude-tool name] [--no-resources] [--no-prompts] [--enable] [--no-approval]|auth token <server> <token-secret>|auth oauth <server> [--resource-metadata url] [--authorization-server url] [--token-secret name] [--scope scope]|call <server> <tool> <json> [--approved]`
- Discovered stdio and Streamable HTTP MCP servers expose Hermes-style virtual tools named `mcp_<server>_<tool>` in `tools`, `toolsets`, and `/tools/run`; capability-aware utility wrappers add `mcp_<server>_list_resources`, `mcp_<server>_read_resource`, `mcp_<server>_list_prompts`, and `mcp_<server>_get_prompt` when the MCP session advertises resources or prompts. Streamable HTTP bearer credentials can be attached by secret name, and OAuth protected-resource metadata from a sanitized `WWW-Authenticate` challenge can be recorded or configured with a brokered OAuth bearer secret. Calls still flow through the MCP allowlist, policy gate, approval path, and tool-output quarantine.
- `reload-mcp`
- `session [new <title>|open <session_id>|rename <title>|set-model <model>|set-personality <name>|activate|archive|pause|append <content> [--role user|assistant] [--trust-class CLASS]|history [session_id] [--limit N]|tasks [--limit N]|compact [keep_last]]`
- `sessions [--limit N]`
- `schedules`
- `schedule create <name> <cron> <task_request> [--natural-language text] [--channel name] [--context-from ref] [--deliver-to channel]`
- `schedule script|no-agent <name> <cron> [--channel name] [--context-from ref] [--deliver-to channel] -- <argv...>`
- `schedule memory-review-digest <name> <cron> [--channel name] [--limit N] [--scope scope]`
- `schedule memory-review-escalation <name> <cron> [--channel name] [--max-age-days N] [--limit N] [--scope scope] [--route name]`
- `schedule evaluation-run <name> <cron> <scenario> [steps...] [--channel name] [--reviewer name]`
- `schedule evaluation-suite <name> <cron> [--suite name] [--scenario-id id] [--channel name] [--reviewer name]`
- `schedule due`
- `schedule approve|activate|pause <id>`
- `schedule run-due`
- `cron [subcommand]`
- `evaluation queue [--reviewer name] [--limit N]`
- `evaluation review <report-id> <reviewed_passed|reviewed_failed|needs_followup|dismissed> [--reviewer name] [--notes text]`
- `evaluation trends [--limit N]`
- `evaluation delta [--baseline-report-id id --candidate-report-id id] [--scenario name]`
- `evaluation readiness [--baseline-report-id id --candidate-report-id id] [--scenario name] [--reviewer name] [--limit N]`
- `browser status|connect|disconnect|session|sessions|close [session_id]|navigate <url>|live-navigate <url>|live-screenshot|live-click <selector>|live-fill <fields-json>|live-submit [selector]|live-download <selector>|live-upload <selector> <workspace-file-path>|live-evaluate <javascript-with-return>`, `chrome`
- `browser activation-packet|verify-activation-packet <packet-id-or-path>`
- `browser extract|inspect|dom [selector]|table [selector]|screenshot|render|click <selector> [--approval-id id]|fill <json> [--approval-id id]|submit [selector] [--approval-id id]`
- `boards`
- `backends`, `backends select <name> --approved`, `sandbox`
- `voice`, `radio`, `stickers`
- `terminal-setup`, `vim`, `tui [default|fullscreen]`, `scroll-speed [value]`; launch fallback with `aegis tui --classic`
- `rollback`
- `diff`, `review`, `release-notes`, `update`, `restart`
- `platforms`
- `security [profile|evaluate <operation> <risk> <scopes> [target_domain]]`
- `capabilities` shows capability groups plus implementation-readiness buckets.
- `keybindings`, `mouse`, `redraw`, `sethome|set-home`
- `audit [export-siem [limit]]`
- `exit`

The TUI uses the same orchestrator, policy gate, approval queue, audit logger, and context firewall as the CLI/API. The CLI accepts the same capability and plural model entry points through `aegis capabilities` and `aegis models ...`; singular `aegis model ...` remains supported for existing scripts. `aegis setup [--init]` provides a Hermes-style first-run checklist that can create the default config on request and then reports model-auth, connector/channel, backend, remote-control, and interface setup actions without starting external login flows or exposing secret values.

The terminal surface renders with a compact Aegis shield/wordmark header, a live session/status strip, a scrollable output stream, and a fixed composer. `/setup` opens the guided setup checklist, `/setup next` opens the first setup step that still needs operator action, and `/setup json` returns the original machine-readable readiness packet for automation and tests. Setup details live behind explicit slash commands rather than a busy permanent menu, so the first screen stays focused on the current conversation.
Policies can require admin approval; use `approve <approval_id> --admin` for those gates.
The full static posture still lives behind `dashboard`, and `--classic` keeps the line-oriented deck available for scripts or terminals that cannot run curses. Plain text submits governed work in the fullscreen surface; slash aliases such as `/tasks`, `/bg`, `/q`, `/setup`, `/model`, `/settings`, `/debug`, `/commands`, `/copy`, `/allowed-tools`, `/tp`, and `/rc` dispatch directly, `/mem`-style prefixes render filtered options, and fuzzy prefix matching means entries like `/su` suggest both `/submit` and `/setup`. The web GUI refreshes a read-only `/commands` catalog from the same TUI command groups plus enabled skill slash labels, then merges non-web commands as palette/readiness entries instead of treating them as arbitrary task text; structured metadata also marks safe web actions such as `/approval`, `/approve`, `/deny`, `/resume`, `/pause`, `/cancel`, `/remote-control status`, and `/remote-control directory` with their token scope and mutation status before dispatch. The classic live prompt wraps long input in-place, and Ctrl+V inserts a literal newline before final Enter submits a multiline prompt. `menu operate|govern|setup|build|explore` opens nested command groups when explicitly requested, tab completion covers top-level commands plus common subcommands and selected flags in both readline and live prompt modes, and local readline history persists in `.aegis/tui_history` with private file permissions. The identity banner uses the deterministic ASCII shield/wordmark so tests and CI remain stable while interactive operators get the original Aegis logo back. Claude/Hermes-style convenience aliases such as `/add-dir`, `/bug`, `/feedback`, `/cost`, `/setup`, `/login`, `/logout`, `/permissions`, `/profile`, `/pr_comments`, `/security-review`, `/terminal-setup`, `/keybindings`, `/mouse`, `/vim`, `/remote-env`, `/web-setup`, `/plugin`, `/sandbox`, `/loop`, `/queue`, `/q`, `/retry`, `/undo`, `/handoff`, `/hooks`, `/agents`, `/branch`, `/fork`, `/context`, `/copy`, `/export`, `/rename`, `/save`, `/prompt`, `/steer`, `/statusbar`, `/statusline`, `/footer`, `/busy`, `/indicator`, `/details`, `/theme`, `/snapshot`, and `/sethome` route to the existing governed Aegis surfaces or metadata-only readiness reports instead of bypassing policy, audit, approval gates, or prompt-boundary controls. `/setup` renders the same first-run readiness checklist as `aegis setup` without starting external logins, live sends, or model calls.
The web `/remote-control` slash dispatcher now covers the implemented local-token relay and push controls, including relay registration, relay-directory, relay-notify, relay-retry, relay-confirm, relay-pull, push-targets, push-register, push-rotate, push-disable, and push.
`bashes`/`processes` manages local background process records with the same executable allowlist, explicit approval for `start`, private redacted bounded logs, metadata-only command storage, and `stop` receipts. `start --pty` adds an explicit pseudo-terminal path for Claude/OpenClaw-style terminal controls; `input <process-id> <text>` streams guarded stdin with hash/count receipts, and `resize <process-id> --rows N --cols N` records terminal resize events without exposing raw input in public state.
Typing `@` in the live prompt now opens workspace-scoped context path completion, with directories shown before files and hidden local state excluded unless explicitly requested. The same path completion is available for path-valued slash arguments such as `/task submit --path ...` and `/add-dir ...`, so operators can add file or directory context without leaving the command deck.
Project context loading follows that target path progressively: `SOUL.md`, `AGENTS.md`, `CLAUDE.md`, `.hermes.md`, `HERMES.md`, `.cursorrules`, `.cursor/rules/*.mdc`, and `TOOLS.md` are loaded from the workspace root down to the active file or directory, bounded per file and passed through the context firewall before live model prompts. `aegis personality context --workspace <path> --path <target>` reports the same source manifest and sanitized loaded items for review.
`agents run <card-id> --approved` executes the deterministic isolated worker subprocess for a delegation card, records sanitized run and parent-bound review receipts, and moves completed cards to review while recursive autonomous model loops remain disabled. Parent task review bindings store hashes, counts, taint flags, and next actions without raw worker stdout/stderr or raw delegation instructions. `agents delegate-child <parent-card-id> <role> <task> --approved` spends one parent recursive-depth budget unit to create a child work card, preserving parent/root card links and child-depth counters while keeping autonomous runtime and model-loop execution disabled. `agents review-packet <card-id>` creates a model-ready review packet for a subagent card as private local artifacts under the Aegis data directory, with JSON and checksum files plus a sanitized audit receipt. `agents verify-packet <packet-id-or-path>` checks the private artifact checksum, packet schema, and no-raw-content control flags without echoing arbitrary packet fields. `agents model-review <card-id> --approved` creates and verifies a fresh packet, sends only sanitized packet metadata through the context firewall to the configured model, records usage and a redacted model-review receipt, and stores only review metadata on the card. `agents autonomy-step <card-id> --approved` creates and verifies a fresh review packet, then writes a private checksum-backed scoped per-step context/plan with tool execution denied, interrupt support marked, budget enforcement recorded, and operator review required before any deeper step. `agents autonomy-run <card-id> --approved` runs that sanitized step plan inside a Python isolated subprocess with no model, tool, network, or raw instruction access and records an operator-review receipt. `agents autonomy-preflight` records the explicit blockers, missing controls, and verification gates that keep recursive autonomous model-loop subagents disabled. The packet, model-review, autonomy-step, autonomy-run, and child-delegation paths exclude raw worker stdout/stderr, raw worker result payloads, raw prompts, and secret values; model review and step rehearsal do not enable recursive autonomous runtime or tool execution.
`queue` and `busy queue` now render active pending/planned/running/waiting/paused task rows for the current session, or all sessions with `queue all`, without raw task requests; `busy steer <instruction>` stores a hashed session steering receipt, and `busy interrupt|pause|resume [task-id]` routes through the existing audited task-control lifecycle.
`plugins fetch-manifest <plugin-id>` and `POST /plugins/marketplace/fetch-manifest` verify and store one marketplace manifest for local review only. `plugins prepare-update <plugin-id>` / `POST /plugins/marketplace/prepare-update` stage a private SHA-verified update candidate, and `plugins apply-prepared-update <candidate-id> --approved` / `POST /plugins/marketplace/apply-prepared-update` revalidate and apply that candidate only after explicit approval. `plugins update-marketplace <plugin-id> --approved` and `POST /plugins/marketplace/update` with `approved: true` are required for direct marketplace update application; unapproved direct updates fail closed.
Live channel sends create a payload-bound approval record first and only deliver when replayed with a matching approved id. The approval binding covers channel, action, target fingerprint, session id, payload fingerprint, and metadata hash without storing raw channel content; `approved: true` by itself is not accepted as authority.
`channel activation-packet` / `POST /channels/live-activation-packet` create a private checksum-backed gateway activation artifact for signed webhook, email, and chat-webhook promotion review. `channel verify-activation-packet <packet>` / `POST /channels/verify-activation-packet` verify the packet schema, checksum, configured controls, blockers, and no-raw-secret/no-raw-channel-content flags without performing a live send or model invocation. `channel activate-packet <packet> --approved` / `POST /channels/activate-packet` records an `aegis.channel.live_activation_approval.v1` approval receipt only after packet verification and a ready preflight; it still writes no activation config, sends no probe payload, performs no model call, and exposes no raw secrets or channel content.
`remote-control relay-directory --pairing-id <id> --relay-auth-secret <name> --approved` publishes one sanitized scoped directory snapshot to the registered relay with brokered bearer auth. The payload excludes pairing tokens, relay bearer values, raw user requests, plans, and receipts.
Remote-control task `status` and `events` views are metadata-only, including task ids, status, risk, session ids/channel labels, action hints, progress counts, and bounded event metadata without raw event details. Relay-pulled and relay-proxied task actions use the same redacted status/events shape, so full task evidence, plans, receipts, and user request text stay behind the local API token.
`remote-control relay-notify --pairing-id <id> --relay-auth-secret <name> --approved [--event task-updated] [--task-id <id>]` publishes one metadata-only notification envelope to the registered relay for mobile or gateway clients. The payload includes a stable delivery id/idempotency key and an `aegis.remote_control.mobile_gateway.v1` delivery contract describing the expected notification payload type, accepted receipt states, and the fact that device tokens and relay bearer values are never accepted or relayed by Aegis. Failed notification attempts persist in `.aegis/remote_control_pairings.json` as metadata-only outbox rows, successful attempts store only a whitelisted redacted relay receipt, `remote-control relay-confirm --pairing-id <id> --outbox-id <id> --relay-auth-secret <name> --approved` asks the registered allowlisted relay for one delivery id and mutates the outbox row only when the sanitized receipt reaches an accepted state, and `remote-control relay-retry --pairing-id <id> --relay-auth-secret <name> --approved` retries due pending or failed rows without exposing relay secrets. `remote-control push-register --provider apns|fcm --push-auth-secret <name> --device-token-secret <name> --approved [--apns-topic topic] [--fcm-project-id project]` stores a private target record with brokered secret references but never raw provider auth or device-token values; `remote-control push-rotate --target-id <id> --approved [--push-auth-secret name] [--device-token-secret name] [--apns-topic topic] [--fcm-project-id project]` rotates those brokered references and tracks only field labels/counts publicly; `remote-control push --pairing-id <id> --target-id <id> --approved` sends one brokered native APNS/FCM notification to an allowlisted provider endpoint and returns only a redacted native-push receipt.
The web model auth panel can mark local providers such as Ollama and LM Studio as no-auth/local, or request a local-terminal login handoff for subscription, OAuth, OAuth-device, and cloud-identity methods; the API returns sanitized command/status metadata and still refuses to execute interactive provider login from the browser. Its doctor rows expose copyable login and verify commands plus a terminal-only notice, so operators can run official provider login from a local shell without pasting browser/session tokens into Aegis. It can also create and verify private model-auth readiness packets through `POST /models/auth/readiness-packet` and `POST /models/auth/verify-readiness-packet`; creation returns sanitized packet metadata plus a receipt, while verification returns only a packet summary plus receipt and never returns raw token values, browser cookies, or credential files. Once verified, subscription, OAuth, and cloud-identity bridges take route precedence over stored API keys, refresh/project metadata is persisted without raw token values, and Copilot OAuth invocation fails closed unless the Copilot API-token exchange succeeds.
Task lists, task cards, evidence, and timeline views show the linked session when a task belongs to a conversation. In the web GUI, `/status [task_id]`, `/events [task_id]`, `/timeline [task_id]`, and `/evidence [task_id]` now dispatch to the same task loaders as the task-card controls; when the id is omitted, they use the selected/latest task and render a local notice if no task is selected.
`/steer <instruction>` records a redacted active-session steering receipt with an instruction digest and character count, without storing or rendering the raw instruction. `/theme`, `/skin`, `/color`, and `/verbose` store sanitized UI preference values in active-session metadata rather than mutating global config.
`/paste <content>` appends explicit pasted text as untrusted chat context without reading the system clipboard or echoing the raw content back to the terminal. `/image <path>` runs the local `vision_analyze` metadata path for an existing workspace-scoped image and appends only the format, dimensions, byte count, and path metadata to the active session; raw image bytes and OCR content are not rendered.
Late Claude/Hermes slash aliases such as `/autofix-pr`, `/chrome`, `/claude-api`, `/extra-usage`, `/fewer-permission-prompts`, `/focus`, `/heapdump`, `/ide`, `/install-github-app`, `/install-slack-app`, `/passes`, `/powerup`, `/privacy-settings`, `/recap`, `/release-notes`, `/scroll-speed`, `/setup`, `/setup-bedrock`, `/setup-vertex`, `/simplify`, `/team-onboarding`, `/tui`, `/ultraplan`, `/ultrareview`, and `/upgrade` resolve to governed local readiness or existing Aegis control surfaces instead of failing as unknown commands.
Resume attempts write explicit audit events with redacted session ids plus readable context refs, so evidence and timeline views can show which original context was used after approval without weakening audit redaction. Distinct resume outcomes, including intermediate `waiting_approval`, approved, and denied states, are appended back to the original session transcript. When a TUI resume command targets a task from another active conversation, the TUI switches its active session back to that originating transcript after the resume result is recorded.
Approval queues and approval details also show linked session context for task-bound approvals and direct runtime session ids for browser approvals. In the TUI, approval rows and detail views include copyable next steps plus chat-style phrases such as `approve`, `yes proceed`, `deny`, `no do not do that`, and `let's revert` when those intents are safe for the current approval state. The web approval detail card collects actor, reason, and admin-decision metadata before approving or denying, the same decision payload is used by inline transcript approval actions, and the approval panel keeps a bounded recent decision history for approved and denied gates.
CLI and API approval list/approve/deny responses include the same linked session fields for task-bound approvals plus machine-readable `action_hints` for approval review, approve, deny, reject/revert intent, `session show`, `session history`, and approved task resume follow-up commands. These hints are designed for terminal use and future Slack/Discord adapters while preserving exact approval-payload matching before execution.
Inbound channel receive commands can recognize those same short Slack/Discord-style replies as `approval_intent` metadata on the stored channel event. The intent is deliberately non-executing: it records `auto_execute: false` and requires a client to resolve the channel event id against a current approval id before any state changes. `channel resolve-approval <event_id> <approval_id>` and `POST /channels/approval-intent/resolve` provide that explicit bridge, reject mismatched session context when both the event and approval are session-bound, and write a channel approval-intent audit receipt. The web channel-events panel renders matching pending-approval buttons for those intents so operators can approve or deny chat decisions without manually copying ids.
Browser commands use the dependency-light HTTP-content sandbox by default. It does not run page JavaScript, maintain cookies, perform real selector clicks, download files, upload files, or capture the original live page DOM unless a live adapter is explicitly enabled. When `security.live_browser_reads = true`, approved `browser live-navigate <url>` and `browser live-screenshot` can run a read-only headless Chromium snapshot against an allowlisted main-frame URL with an ephemeral profile, disabled JavaScript/images, private PNG/evidence artifacts, no raw DOM return, and no persisted cookies/storage. When `security.live_browser_mutations = true`, approved `browser live-click <selector>`, `browser live-fill <fields-json>`, and `browser live-submit [selector]` can run live selector mutation through an ephemeral Chromium CDP profile with allowlisted navigation, private PNG/evidence artifacts, no raw DOM/cookie/storage return, no downloads/uploads, and no persistent browser profile. When `security.live_browser_downloads = true`, approved `browser live-download <selector>` can click an allowlisted page selector through an ephemeral Chromium CDP profile and store one bounded private download artifact plus screenshot/evidence hashes. When `security.live_browser_uploads = true`, approved `browser live-upload <selector> <workspace-file-path>` can attach one workspace-scoped allowlisted source file, up to 10 MiB, to an allowlisted page file input through an ephemeral Chromium CDP profile and store private screenshot/evidence hashes without returning source bytes. When `security.live_browser_javascript = true`, approved `browser live-evaluate <javascript-with-return>` can evaluate bounded JavaScript through an ephemeral Chromium CDP profile and return only a redacted summary plus private screenshot/evidence hashes. Raw live DOM capture, raw network body capture, persistent cookies/storage, raw cookie/storage value return, unscoped uploads, and approval bypass still fail closed.

Activation packets still name the denied-by-default `playwright-chromium` candidate, runtime availability, and blockers without exposing raw executable paths, while the implemented CDP selector-mutation, selector-download, and selector-upload slices are exposed separately when configured. DOM snapshots parse a bounded redacted tree from stored HTTP content only, support conservative `tag`, `#id`, `.class`, `tag#id`, `tag.class`, `[name=value]`, and `tag[name=value]` filters, omit script/style text, and report unsupported selectors without dispatching DOM events. Table extraction supports a conservative table selector subset (`table`, `#id`, `.class`, `table#id`, and `table.class`), unsupported selectors are reported truthfully, screenshot actions write deterministic local PNG session snapshots plus redacted text sidecars and structured JSON evidence artifacts, and render actions can create a sanitized Chrome-rendered PNG from stored HTTP text/table state without preserving original scripts, styles, iframes, forms, cookies, or remote subresources. Browser artifact files and sidecars are written with private file permissions under the private browser artifact directory, and artifact-facing URL, title, selector, virtual state, DOM snapshot, download/upload metadata, and persisted session fields pass through the secret redactor. The API returns authenticated `/browser-artifacts/...` links for the GUI to open those artifacts without exposing arbitrary filesystem paths.

Approved exact-match anchor clicks can follow safe HTTP(S) hrefs through the governed HTTP connector without JavaScript, cookies, or DOM events; missing, ambiguous, fragment-only, non-HTTP(S), or connector-denied targets fail closed. Approved fills update matching stored static `input` and `textarea` controls when the selector is supported, report `static_dom_form_fill_no_js`, and still mark `real_page_mutated=false`; unmatched fills remain virtual interaction state. Approved static GET form submits resolve one matching form, hash the target URL in the approval payload, navigate through the governed HTTP connector, and still report no JavaScript, cookies, storage, selector-event dispatch, or live page mutation. Navigation responses include a bounded static `interactive_elements` index for links, buttons, inputs, textareas, and selects; `browser inspect` and `POST /browser/inspect` expose the same redacted selector inventory with supported virtual actions, approval requirements, unsupported live actions, readiness status, live-automation activation preflight, and automation-boundary receipts. `browser dom [selector]`, `browser_dom_snapshot`, and `POST /browser/dom-snapshot` expose the bounded static DOM tree with evidence that JavaScript, cookies, storage, remote subresources, selector-event dispatch, and live page mutation were not used. The GUI renders selector entries as selectable rows that populate the selector and fill-field controls without executing page code.

Browser action responses include auditable evidence metadata with URL-before/after, bounded redacted content hashes, content-changed status, DOM-mutated status, click count, form-field count, download/upload file hashes, JavaScript result summaries, sandbox receipts, and SHA-256 hashes for the emitted PNG, metadata, download, upload, and evidence artifacts. Snapshot evidence JSON records the non-rendered capture surface, content hash, static interactive-element count, parser-derived table counts, redacted virtual click/fill state, artifact hashes, sandbox boundaries, and explicit limitations; render evidence JSON records the sanitized render surface and renderer receipt. Live read evidence records the live read-only capture surface, URL hash, private PNG/evidence hashes, ephemeral Chromium receipt, no raw browser content, no persistent cookies/storage, and no selector-event/page-mutation execution. Live mutation evidence records action, selector, field selectors, URL hashes, private PNG/evidence hashes, ephemeral Chromium receipt, allowlisted-only subresource posture, no raw DOM/cookie/storage return, no persistent cookies/storage, and no downloads/uploads. Live download evidence records action, selector, filename, MIME type, byte count, URL hash, private download/screenshot/evidence hashes, ephemeral Chromium receipt, allowlisted-only subresource posture, no raw DOM/cookie/storage return, no raw network body return, no uploads, and no persistent cookies/storage. Live upload evidence records action, selector, source filename, source MIME type, byte count, source and path hashes, URL hash, private screenshot/evidence hashes, ephemeral Chromium receipt, allowlisted-only subresource posture, no raw source bytes returned, no raw DOM/cookie/storage return, no downloads, and no persistent cookies/storage. Live evaluate evidence records action, script SHA-256, script/result limits, URL hashes, bounded redacted evaluation result, private screenshot/evidence hashes, ephemeral Chromium receipt, allowlisted-only subresource posture, no raw DOM/cookie/storage return, no raw network body return, no downloads/uploads, and no persistent cookies/storage. Evidence formats include a `browser_automation_boundaries_v1` block covering navigation network, remote subresources, page script execution, cookies, cookie jars, local/session storage, selector-event dispatch, page mutation, downloads, uploads, JavaScript evaluation, virtual-only interactions, and the safety controls required before deeper live browser automation can be enabled.

Browser sessions persist redacted, bounded snapshots under `.aegis/browser/sessions.json`, so the GUI can recover navigation, DOM snapshots, table extraction, static form fills, static GET submits, virtual interaction state, redacted live-mutation metadata, redacted live-download metadata, redacted live-upload metadata, and redacted live-evaluation metadata after a server restart without storing raw secret-shaped values. Browser click, fill, submit, live-navigate, live-screenshot, live-click, live-fill, live-submit, live-download, live-upload, and live-evaluate commands create approval records first; after approving with `approve <approval_id>`, rerun the same browser command with `--approval-id <approval_id>`.

The browser live activation packet surface is a private artifact and verifier path for adapter review, not approval by itself. `create_live_activation_packet(actor=...)` writes an `aegis.browser.live_activation_packet.v1` JSON packet plus checksum under `.aegis/browser/live-activation-packets/` and records `browser.live_activation_packet_created`; `verify_live_activation_packet(packet, actor=...)` accepts only a packet id or path inside that private directory, checks the checksum, schema, blockers, control flags, and automation-boundary flags, and records `browser.live_activation_packet_verified`. Default packet and verifier receipts keep `live_browser_adapter_enabled=false`, `preflight_status=blocked`, and `activation_status=live_browser_adapter_required`; when read-only, selector-mutation, selector-download, selector-upload, or JavaScript-evaluation live browser capture is explicitly configured, packets report the configured adapter and still keep raw browser content, cookies, storage, raw DOM, model invocation, unscoped upload, and approval bypass out of scope. The packet summary and verification receipt deliberately exclude raw browser content, raw DOM/HTML, raw cookies, raw storage values, raw secret values, raw environment, and raw packet payloads; verification fails the integrity receipt when forbidden raw-content keys are present.

Tool commands use JSON parameters and the same approval semantics as the governed tool catalog:

```text
tool run calculator '{"expression":"2+2"}'
tools run service_ticket_read '{"query":"incident"}'
tools run service_ticket_write '{"operation":"close","ticket":{"id":"INC000001"}}' --approved
tools run message_send '{"message":{"text":"Hello from Aegis","channel":"general"}}' --approved
```

## Web GUI

Run:

```bash
PYTHONPATH=src python3 -m aegis.cli.main serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/`.

The CLI, TUI, and GUI all expose the governed tool catalog plus a conservative tool runner. The TUI dashboard opens with a stable Aegis ASCII identity banner, a selectable curses command center, and a focused command palette, and the `menu` command renders a minimal lane selector before operators open nested operate/govern/setup/build/explore groups or drill into competitive parity targets with their remaining live-integration gaps plus the structured live-gap backlog, including the controls and verification gates needed before each gap can be closed. The TUI capabilities view and GUI live-gap cards also expose the browser/media readiness checklist for boundary receipts, taint preservation, artifact hashing, approval, secret-capture boundaries, media_sandbox_profile_v1 receipts, live automation status, and provider depth; live connector readiness for credential handles, allowlists, enablement flags, approval, redaction, mock fallback, read inventory, and promotion scope; subagent runtime-depth readiness for approval-gated durable delegation queues, profiles, budget snapshots, handoff receipts, tainted instruction metadata, approved sanitized model reviews, approved autonomy step plans, approved isolated autonomy loop rehearsals, operator lane control, and blocked autonomous recursion; plus remote backend readiness for explicit enablement, brokered auth, scope/resource limits, rollback receipts, disabled-backend denial, and lifecycle depth. The GUI parity cards render the same gap metadata. The GUI is static HTML/CSS/JavaScript served by the local API. Its task composer has a Codex-style slash palette with fuzzy `/su`-style matching, Tab/click completion, Ctrl+Enter send, governed `/submit` and `/q` task submission, and local navigation commands for models, memory, tools, automation, evidence, approvals, and remote control. It exposes task submission, the approval queue, recent tasks, a dedicated session-linked task recovery feed, runtime health, security controls, parity targets, connectors with operation risk/scope/sensitivity metadata, channels, outbound channel rendering, channel events, governed memory create/search/update/explain/export/delete controls, session memory preview and commit controls, Hermes/OpenClaw memory migration preview and commit controls, models with provider/model usage telemetry and external-auth verification results including Gemini CLI subscription verification, tools, installed governed skill inventory, local plugin install/enable/disable/remove/reload controls, metadata-only plugin marketplace and update planning plus SHA-verified marketplace manifest fetch/install, signed bundle review/install, and prepared update review/apply controls, scoped remote-control pairing creation/status/revoke/directory controls, remote-control relay preflight, approved relay registration with URL secret redaction, approved relay directory/notification publishing, durable relay notification outbox status/retry, split relay action preview/apply controls, registered relay action-pull/proxy status, virtual Skill Hub search, a conservative tool runner, browser sandbox actions, schedules, scheduled evaluation runs, evaluation review queues, trend dashboards, regression deltas, release readiness summaries, session create/update controls, work boards, subagent delegation status/profile/delegate/handoff/review-packet/autonomy-step/autonomy-run/model-review controls, verified repair attempts, audit logs, and normalized SIEM JSONL audit export.
The web slash dispatcher accepts `/remote-control push-targets [--target-id ID]` as a read-only native push target lookup in the same catalog as the TUI and CLI command.
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
The TUI and repair panel can select an improvement proposal, view repair readiness blockers, generate an isolated no-mutation repair plan sandbox with a verifier receipt, create a redacted synthesis prompt packet for a model or operator, synthesize a model-style patch candidate from JSON into a preflighted workspace-scoped unified diff, create a pending repair candidate with planned files, a patch plan, and an optional unified diff, approve or reject the candidate review decision, apply an approved candidate patch, roll back an applied candidate before verification, and record an implemented repair attempt with changed-file evidence plus a verification command/result. Candidate diffs are preflighted with `git apply --check` before storage, synthesis JSON can echo `prompt_id` to bind the candidate back to the private prompt artifact and checksum sidecar, workspace mutation is blocked until the candidate itself has `review_status=approved`, linked prompt lineage is rechecked before application, candidate-linked verification requires the exact candidate to be applied and pending verification, and passing verification marks the candidate `verified` with the redacted verification receipt attached. Browser live activation packets have a similar checksum-backed private-artifact verifier receipt for future adapter review, but they remain browser-controller metadata only and do not enable browser automation from the TUI, GUI, API, or tool runner.
It also surfaces execution backend definitions and the virtual skill hub.

The API is a local control plane and does not implement user authentication. Bind it to `127.0.0.1` unless it is placed behind a trusted local access layer.

## API Endpoints

- `GET /`
- `GET /dashboard`
- `GET /commands`
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
- `POST /channels/render`
- `POST /channels/receive`
- `POST /channels/approval-intent/resolve`
- `POST /channels/live-activation-packet`
- `POST /channels/verify-activation-packet`
- `POST /channels/activate-packet`
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
- `GET /remote-control/status`
- `GET /remote-control/directory`
- `GET /remote-control/relay`
- `GET /remote-control/relay/outbox`
- `GET /remote-control/push/targets`
- `POST /remote-control/relay`
- `POST /remote-control/relay/directory`
- `POST /remote-control/relay/notify`
- `POST /remote-control/relay/confirm`
- `POST /remote-control/push`
- `POST /remote-control/push/register`
- `POST /remote-control/push/rotate`
- `POST /remote-control/push/disable`
- `POST /remote-control/relay/retry`
- `POST /remote-control/relay/pull`
- `POST /remote-control/relay/action`
- `POST /remote-control/pair`
- `POST /remote-control/revoke`
- `GET /remote-control/tasks/:id`
- `GET /remote-control/tasks/:id/events`
- `POST /remote-control/tasks/:id/resume|pause|cancel`
- `GET /subagents/status`
- `GET /subagents/autonomy-preflight`
- `POST /subagents/delegate`
- `POST /subagents/delegate-child`
- `GET|POST /subagents/profiles`
- `POST /subagents/profiles/:id/disable`
- `POST /subagents/handoff`
- `POST /subagents/run`
- `POST /subagents/run-batch`
- `POST /subagents/review-packet` accepts a `card_id` and optional `actor`, creates the same sanitized/private review packet artifacts as `agents review-packet <card-id>`, and returns the packet metadata, receipt, audit hash, and refreshed subagent status. The response receipt is explicit about the review boundary: model invocation is not performed, autonomous runtime remains disabled, and raw instructions, raw worker output, raw worker results, raw prompts, and secret values are not included or forwarded.
- `POST /subagents/verify-packet` accepts a packet id or private packet path and optional `actor`, checks checksum/schema/control integrity, returns only a sanitized packet summary plus verification receipt, and refuses paths outside `.aegis/subagent-review-packets`.
- `POST /subagents/model-review` accepts a `card_id`, optional `actor`, optional `session_id`, and `approved: true`; without approval it returns `approval_required`, and with approval it invokes the selected model only on sanitized packet metadata while keeping autonomous recursion disabled.
- `POST /subagents/autonomy-step` accepts a `card_id`, optional `actor`, `max_steps`, and `approved: true`; without approval it returns `approval_required`, and with approval it creates a private scoped step-plan artifact from verified review metadata while keeping model invocation, tool execution, and autonomous recursion disabled.
- `POST /subagents/autonomy-run` accepts a `card_id`, optional `actor`, `max_steps`, and `approved: true`; without approval it returns `approval_required`, and with approval it creates a fresh scoped step plan and executes it inside an isolated no-network subprocess that records review-required loop receipts without model invocation, tool execution, or raw instruction access.
- `POST /models/auth/login` with `method: "none"` for no-auth local providers, `method: "api_key"` for stored API-key providers, or guarded `method: "subscription"`, `"oauth"`, `"oauth_device"`, or `"cloud_identity"` metadata; `verify_external: true` may run non-secret official status checks and remember verified external auth links, while interactive `run_external` provider login is refused over API and must run in a local CLI/TUI terminal.
- `POST /models/auth/logout` removes API-key secrets and verified external auth links without exposing provider tokens.
- `GET /tools`
- `POST /tools/run`
- `GET /backends`
- `GET /processes`
- `GET /processes/:id/logs`
- `POST /processes/start`
- `POST /processes/:id/input`
- `POST /processes/:id/resize`
- `POST /processes/:id/stop`
- `GET /skill-hub?q=query`
- `GET /skills`
- `POST /skills/{skill_id}/disable`
- `POST /skills/{skill_id}/enable`
- `GET /plugins`
- `GET /plugins/marketplace`
- `GET /plugins/updates`
- `POST /plugins`
- `POST /plugins/reload`
- `POST /plugins/marketplace/fetch-manifest`
- `POST /plugins/marketplace/fetch-bundle`
- `POST /plugins/marketplace/install-bundle`
- `POST /plugins/marketplace/install`
- `POST /plugins/marketplace/update`
- `POST /plugins/marketplace/prepare-update`
- `POST /plugins/marketplace/apply-prepared-update`
- `POST /plugins/:id/enable`
- `POST /plugins/:id/disable`
- `POST /plugins/:id/remove`
- `GET /mcp/servers`
- `POST /mcp/servers`
- `POST /mcp/auth/oauth`
- `GET /hooks`
- `POST /hooks`
- `POST /hooks/run`
- `POST /hooks/:id/enable`
- `POST /hooks/:id/disable`
- `POST /hooks/:id/remove`
- `GET /schedules`
- `GET /schedules/due`
- `POST /schedules`
- `POST /schedules/script`
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
- `POST /sessions/:id/memory-commit`
- `POST /memory`
- `POST /memory/:id/update`
- `POST /memory/resolve-conflict`
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
- `POST /browser/dom-snapshot`
- `POST /browser/table`
- `POST /browser/screenshot`
- `POST /browser/render-screenshot`
- `POST /browser/live-navigate`
- `POST /browser/live-screenshot`
- `POST /browser/click`
- `POST /browser/fill`
- `POST /browser/submit`
- `POST /browser/live-activation-packet`
- `POST /browser/verify-activation-packet`

`POST /browser/click`, `/browser/fill`, and `/browser/submit` accept `live: true` only for the explicit selector-mutation adapter path.
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
- `GET /kanban/boards`
- `POST /kanban/boards`
- `GET /kanban/boards/{board_id}/cards`
- `POST /kanban/boards/{board_id}/cards`
- `POST /kanban/cards/{card_id}/move`
