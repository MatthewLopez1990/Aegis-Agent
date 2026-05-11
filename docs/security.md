# Security

Aegis is built around control layers:

- Context firewall.
- Taint tracking.
- Tool-output isolation.
- Permission manifests.
- Policy gate.
- Secrets broker.
- Signed skill manifest verification.
- Sandboxed skill profiles.
- Scoped connectors.
- Human approvals.
- Audit logs and receipts.

## Prompt Injection

Untrusted content is never treated as an instruction source. Files, web pages, email, chat messages, connector records, and tool output can be summarized or used as evidence, but they cannot directly route tools.

## Secret Handling

Do not put raw secrets in requests, memory, skill manifests, docs, or logs. The secrets broker returns handles, model prompts redact secret-like values, receipts use sanitized request fields, and audit logs redact both secret-like field names and common token-shaped values.

## Policy Profiles

Policy profiles are trusted admin TOML files loaded from `.aegis/config.toml`. They can tighten or relax non-immutable actions, replace network and shell allowlists, and keep raw secret exposure plus secret-data handling as immutable deny controls.

## Writes and Sends

Connector writes, destructive operations, shell execution, and message sending require scoped permissions and approval.
Approval decisions record status, actor, reason, and decision time in the approval payload and audit log, so replayed actions have reviewer evidence instead of only a terminal status.
Policy profiles can require admin approval for selected actions. Those gates require an approval decision with `admin=true`; a normal approval leaves the task paused and creates a new admin-required approval checkpoint.
