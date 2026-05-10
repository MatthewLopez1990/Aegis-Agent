# Security

Aegis is built around control layers:

- Context firewall.
- Taint tracking.
- Tool-output isolation.
- Permission manifests.
- Policy gate.
- Secrets broker.
- Sandboxed skill profiles.
- Scoped connectors.
- Human approvals.
- Audit logs and receipts.

## Prompt Injection

Untrusted content is never treated as an instruction source. Files, web pages, email, chat messages, connector records, and tool output can be summarized or used as evidence, but they cannot directly route tools.

## Secret Handling

Do not put raw secrets in requests, memory, skill manifests, docs, or logs. The secrets broker returns handles and audit logs redact secret-like field names.

## Writes and Sends

Connector writes, destructive operations, shell execution, and message sending require scoped permissions and approval.
