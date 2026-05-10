# Threat Model

## Assets

- User files and workspace data.
- Connector data.
- Memory records.
- Skill manifests.
- Approval decisions.
- Audit logs.
- Secrets handled by the secrets broker.

## Trust Boundaries

- Trusted: system code, developer code, direct user directives.
- Conditional: approved memory and validated skill manifests.
- Untrusted: connector data, web content, email content, document content, chat content, tool output, skill output, unknown content.

## Primary Threats

- Prompt injection in files, web pages, email, chat, or tool output.
- Skills requesting undeclared filesystem, network, shell, or secret permissions.
- Connectors performing writes without approval.
- Secrets leaking into logs or normal memory.
- Memory becoming stale, conflicting, or treated as authority.
- Audit tampering.
- Shell or network actions escaping policy.

## MVP Controls

- Context firewall and taint metadata.
- Policy decisions with allow, deny, and require approval.
- Connector scopes and read-only defaults.
- Secret redaction in audit logs.
- Memory secret-like content refusal.
- Skill manifest validation and runtime permission checks.
- Audit hash-chain verification.
- Shell command allowlist.
- HTTP allowlist and mock-mode default.
