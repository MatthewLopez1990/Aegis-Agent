# Security Model

Aegis uses controls outside prompt wording. The model should not be trusted to hold secrets or enforce permissions by itself.

## Context Firewall

The firewall assigns each context item a trust class and taint metadata. External content can inform decisions, but it cannot issue commands. Suspicious instruction patterns are replaced with `[QUARANTINED_INSTRUCTION]` and marked as quarantined.

## Policy Engine

Default policies:

- Read-only by default.
- No raw secret exposure.
- No destructive action without approval.
- No sending messages without approval.
- No external network egress except approved domains.
- No running unknown shell commands.
- No skill execution without manifest validation.
- No connector write action without scoped permission.
- No high-risk memory storage without confirmation.

## Secrets

`SecretsBroker` issues scoped handles. Raw values are only resolvable for authorized tool code and are not returned to model-facing flows. Model provider login stores API keys in the local secret store, with environment variables taking precedence. Audit logs redact secret-like keys recursively.

## Approvals

High-risk operations create approval records and pause the task. Approved tasks can resume from the stored checkpoint.
