# Roadmap

## Next MVP Hardening

- Add a real policy file parser and admin policy profiles.
- Add migration tooling for the SQLite schema.
- Add signed skill packages.
- Enable live channel adapters one at a time behind signature verification and approval gates.
- Add live implementations for selected high-value tools after sandbox hardening.
- Add model invocation clients for the registered providers.
- Add richer memory conflict resolution and TTL expiration jobs.
- Add a model/provider abstraction with context budget accounting.
- Add stronger sandboxing for generated skills.

## Connector Growth

- Real OAuth-backed Microsoft Graph and Google Workspace connectors.
- GitHub/GitLab connector with scoped read/write modes.
- Jira/Linear and ServiceNow write paths with rollback receipts.
- SIEM export for audit events.

## Evaluation Growth

- Scenario corpus for prompt injection, memory poisoning, connector abuse, and skill escalation.
- Regression gates for every high-risk policy class.
