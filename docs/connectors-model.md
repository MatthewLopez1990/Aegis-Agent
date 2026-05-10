# Connectors Model

Connectors declare:

- Name, version, auth type.
- Required and optional scopes.
- Supported operations.
- Risk level per operation.
- Rate limits and data sensitivity.
- Default mode and approval requirements.

Implemented reference connectors:

- `filesystem`: scoped local root, read-only by default, dry-run writes.
- `shell`: strict command allowlist, approval for execution.
- `http`: allowlist and mock-mode by default.
- `github`: GitHub-style mock for repos, issues, and pull requests.
- `generic_rest`: brokered mock REST connector.
- `mock_graph`: Microsoft Graph-style mock.
- `mock_servicenow`: ServiceNow-style mock.
- `mock_messaging`: Slack/Teams-style mock.

Connector output is treated as untrusted tool output and passed through the context firewall.
