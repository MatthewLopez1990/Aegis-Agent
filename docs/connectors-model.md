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
- `http`: allowlist and mock-mode by default, with opt-in live reads for safe `http`/`https` URLs.
- `github`: GitHub-style mock for repos, issues, pull requests, PR comments, PR autofix planning, approved local PR autofix patch application, and approved PR autofix responses, with optional approved brokered-token live issue/comment writes.
- `gitlab`: GitLab-style mock for projects, issues, and merge requests, with optional approved brokered-token live issue/note writes.
- `generic_rest`: brokered mock REST connector with optional approved HTTPS writes.
- `mock_graph`: Microsoft Graph-style mock with optional approved brokered-token live calendar, contact, and email writes.
- `mock_servicenow`: ServiceNow-style mock with optional approved brokered-token live ticket writes.
- `mock_messaging`: Slack/Teams-style mock with optional approved, brokered-token, allowlisted HTTPS live sends and approved redacted rollback_message receipts.

Connector output is treated as untrusted tool output and passed through the context firewall.
