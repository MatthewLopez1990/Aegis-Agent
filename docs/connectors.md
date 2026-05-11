# Connectors

List connectors:

```bash
PYTHONPATH=src python3 -m aegis.cli.main connector list
PYTHONPATH=src python3 -m aegis.cli.main connector status
```

Reference connectors are intentionally conservative. Real credential-backed integrations should use the secrets broker, scoped permissions, mock/test modes, dry runs, audit logging, and approval gates for writes. The CLI, API, and browser GUI expose connector policy metadata, including required and optional scopes, per-operation scopes, risk labels, and declared data sensitivity.

The current runtime includes mock/stub connectors for messaging, shell, and local filesystem. Generic REST, GitHub, GitLab, service-desk, calendar, contact, Graph-compatible email, and messaging writes are mock summaries by default, but can run as approved live HTTPS writes when explicitly enabled, allowlisted, and backed by brokered credentials where required. GitHub issue and pull-request reads plus GitLab issue and merge-request reads can also use allowlisted provider-compatible JSON URLs through the governed HTTP connector, calendar/contact reads can use allowlisted Graph-compatible JSON URLs with mock fallback, and service-desk ticket reads can use allowlisted ServiceNow/Jira-style JSON URLs with mock fallback. Connectors declare per-operation scopes, and the tool router uses that metadata so connector-specific reads such as calendar lookup stay read-scoped while writes such as event creation, ticket closure, or message send require write scope before connector execution. Mock connector write, dry-run, rollback, governed live-write denials, and governed live-write results summarize accepted parameters by keys, size, hash, activation preflight status, and blockers instead of returning raw payload or secret values. The product dashboard reports configured live connector and channel adapters through redacted `implemented_live_adapters` evidence, and disabled-but-implemented opt-in paths through redacted `available_live_adapters` evidence with activation preflight blockers, so operators can tell which parity gaps require configuration versus new adapter work without exposing secret names or payloads.

HTTP reads can run live only when `live_http_reads = true` is set and the target domain is allowlisted; unsafe schemes, credentials embedded in URLs, DNS targets that cannot be verified, and local/private network targets are blocked. The governed HTTP connector does not follow redirects, and off-allowlist redirect targets are rejected before response bodies are read.

Generic REST writes and `webhook_call` remain mock summaries by default. When `live_rest_writes = true` is set, approved writes can make HTTPS calls to allowlisted public domains. Live REST writes reject non-HTTPS URLs, redirects, local/private network targets, and missing approval, and still return only payload hashes, keys, byte counts, status, and rollback guidance instead of raw payload values.

GitHub issue creation and pull-request comments use the same explicit write posture. Without `api_url` or `provider_url`, the connector returns the mock summary used for offline tests. With a GitHub-compatible HTTPS API URL, `live_rest_writes = true`, an allowlisted host, approval, and a brokered `GITHUB_TOKEN` or requested `token_secret`, Aegis sends the write and returns only status plus sanitized request metadata.

GitLab issue creation and merge-request comments follow the same posture. Without `api_url` or `provider_url`, the connector returns the mock summary used for offline tests. With a GitLab-compatible HTTPS API URL, `live_rest_writes = true`, an allowlisted host, approval, and a brokered `GITLAB_TOKEN` or requested `token_secret`, Aegis sends the write and returns only status plus sanitized request metadata.

Service-desk ticket creation, update, and close actions follow the same pattern. Without `api_url` or `provider_url`, the connector returns the mock summary used for offline tests. With a ServiceNow/Jira-compatible HTTPS API URL, `live_rest_writes = true`, an allowlisted host, approval, and a brokered `SERVICE_DESK_TOKEN` or requested `token_secret`, Aegis sends the write and returns only status plus sanitized request metadata.

Calendar event creation is also mock-first. Without `api_url` or `provider_url`, the Graph-style connector returns the mock summary used for offline tests. With a Microsoft Graph or Google-style HTTPS events API URL, `live_rest_writes = true`, an allowlisted host, approval, and a brokered `GRAPH_TOKEN` or requested `token_secret`, Aegis sends the write and returns only status plus sanitized request metadata.

Graph-compatible email draft and send actions use the same connector posture. Without `api_url` or `provider_url`, the connector returns the mock summary used for offline tests. With a Microsoft Graph or Google-style HTTPS mail API URL, `live_rest_writes = true`, an allowlisted host, approval, and a brokered `GRAPH_TOKEN` or requested `token_secret`, Aegis sends the write and returns only status plus sanitized request metadata.

Contact creation and update actions also use the Graph-style connector. Without `api_url` or `provider_url`, the connector returns the mock summary used for offline tests. With a Microsoft Graph or Google-style HTTPS contacts API URL, `live_rest_writes = true`, an allowlisted host, approval, and a brokered `GRAPH_TOKEN` or requested `token_secret`, Aegis sends the write and returns only status plus sanitized request metadata.
