# MCP

The MCP registry stores server definitions:

- Name.
- Command.
- Allowed tools.
- Enabled flag.
- Approval-required flag.
- Metadata.

Servers are disabled by default. Live stdio and Streamable HTTP MCP execution is available through one-shot calls after all of these checks pass:

- Server is enabled.
- Tool name is listed in the server's allowed tools.
- Approval is present when the server requires approval.
- Policy allows the high-risk MCP call.
- For stdio, the server executable is in the admin shell allowlist.
- For Streamable HTTP, the endpoint host is in the network allowlist; remote endpoints must use HTTPS, and only explicit loopback hosts may use HTTP.
- Optional Streamable HTTP bearer credentials come from a named local secret handle, not from registry metadata, URLs, audit logs, or model context.
- Output is treated as untrusted tool output and passed through the context firewall before use as model context.

Register and call:

```bash
PYTHONPATH=src python3 -m aegis.cli.main mcp register local-search "python3 /path/to/server.py" --tool search --enable
PYTHONPATH=src python3 -m aegis.cli.main mcp call local-search search --arguments '{"query":"aegis"}' --approved
PYTHONPATH=src python3 -m aegis.cli.main mcp register remote-search "https://mcp.example.com/mcp" --transport streamable-http --discover --tool search --token-secret MCP_REMOTE_TOKEN --enable
PYTHONPATH=src python3 -m aegis.cli.main mcp auth token remote-search MCP_REMOTE_TOKEN
```

The web GUI can list MCP servers, register new server definitions, and run governed MCP calls from the MCP panel. Web-created definitions stay disabled by default and require approval for calls. The dedicated web call form creates an approval record first; replay only succeeds when the approved request matches the original server, tool, argument keys, and argument hash.
The TUI exposes the same conservative registry controls with `mcp list`, `mcp register <name> <command-or-endpoint> <tool,tool> [--transport stdio|streamable-http] [--token-secret name]`, and `mcp auth token <server> <token-secret>`; TUI-created definitions are also disabled and approval-required by default. TUI one-shot calls use `mcp call <server> <tool> <json> [--approved]`, returning approval-required unless the user explicitly passes `--approved`.

MCP stdio calls do not receive raw secrets in their environment. Streamable HTTP calls can attach a brokered bearer token in the `Authorization` header when a token secret is configured, but the raw value stays in the local secrets broker and is redacted from audit/model-facing output. Full OAuth PKCE login and refresh orchestration should be added only with explicit scopes and tests.
