# MCP

The MCP registry stores server definitions:

- Name.
- Command.
- Allowed tools.
- Enabled flag.
- Approval-required flag.
- Metadata.

Servers are disabled by default. Live stdio MCP execution is available through one-shot calls after all of these checks pass:

- Server is enabled.
- Tool name is listed in the server's allowed tools.
- Approval is present when the server requires approval.
- Policy allows the high-risk MCP call.
- The server executable is in the admin shell allowlist.
- Output is treated as untrusted tool output and passed through the context firewall before use as model context.

Register and call:

```bash
PYTHONPATH=src python3 -m aegis.cli.main mcp register local-search "python3 /path/to/server.py" --tool search --enable
PYTHONPATH=src python3 -m aegis.cli.main mcp call local-search search --arguments '{"query":"aegis"}' --approved
```

The web GUI can list MCP servers, register new server definitions, and run governed MCP calls from the MCP panel. Web-created definitions stay disabled by default and require approval for calls. The dedicated web call form creates an approval record first; replay only succeeds when the approved request matches the original server, tool, argument keys, and argument hash.
The TUI exposes the same conservative registry controls with `mcp list` and `mcp register <name> <command> <tool,tool>`; TUI-created definitions are also disabled and approval-required by default. TUI one-shot calls use `mcp call <server> <tool> <json> [--approved]`, returning approval-required unless the user explicitly passes `--approved`.

MCP calls do not receive raw secrets in their environment in the current runtime. Brokered per-server secret injection should be added only with explicit scopes and tests.
