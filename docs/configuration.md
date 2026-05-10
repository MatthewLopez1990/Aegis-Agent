# Configuration

Configuration lives in `.aegis/config.toml`.

```toml
[runtime]
data_dir = ".aegis"
database = "aegis.db"
audit_log = "audit.jsonl"
secrets = "secrets.json"

[security]
default_read_only = true
allowed_shell_commands = ["pwd", "ls", "find", "python", "python3"]
network_allowlist = ["example.com", "localhost", "127.0.0.1"]
```

Secure defaults:

- Filesystem connector is read-only.
- HTTP connector is mock-mode unless changed in code.
- Shell commands are parsed without a shell and must match the allowlist.
- Data, audit logs, and brokered model auth secrets stay local.
