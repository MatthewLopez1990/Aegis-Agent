# Connectors

List connectors:

```bash
PYTHONPATH=src python3 -m aegis.cli.main connector list
PYTHONPATH=src python3 -m aegis.cli.main connector status
```

Reference connectors are intentionally conservative. Real credential-backed integrations should use the secrets broker, scoped permissions, mock/test modes, dry runs, audit logging, and approval gates for writes.

The current runtime includes mock/stub connectors for GitHub, Microsoft Graph, ServiceNow, messaging, generic REST, HTTP, shell, and local filesystem.
