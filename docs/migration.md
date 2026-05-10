# Migration

Aegis includes dry-run inspectors for Hermes and OpenClaw homes.

```bash
PYTHONPATH=src python3 -m aegis.cli.main migrate openclaw ~/.openclaw
PYTHONPATH=src python3 -m aegis.cli.main migrate hermes ~/.hermes
```

The inspectors report discovered memory, skills, config, sessions, and context files. Secret import is blocked by default and must be routed through the Aegis secrets broker.
