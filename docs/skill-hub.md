# Skill Hub

Aegis includes a virtual Skill Hub facade for large external skill registries.

Browse it safely from the CLI, TUI, or web GUI:

```bash
PYTHONPATH=src python3 -m aegis.cli.main skill hub-search browser
PYTHONPATH=src python3 -m aegis.cli.main tui
# then run: skills hub browser
PYTHONPATH=src python3 -m aegis.cli.main serve
# then search the Skill Hub panel in the browser UI
```

The facade can advertise a large registry capacity while keeping installation safe:

- No code is downloaded automatically.
- Search results are metadata only.
- Installation requires signed manifest verification, manifest validation, static checks, sandbox checks, risk classification, and approval.
- High-risk skills start disabled or approval-required.

This is how Aegis supports OpenClaw-style broad skill ecosystems without inheriting unsafe community-skill defaults.
