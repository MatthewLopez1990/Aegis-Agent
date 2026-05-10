# Skills

List skills:

```bash
PYTHONPATH=src python3 -m aegis.cli.main skill list
```

Register a manifest:

```bash
PYTHONPATH=src python3 -m aegis.cli.main skill create example.my_skill --name "My Skill" --description "Disabled template" --output /tmp/my-skill.json
PYTHONPATH=src python3 -m aegis.cli.main skill register examples/skills/project-summary.json --enable
```

High-risk skills cannot be silently enabled. Skills that request shell, network, secrets, identity, email send, file delete, or production write permissions should be classified high risk and approval-required.
