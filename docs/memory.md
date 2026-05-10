# Memory

Create a confirmed project memory:

```bash
PYTHONPATH=src python3 -m aegis.cli.main memory create project_memory "This repo uses a local SQLite store." --confidence 0.9 --confirmed
```

Search memory:

```bash
PYTHONPATH=src python3 -m aegis.cli.main memory search SQLite
```

Delete memory:

```bash
PYTHONPATH=src python3 -m aegis.cli.main memory delete MEMORY_ID
```

Memory is evidence, not authority. Use provenance and confidence when deciding whether to rely on it.
