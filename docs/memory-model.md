# Memory Model

Memory records include:

- ID, type, content, summary, source, provenance.
- Confidence, sensitivity, owner, scope, tags.
- Created, updated, and last-confirmed timestamps.
- Expiration placeholder and deletion state.
- Redaction status and searchable text.

Supported memory types:

- `profile_memory`
- `preference_memory`
- `project_memory`
- `workflow_memory`
- `procedural_memory`
- `episodic_memory`
- `connector_memory`
- `policy_memory`
- `skill_memory`

## Safety Rules

- Secret-like content is refused as normal memory.
- Confidential or secret memory requires explicit confirmation.
- Low-confidence memory requires confirmation.
- Retrieval is audited and does not make memory automatically true.
- Deletion is soft-delete for auditability.

## CLI

```bash
PYTHONPATH=src python3 -m aegis.cli.main memory create project_memory "Uses SQLite for durable state" --confidence 0.9 --tag sqlite
PYTHONPATH=src python3 -m aegis.cli.main memory search SQLite
PYTHONPATH=src python3 -m aegis.cli.main memory delete MEMORY_ID
```
