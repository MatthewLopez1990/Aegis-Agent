# Memory Model

Memory records include:

- ID, type, content, summary, source, provenance.
- Confidence, sensitivity, owner, scope, tags.
- Created, updated, and last-confirmed timestamps.
- Expiration, recertification, and deletion state.
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
- Health reports are read-only and audit aggregate counts, not raw memory content.

## Lifecycle And Readiness

Memory starts as a candidate, imported/session preview, or direct create request. Candidate commits preserve source provenance and stay unconfirmed unless the operator explicitly confirms them. Review queues, digests, escalations, recertification, and health reports surface records that need human review before they should influence high-impact work.

The memory health report scores records by confidence, provenance, confirmation, and freshness. It also recommends duplicate merges, conflict resolution, recertification, or confirm/delete review actions. The dashboard summarizes this as `memory_readiness` with counts and flags, while detailed record content stays inside the governed memory APIs.

Conflict resolution is explicit and audited. Operators can keep one memory, synthesize memories, or keep both with review tags. Duplicate consolidation is recommended by health reports but still requires an explicit merge action.

## CLI

```bash
PYTHONPATH=src python3 -m aegis.cli.main memory create project_memory "Uses SQLite for durable state" --confidence 0.9 --tag sqlite
PYTHONPATH=src python3 -m aegis.cli.main memory health
PYTHONPATH=src python3 -m aegis.cli.main memory search SQLite
PYTHONPATH=src python3 -m aegis.cli.main memory delete MEMORY_ID
```
