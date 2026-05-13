# Migration

Aegis includes dry-run inspectors for Hermes and OpenClaw homes.

```bash
PYTHONPATH=src python3 -m aegis.cli.main migrate openclaw ~/.openclaw
PYTHONPATH=src python3 -m aegis.cli.main migrate hermes ~/.hermes
PYTHONPATH=src python3 -m aegis.cli.main migrate openclaw-memory-preview ~/.openclaw
PYTHONPATH=src python3 -m aegis.cli.main migrate hermes-memory-preview ~/.hermes
PYTHONPATH=src python3 -m aegis.cli.main migrate openclaw-memory-commit ~/.openclaw --reviewer operator
PYTHONPATH=src python3 -m aegis.cli.main migrate hermes-memory-commit ~/.hermes --reviewer operator
```

The inspectors report a metadata-only inventory of discovered memory, skills, config, sessions, context files, plugins, schedules, and process records. Inventory entries include relative paths, suffixes, sizes, path hashes, and secret-like path flags, but never raw file content or content hashes. Memory preview commands parse supported Markdown, text, JSON, and JSONL memory/session files into sanitized candidate records with memory type, source, provenance, confidence, owner, scope, tags, and review-required import action. They do not persist memories automatically. Memory preview resolves candidate files and blocks symlink targets outside the inspected import root without reading or disclosing the target content. Memory commit commands rerun the same preview, persist only unblocked candidates through the governed memory manager, preserve the original platform/path/entry provenance plus reviewer metadata, and leave imported memories unconfirmed unless `--confirmed` is supplied. CLI, API, TUI, and GUI commit flows can narrow commits to selected preview candidate ids. Secret-like imported content is blocked from candidate content and must be routed through the Aegis secrets broker or a separate human-reviewed memory create flow.

The same dry-run inspection, memory-preview, and memory-commit commands are available in `aegis tui` through `migrate openclaw|hermes|openclaw-memory-preview|hermes-memory-preview|openclaw-memory-commit|hermes-memory-commit <path>`.

Local SQLite schema migrations are forward-only and checksum-verified. Operators can inspect the exact dry-run plan and create a private backup before future migration work:

```bash
PYTHONPATH=src python3 -m aegis.cli.main migrate schema
PYTHONPATH=src python3 -m aegis.cli.main migrate plan
PYTHONPATH=src python3 -m aegis.cli.main migrate external-plan postgresql
PYTHONPATH=src python3 -m aegis.cli.main migrate external-plan mysql
PYTHONPATH=src python3 -m aegis.cli.main migrate external-runner postgresql --output-dir .aegis/external-migrations/postgresql
PYTHONPATH=src python3 -m aegis.cli.main migrate backup --destination .aegis/aegis.backup.db
```

Backups are written through SQLite's backup API with private file permissions. The plan includes each migration version, name, checksum, statement count, and applied/pending status.

External schema plans are dry-run artifacts for staging reviews. They translate the checksum-verified forward migrations into target-specific SQL for PostgreSQL or MySQL without opening a network connection or writing to the target. `external-runner` creates a private operator-reviewed bundle with checksum-stamped SQL files, `manifest.json`, and an executable `run.sh` that uses `DATABASE_URL` for PostgreSQL or `MYSQL_DSN` for MySQL. Aegis does not embed credentials or connect to the target; operators must review generated SQL, indexes, and operational DDL before running the script in their own database change workflow.
