# Skills Model

Skills are governed by manifests. A manifest declares:

- Stable ID, name, description, version, author, and source.
- Permissions, connectors, secrets, network, filesystem, and commands.
- Input and output schemas.
- Risk level and approval requirement.
- Sandbox profile.
- Tests, evals, rollback, and changelog.

No skill may execute outside its manifest. Runtime permission requests must be a subset of declared permissions.

## Built-In Skills

- `aegis.project_summary`: enabled, read-only filesystem listing through the context firewall.
- `aegis.workflow_candidate`: disabled by default, creates a candidate workflow that requires review.

## Lifecycle

1. Observe repeated work.
2. Propose a candidate.
3. Generate a manifest and tests.
4. Run safety checks.
5. Require approval.
6. Enable and audit usage.
7. Disable or roll back if needed.
