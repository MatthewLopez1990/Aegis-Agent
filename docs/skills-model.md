# Skills Model

Skills are governed by manifests. A manifest declares:

- Stable ID, name, description, version, author, and source.
- Permissions, connectors, secrets, network, filesystem, and commands.
- Input and output schemas.
- Risk level and approval requirement.
- Sandbox profile.
- Tests, evals, rollback, and changelog.
- Optional manifest signature metadata for externally registered skills.

No skill may execute outside its manifest. Runtime permission requests must be a subset of declared permissions, and the declared sandbox profile is enforced before connector access. Profile violations are blocked even if a manifest claims broader connector permissions. Registration also performs static checks over manifest commands, wildcard network access, and local source files to block dangerous generated code before storage.

Generated process skills use `isolated_process_no_network` or the stricter `isolated_process_ephemeral` profile. The runtime accepts one manifest command in the form `python3 <script.py>`, resolves the script under the skill source path, runs it without a shell through isolated Python, sends validated inputs on JSON stdin, requires JSON object stdout, strips inherited secrets from the environment, enforces bounded stdout/stderr before parsing, and audits completion, timeout, or output-limit violations. Manifests can set `permissions.process.max_output_bytes` up to the runtime cap for reviewed skills that need larger JSON responses.

`isolated_process_ephemeral` additionally rejects declared filesystem access and runs the script from a private temporary working directory instead of the skill source directory. This is the preferred generated-skill profile when the skill only needs JSON inputs and should not see adjacent source files through relative paths.

## Built-In Skills

- `aegis.project_summary`: enabled, read-only filesystem listing through the context firewall.
- `aegis.workflow_candidate`: disabled by default, creates a candidate workflow that requires review.

## Lifecycle

1. Observe repeated work.
2. Propose a candidate.
3. Generate a manifest and tests.
4. Run safety checks.
5. Sign the manifest or mark it explicitly as unsigned local development.
6. Require approval.
7. Enable and audit usage.
8. Disable or roll back if needed.
