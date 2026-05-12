# Skills

List skills:

```bash
PYTHONPATH=src python3 -m aegis.cli.main skill list
```

The local API exposes the same installed skill inventory at `GET /skills` for the browser GUI. That response is intentionally summarized: it includes enabled state, name, description, version, risk, approval requirement, sandbox profile, validation state, connectors, permission capability labels, and boolean flags for secrets/network/commands/filesystem access, but it does not expose raw manifests, source paths, command strings, schema bodies, signature material, or secret handle names.

Installed skills can be disabled without deleting their manifest through the CLI (`skill disable <skill_id>`), TUI (`skills disable <skill_id>`), token-protected local API (`POST /skills/{skill_id}/disable`), or the browser GUI installed-skill list. Low- and medium-risk skills can be re-enabled through the matching `enable` commands or `POST /skills/{skill_id}/enable`. High-risk skills create an approval request bound to the skill id, risk level, and manifest hash; after approval, replay `skill enable <skill_id> --approval-id <approval_id>`, `skills enable <skill_id> --approval-id <approval_id>`, or `POST /skills/{skill_id}/enable` with `{"approval_id":"..."}`. Critical-risk skills additionally require an admin approval decision. Unknown skill IDs fail closed.

Local plugin manifests can group skills with MCP servers and lifecycle hooks without bypassing those controls. Use `plugin install /path/to/plugin.json` or `plugins install /path/to/plugin.json --unsigned-local` for development-only unsigned skill manifests, then `plugin enable|disable|remove <plugin_id>` or the matching token-protected `/plugins` API endpoints. `plugins marketplace` and `plugins updates` provide metadata-only marketplace discovery and update planning from the built-in catalog or an operator-supplied local catalog JSON; they do not download marketplace bundles, dynamically import plugin code, capture marketplace tokens, or auto-update unsigned resources. Plugin resource paths must stay relative to the plugin manifest directory, duplicate skills or MCP server names are rejected, owned resources are removed with the plugin, and failed installs roll back any resources registered before the failure. The current plugin lifecycle remains local-install only; marketplace entries must still be obtained, reviewed, and installed through the governed manifest path.

Register a manifest:

```bash
PYTHONPATH=src python3 -m aegis.cli.main skill create example.my_skill --name "My Skill" --description "Disabled template" --output /tmp/my-skill.json
PYTHONPATH=src python3 -m aegis.cli.main skill signing-key
PYTHONPATH=src python3 -m aegis.cli.main skill sign /tmp/my-skill.json
PYTHONPATH=src python3 -m aegis.cli.main skill verify /tmp/my-skill.json
PYTHONPATH=src python3 -m aegis.cli.main skill register /tmp/my-skill.json --enable
```

External skill manifests must be signed before registration. The current signer verifies manifest JSON with a local HMAC trust root; it is not a third-party package-signing chain. For local development only, pass `--unsigned-local` to register an unsigned manifest without treating it as trusted provenance.

High-risk skills cannot be silently enabled. Skills that request shell, network, secrets, identity, email send, file delete, production write permissions, or isolated process execution should be classified high risk and approval-required.

Registration also runs dependency-light static checks over manifest commands, network allowlists, and local source paths when present. Wildcard network access, shell download/install patterns, destructive command entries, dynamic eval/exec, raw socket creation, and direct shell spawns are blocked before the manifest is stored. Failures are audited as `skill.static_scan_failed`.

Sandbox profiles are enforced at runtime, not only documented in the manifest. `no_tools` blocks connectors, filesystem, network, shell, and secrets; `read_only_no_network` allows read-only filesystem access but rejects writes, network, shell, and secrets; `mock_connectors_only` rejects non-mock connectors; `isolated_process_no_network` allows one manifest-declared Python entrypoint to run as a subprocess with JSON stdin/stdout, no network declaration, no secrets, no shell, a minimal environment, bounded output, OS-enforced CPU/address-space limits when supported, and timeout auditing. Oversized stdout/stderr is rejected and audited before JSON parsing; reviewed manifests can tune this with `permissions.process.max_output_bytes`, `permissions.process.max_cpu_seconds`, and `permissions.process.max_memory_mb` within runtime caps. `isolated_process_ephemeral` is stricter: it rejects declared filesystem access and starts the Python process in a private temporary working directory instead of the skill source directory. Denials are audited as `skill.sandbox_profile_denied`; completed, timed-out, and output-limited process skills are audited as `skill.process_completed`, `skill.process_timeout`, and `skill.process_output_limit`.
