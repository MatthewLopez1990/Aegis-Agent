# Policy Model

The policy engine evaluates:

- User role and workspace.
- Task type and risk level.
- Connector and operation.
- Requested scopes.
- Data sensitivity.
- Skill manifest validation.
- Approval state.
- Environment and target domain.

Possible decisions:

- `allow`
- `deny`
- `require_approval`
- `require_dry_run_first`
- `require_additional_evidence`
- `require_safer_alternative`
- `require_admin_approval`
- `quarantine`

The current runtime actively uses allow, deny, require approval, and require admin approval. Other decisions are defined for policy-file growth. Built-in bundles (`strict-local`, `approval-first`, and `developer-local`) can be listed through the CLI/API/TUI/GUI, exported as TOML starting points, validated as imports, diffed against the active profile, applied only with explicit approval, scheduled as approved rollout receipts, activated when due by a local worker, and rolled back from the last apply or activation receipt. Applying or activating a bundle stores a normalized local TOML file under `.aegis/policies/` and updates `.aegis/config.toml`.

See `examples/policies/default-policy.toml`.
