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

The current runtime actively uses allow, deny, and require approval. Other decisions are defined for policy-file growth.

See `examples/policies/default-policy.toml`.
