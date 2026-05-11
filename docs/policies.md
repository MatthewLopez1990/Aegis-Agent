# Policies

The default policy posture is read-only and approval-first for risky actions. Aegis can also load an admin policy profile from TOML through `.aegis/config.toml`:

```toml
[policy]
path = "../examples/policies/default-policy.toml"
```

Supported profile sections:

- `[defaults]`: controls decisions such as `message_send`, `shell_execution`, `destructive_action`, `unapproved_network_egress`, `connector_write_without_scope`, and `high_risk_action`.
- `[network]`: sets the allowlist used by policy checks for HTTP, REST, and model-provider egress.
- `[shell]`: sets allowed shell command names.

Raw secret exposure and secret data are immutable-deny controls. A policy file cannot relax them to `allow`.

The local API exposes read-only policy posture through `GET /policy`, built-in environment bundles through `GET /policy/bundles`, and a dry policy evaluator through `POST /policy/evaluate`. The evaluator returns the decision, reasons, risk level, and requirements without executing the requested operation. The TUI exposes the same surface through `security profile`, `security bundles`, and `security evaluate <operation> <risk> <scopes> [target_domain]`.

Built-in policy bundles are exportable from the CLI:

```bash
PYTHONPATH=src python3 -m aegis.cli.main policy bundles
PYTHONPATH=src python3 -m aegis.cli.main policy export-bundle strict-local
PYTHONPATH=src python3 -m aegis.cli.main policy import-bundle ./policy.toml
PYTHONPATH=src python3 -m aegis.cli.main policy diff-bundle ./policy.toml
PYTHONPATH=src python3 -m aegis.cli.main policy apply-bundle ./policy.toml --name workspace-policy --approved
PYTHONPATH=src python3 -m aegis.cli.main policy apply-bundle strict-local --approved
PYTHONPATH=src python3 -m aegis.cli.main policy schedule-bundle strict-local --activate-at 2026-05-11T12:00:00Z --environment staging --approved
PYTHONPATH=src python3 -m aegis.cli.main policy activate-due --now 2026-05-11T12:01:00Z
PYTHONPATH=src python3 -m aegis.cli.main policy promote-bundle strict-local --from-environment staging --to-environment production --approved
PYTHONPATH=src python3 -m aegis.cli.main policy rollouts
PYTHONPATH=src python3 -m aegis.cli.main policy rollback-bundle --approved
```

`strict-local` requires admin approval for risky local actions and unapproved egress, `approval-first` mirrors the default Aegis posture, and `developer-local` keeps approval gates while adding loopback/example development allowlists. Raw secret exposure and secret data stay immutable-deny in every bundle.

Policy import validates an external TOML bundle without applying it. Policy diff compares a candidate bundle against the active profile before rollout. Policy apply requires explicit approval, writes the normalized bundle to `.aegis/policies/<name>.toml`, updates `.aegis/config.toml` to point at it, and records a rollback receipt. Scheduled rollouts and environment promotion also require approval, write private receipts or promoted TOML artifacts under `.aegis/policies/`, and do not update the active config by themselves. Due rollout activation is a separate worker action: it consumes approved scheduled receipts whose `activate_at` is due, writes the normalized policy file, updates the active config pointer, marks the receipt `activated`, and reports `restart_required`. Rollback also requires explicit approval and restores the previous policy pointer or removes the policy pointer if no previous bundle was configured. Apply, activation, and rollback report `restart_required` so a running server can reload connectors and policy-backed allowlists from the new configuration. The web API exposes validation, diff, apply, schedule, activation, promote, rollout listing, and rollback through `POST /policy/import-bundle`, `POST /policy/diff-bundle`, `POST /policy/apply-bundle`, `POST /policy/schedule-bundle`, `POST /policy/activate-due`, `POST /policy/promote-bundle`, `GET /policy/rollouts`, and `POST /policy/rollback-bundle`; the browser GUI can diff/apply built-in bundles from the policy list and roll back the last applied bundle.

Examples:

- Filesystem read: allowed.
- Filesystem write without write scope: denied.
- Message send: approval required.
- Message send with `message_send = "require_admin_approval"`: admin approval required.
- Shell execution without execute scope: denied.
- Shell execution with scope but no approval: approval required.
- Raw secret exposure: denied.
- HTTP egress to a domain outside the allowlist: approval required.

Admin approval uses the same approval queue with stronger decision evidence. CLI and TUI approval commands accept `--admin`; the API approve/deny endpoints accept an `admin` boolean. A normal approval does not satisfy `require_admin_approval`, so the task remains paused until an admin decision is recorded.
