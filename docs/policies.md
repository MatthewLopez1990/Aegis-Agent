# Policies

The default policy posture is read-only and approval-first for risky actions.

Examples:

- Filesystem read: allowed.
- Filesystem write without write scope: denied.
- Message send: approval required.
- Shell execution without execute scope: denied.
- Shell execution with scope but no approval: approval required.
- Raw secret exposure: denied.
- HTTP egress to a domain outside the allowlist: approval required.

Future policy work should load environment-specific TOML/YAML files and support admin approval routes.
