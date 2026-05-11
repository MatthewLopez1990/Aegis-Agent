# Execution Backends

Aegis models execution backends as policy-visible capabilities:

- `local`
- `docker`
- `ssh`
- `singularity`
- `modal`
- `daytona`
- `vercel_sandbox`

Only `local` is marked enabled by default, and even local execution still flows through shell allowlists, policy gates, and approvals. Approved `terminal_backend` tool calls can select an enabled backend and expose the active backend in runtime listings.

Docker can be activated explicitly with `[execution].enabled_backends = ["local", "docker"]`. The Docker adapter resolves the configured executable, injects container resource limits for `container_run`, blocks privileged mode, host networking, mounts, and volume flags, and returns activation, execution, and cleanup receipts. Execution receipts hash the command vector instead of logging raw command text.

SSH can be activated explicitly with `[execution].enabled_backends = ["local", "ssh"]`, `ssh_allowed_hosts`, and a brokered private-key secret. The SSH adapter rejects unallowlisted hosts and shell-metacharacter commands, invokes the configured `ssh` executable with batch mode and strict host-key checking, hashes the remote command instead of logging it raw, and deletes temporary key material before returning a cleanup receipt.

Hosted remote backends remain disabled until a secure live adapter, secret broker integration, sandbox profile, and tests are added. Backend listings and backend-gated tool receipts include the required controls and verification gates, so operators can see the exact activation work before enabling hosted sandboxes or other remote execution surfaces.
