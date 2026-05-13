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

Hosted sandbox backends can be activated explicitly for `modal`, `daytona`, or `vercel_sandbox` with `[execution].enabled_backends`, `hosted_sandbox_allowed_hosts`, an HTTPS `hosted_sandbox_api_url` or per-call `provider_url`, and a brokered token secret. The generic hosted sandbox adapter rejects unallowlisted API hosts, local/private targets, redirects, and shell-metacharacter commands, submits command arguments to the configured provider endpoint, hashes the command in receipts instead of logging it raw, and returns only sanitized job metadata. The same approved tool path can send generic lifecycle requests with `action=status|logs|cancel|artifact|rollback` and a simple `job_id`; responses are summarized through redacted receipts, logs are bounded, and downloaded artifacts are written privately under `.aegis/backend-artifacts`.

Provider-specific hosted lifecycle APIs remain staged behind future adapter work, but the generic lifecycle contract now covers status, bounded log retrieval, cancellation, artifact download, and rollback requests through the configured HTTPS provider endpoint. Backend listings and backend-gated tool receipts include the required controls and verification gates, so operators can see the exact activation work before enabling broader remote execution surfaces. Backend listings and denied backend-gated tool calls also include an activation preflight with configured controls and blockers: Docker checks container network/resource posture, SSH checks allowlisted hosts plus brokered key handles, and hosted sandboxes check HTTPS API URL, allowed hosts, and brokered token handles.

The product dashboard reports enabled nonlocal adapters as redacted `implemented_backend_adapters` evidence and disabled implemented adapters as redacted `available_backend_adapters` evidence. Singularity remains listed as a policy-visible backend definition, but it is not reported as an available adapter until a concrete execution implementation exists.
