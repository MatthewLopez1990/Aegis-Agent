# Execution Backends

Aegis models execution backends as policy-visible capabilities:

- `local`
- `docker`
- `ssh`
- `singularity`
- `modal`
- `daytona`
- `vercel_sandbox`

Only `local` is marked enabled by default, and even local execution still flows through shell allowlists, policy gates, and approvals. Remote and container backends remain disabled until a secure live adapter, secret broker integration, sandbox profile, and tests are added.
