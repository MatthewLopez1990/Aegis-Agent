# Scheduler

Schedules store:

- Name.
- Natural-language purpose.
- Cron expression.
- Task request.
- Delivery channel.
- Optional `context_from` references, such as workspace paths or `@path` refs.
- Optional delivery targets for rendered run summaries.
- Status.
- Next and last run timestamps.

New schedules start as `paused_pending_approval`. This prevents unattended automation from becoming a hidden write or send path.

Schedules must be approved before activation, then can be paused again, listed when due, and run through the governed task orchestrator:

```bash
PYTHONPATH=src python3 -m aegis.cli.main schedule approve SCHEDULE_ID
PYTHONPATH=src python3 -m aegis.cli.main schedule activate SCHEDULE_ID
PYTHONPATH=src python3 -m aegis.cli.main schedule due
PYTHONPATH=src python3 -m aegis.cli.main schedule run-due
PYTHONPATH=src python3 -m aegis.cli.main schedule pause SCHEDULE_ID
PYTHONPATH=src python3 -m aegis.cli.main schedule create "Context report" @daily "Summarize status" --context-from @docs/status.md --deliver-to slack
PYTHONPATH=src python3 -m aegis.cli.main schedule script "Local probe" @hourly --context-from @docs/status.md --deliver-to slack -- python3 scripts/probe.py
PYTHONPATH=src python3 -m aegis.cli.main schedule evaluation-run "Nightly evaluation" @daily "policy regression" seed "run gates" "review digest" --channel terminal --reviewer security-reviewer
PYTHONPATH=src python3 -m aegis.cli.main schedule evaluation-suite "Security suite" @daily --suite security --reviewer security-reviewer
```

Activation fails until approval metadata is recorded. `run-due` submits due task requests through the same planner, policy gate, approval manager, context firewall, receipts, and audit log as interactive tasks. Explicit `context_from` refs are recorded as schedule metadata, appended to the scheduled task as labeled references, and the first workspace path ref is passed as the planner path target without dumping raw context into schedule metadata. A no-agent hook schedule stores only a bounded redacted `last_hook_output` snapshot, and later schedules can reference it as `schedule:last-hook-output:<schedule_id>`; the snapshot is injected as untrusted, redacted, bounded context with hash/count metadata, not as a trusted instruction source. Each run records the submitted task ID in schedule metadata and advances `next_run_at`.

Specialized memory review schedules render approval-gated digest or escalation messages instead of sending directly. No-agent script schedules are stored as enabled manual hooks and schedule metadata keeps only the hook id, context refs, and delivery targets; execution is argv-only, executable-allowlisted, policy-gated, timeout/output-limited, and receives metadata-only context on JSON stdin. Evaluation run schedules generate a local trajectory, append a private JSONL evaluation report under `.aegis/research/`, include trend summaries, assign the report to a reviewer queue, and render an operator review digest through the configured channel as `rendered_pending_approval`. Evaluation suite schedules run selected security scenarios or the full built-in security suite and queue each report for the configured reviewer. Reviewers can then record dispositions (`reviewed_passed`, `reviewed_failed`, `needs_followup`, or `dismissed`) through CLI, TUI, API, or GUI controls.

When `aegis serve` is running, a local background maintenance worker also polls due schedules and calls the same governed `run-due` path. Due rows are claimed atomically before task submission, so a second worker or concurrent manual trigger skips a schedule already claimed for the same `next_run_at`. The same maintenance pass quietly cleans expired memories and writes audit evidence when records are removed.

Supported cron handling is intentionally conservative in the current runtime: `@hourly`, `0 * * * *`, `@daily`, `0 0 * * *`, or a one-hour fallback estimate for other expressions.
