# Scheduler

Schedules store:

- Name.
- Natural-language purpose.
- Cron expression.
- Task request.
- Delivery channel.
- Status.
- Next and last run timestamps.

New schedules start as `paused_pending_approval`. This prevents unattended automation from becoming a hidden write or send path.

Supported cron handling is intentionally conservative in the current runtime: `@hourly`, `0 * * * *`, `@daily`, `0 0 * * *`, or a one-hour fallback estimate for other expressions.
