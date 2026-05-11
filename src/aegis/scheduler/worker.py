"""Background scheduler worker for local server mode."""

from __future__ import annotations

from threading import Event, Thread
from typing import Protocol

from aegis.audit.logger import redact


class RunnableScheduler(Protocol):
    audit_logger: object

    def run_due_schedules(self) -> dict[str, object]: ...

    def run_background_maintenance(self) -> dict[str, object]: ...


class ScheduleWorker:
    def __init__(self, orchestrator: RunnableScheduler, *, interval_seconds: float = 30.0) -> None:
        self.orchestrator = orchestrator
        self.interval_seconds = interval_seconds
        self._stop = Event()
        self._thread = Thread(target=self._loop, name="aegis-schedule-worker", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, min(self.interval_seconds, 5.0)))

    def run_once(self) -> dict[str, object]:
        if hasattr(self.orchestrator, "run_background_maintenance"):
            return self.orchestrator.run_background_maintenance()
        return self.orchestrator.run_due_schedules()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:  # noqa: BLE001 - background worker must not die silently.
                audit_logger = getattr(self.orchestrator, "audit_logger", None)
                if audit_logger is not None:
                    audit_logger.append("schedule.worker_error", {"error": str(redact(str(exc)))})
            self._stop.wait(self.interval_seconds)
