"""Small runtime rate limiter for live connector calls."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import threading
import time
from typing import Callable


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    window_seconds: int
    remaining: int
    retry_after_seconds: int

    def to_dict(self) -> dict[str, int | bool]:
        return {
            "allowed": self.allowed,
            "limit": self.limit,
            "window_seconds": self.window_seconds,
            "remaining": self.remaining,
            "retry_after_seconds": self.retry_after_seconds,
        }


class InMemoryRateLimiter:
    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, *, limit: int, window_seconds: int = 60) -> RateLimitDecision:
        if limit <= 0 or window_seconds <= 0:
            return RateLimitDecision(True, limit, window_seconds, 0, 0)
        now = self._clock()
        cutoff = now - window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(round(window_seconds - (now - events[0]))))
                return RateLimitDecision(False, limit, window_seconds, 0, retry_after)
            events.append(now)
            remaining = max(0, limit - len(events))
        return RateLimitDecision(True, limit, window_seconds, remaining, 0)
