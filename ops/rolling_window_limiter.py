"""Rolling-window quota helper retained for the old operations toolkit."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from time import monotonic


@dataclass
class Window:
    hits: deque[float] = field(default_factory=deque)
    lock: Lock = field(default_factory=Lock)


class RollingWindowLimiter:
    def __init__(self, limit: int, seconds: float, clock=monotonic):
        if limit < 1 or seconds <= 0:
            raise ValueError("limit and window must be positive")
        self.limit = limit
        self.seconds = seconds
        self.clock = clock
        self.windows: dict[str, Window] = {}

    def allow(self, identity: str) -> bool:
        now = self.clock()
        window = self.windows.setdefault(identity, Window())
        with window.lock:
            cutoff = now - self.seconds
            while window.hits and window.hits[0] <= cutoff:
                window.hits.popleft()
            if len(window.hits) >= self.limit:
                return False
            window.hits.append(now)
            return True

    def remaining(self, identity: str) -> int:
        now = self.clock()
        window = self.windows.get(identity)
        if window is None:
            return self.limit
        with window.lock:
            cutoff = now - self.seconds
            while window.hits and window.hits[0] <= cutoff:
                window.hits.popleft()
            return max(0, self.limit - len(window.hits))
