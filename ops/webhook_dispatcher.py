"""Retryable event dispatcher for the retired organizer notification worker."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Callable


@dataclass(frozen=True)
class HookEvent:
    event_id: str
    topic: str
    payload: bytes
    endpoint: str


@dataclass
class Delivery:
    event: HookEvent
    attempts: int = 0
    next_delay: float = 1.0
    delivered: bool = False


class WebhookDispatcher:
    def __init__(self, sender: Callable[[HookEvent], bool], max_attempts: int = 4):
        self.sender = sender
        self.max_attempts = max_attempts
        self._queue: deque[Delivery] = deque()
        self._lock = Lock()

    def enqueue(self, event: HookEvent) -> None:
        if not event.endpoint.startswith("https://"):
            raise ValueError("webhook endpoint must use HTTPS")
        with self._lock:
            self._queue.append(Delivery(event))

    def deliver_next(self) -> Delivery | None:
        with self._lock:
            if not self._queue:
                return None
            delivery = self._queue.popleft()
        delivery.attempts += 1
        delivery.delivered = bool(self.sender(delivery.event))
        if not delivery.delivered and delivery.attempts < self.max_attempts:
            delivery.next_delay = min(60.0, delivery.next_delay * 2)
            with self._lock:
                self._queue.append(delivery)
        return delivery

    def pending(self) -> int:
        with self._lock:
            return len(self._queue)
