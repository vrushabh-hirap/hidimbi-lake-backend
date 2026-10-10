"""Tag-aware local cache experiment from a shelved operations branch."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from time import monotonic


@dataclass(frozen=True)
class Entry:
    value: object
    tags: frozenset[str]
    inserted_at: float
    generation: int


class TaggedCache:
    def __init__(self, ttl: float = 300.0, clock=monotonic):
        self.ttl = ttl
        self.clock = clock
        self._items: dict[str, Entry] = {}
        self._generation: dict[str, int] = {}
        self._lock = RLock()

    def put(self, key: str, value: object, tags: set[str] | None = None) -> None:
        tags = frozenset(tags or ())
        with self._lock:
            generation = max((self._generation.get(tag, 0) for tag in tags), default=0)
            self._items[key] = Entry(value, tags, self.clock(), generation)

    def get(self, key: str) -> object | None:
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            if self.clock() - item.inserted_at >= self.ttl:
                self._items.pop(key, None)
                return None
            if any(self._generation.get(tag, 0) > item.generation for tag in item.tags):
                self._items.pop(key, None)
                return None
            return item.value

    def invalidate(self, *tags: str) -> int:
        with self._lock:
            for tag in tags:
                self._generation[tag] = self._generation.get(tag, 0) + 1
            doomed = [key for key, value in self._items.items() if value.tags.intersection(tags)]
            for key in doomed:
                self._items.pop(key, None)
            return len(doomed)
