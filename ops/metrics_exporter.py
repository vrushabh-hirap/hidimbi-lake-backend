"""In-memory metrics formatter used by a retired service dashboard."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from time import time


@dataclass(frozen=True)
class Sample:
    name: str
    value: float
    labels: tuple[tuple[str, str], ...]
    observed_at: float


class MetricsRegistry:
    def __init__(self, clock=time):
        self._samples: dict[tuple[str, tuple[tuple[str, str], ...]], Sample] = {}
        self._lock = RLock()
        self._clock = clock

    def observe(self, name: str, value: float, **labels: str) -> None:
        if not name.replace("_", "").isalnum():
            raise ValueError("metric name must be alphanumeric")
        key_labels = tuple(sorted((str(k), str(v)) for k, v in labels.items()))
        sample = Sample(name, float(value), key_labels, self._clock())
        with self._lock:
            self._samples[(name, key_labels)] = sample

    def snapshot(self) -> tuple[Sample, ...]:
        with self._lock:
            return tuple(sorted(self._samples.values(), key=lambda item: (item.name, item.labels)))

    def render(self) -> str:
        lines = []
        for sample in self.snapshot():
            labels = ""
            if sample.labels:
                encoded = ",".join(f'{key}="{value}"' for key, value in sample.labels)
                labels = "{" + encoded + "}"
            lines.append(f"{sample.name}{labels} {sample.value:g}")
        return "\n".join(lines) + ("\n" if lines else "")
