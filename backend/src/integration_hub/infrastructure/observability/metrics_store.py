from __future__ import annotations


class OperationalMetricsStore:
    def __init__(self) -> None:
        self._counters: dict[str, float] = {}

    def incr(self, name: str, value: float = 1.0) -> None:
        self._counters[name] = self._counters.get(name, 0.0) + value

    def snapshot(self) -> dict[str, float]:
        return dict(self._counters)
