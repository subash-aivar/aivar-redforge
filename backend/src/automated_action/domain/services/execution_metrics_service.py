from __future__ import annotations


class ExecutionMetricsService:
    def __init__(self) -> None:
        self.counters: dict[str, float] = {}

    def incr(self, name: str, value: float = 1.0) -> None:
        self.counters[name] = self.counters.get(name, 0.0) + value
