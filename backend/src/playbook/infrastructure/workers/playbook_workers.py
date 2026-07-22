"""Playbook schedulers and metrics workers."""

from __future__ import annotations

from typing import Any


class MetricsWorker:
    def __init__(self) -> None:
        self.ticks = 0
        self.metrics: dict[str, float] = {}

    def tick(self) -> None:
        self.ticks += 1
        self.metrics["playbook.worker.ticks"] = float(self.ticks)


class PolicyScheduler:
    def __init__(self, policy_cache: dict[str, Any] | None = None) -> None:
        self._cache = policy_cache if policy_cache is not None else {}
        self.ticks = 0

    def tick(self) -> None:
        self.ticks += 1
        # cache TTL enforcement placeholder — entries older than 10s cleared by caller
        stale = [k for k, v in self._cache.items() if v.get("age_s", 0) > 10]
        for k in stale:
            del self._cache[k]


class PlaybookScheduler:
    def __init__(self) -> None:
        self.metrics_worker = MetricsWorker()
        self.policy_scheduler = PolicyScheduler()

    def tick_all(self) -> dict[str, int]:
        self.metrics_worker.tick()
        self.policy_scheduler.tick()
        return {
            "metrics_ticks": self.metrics_worker.ticks,
            "policy_ticks": self.policy_scheduler.ticks,
        }
