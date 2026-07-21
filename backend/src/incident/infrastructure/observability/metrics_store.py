from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class OperationalMetricsStore:
    counters: dict[str, int] = field(default_factory=dict)
    timings_ms: list[float] = field(default_factory=list)
    worker_health: dict[str, dict[str, Any]] = field(default_factory=dict)

    def incr(self, name: str, amount: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + amount

    def record_timing(self, ms: float) -> None:
        self.timings_ms.append(ms)

    def mark_worker(self, name: str, ok: bool, error: str | None = None) -> None:
        row = self.worker_health.setdefault(name, {"success": 0, "failure": 0})
        if ok:
            row["success"] += 1
            row["last_success_at"] = datetime.now(UTC).isoformat()
            row["status"] = "healthy"
        else:
            row["failure"] += 1
            row["last_error"] = error
            row["status"] = "degraded"

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(self.counters),
            "timings_ms": list(self.timings_ms[-50:]),
            "workers": list(self.worker_health.values()),
        }
