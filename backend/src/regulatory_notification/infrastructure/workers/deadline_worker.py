from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


class DeadlineAlertingWorker:
    def __init__(self, repo: Any, alerting: Any, alert_port: Any, deadline_repo: Any) -> None:
        self._repo = repo
        self._alerting = alerting
        self._alert_port = alert_port
        self._deadline_repo = deadline_repo
        self.dead_letters: list[dict[str, Any]] = []
        self.last_events: list[Any] = []

    async def reconstitute_and_tick(self) -> dict[str, Any]:
        now = datetime.now(UTC)
        active = await self._repo.find_active_for_alerting(now)
        events = self._alerting.reconstitute_on_startup(active, now)
        self.last_events = events
        for e in events:
            await self._alert_port.notify(e.tenant_id, type(e).__name__, "high")
        return {"reconstituted": True, "events": len(events), "active": len(active)}

    async def tick(self) -> dict[str, Any]:
        now = datetime.now(UTC)
        active = await self._repo.find_active_for_alerting(now)
        events = self._alerting.evaluate(active, now)
        self.last_events = events
        for e in events:
            await self._alert_port.notify(e.tenant_id, type(e).__name__, "high")
        return {"events": len(events)}


class RegulatoryScheduler:
    def __init__(self, worker: DeadlineAlertingWorker) -> None:
        self._worker = worker
        self.ticks = {
            "deadline": 0,
            "reminder": 0,
            "escalation": 0,
            "notification": 0,
            "health": 0,
            "metrics": 0,
        }

    async def tick_all(self) -> dict[str, Any]:
        for k in self.ticks:
            self.ticks[k] += 1
        result = await self._worker.tick()
        return {"ticks": dict(self.ticks), **result}
