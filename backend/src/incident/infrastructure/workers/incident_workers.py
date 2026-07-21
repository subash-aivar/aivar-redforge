"""Incident workers — recovery, analytics publish, retry/DLQ, schedulers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


class RetryWorker:
    def __init__(self, max_retries: int = 3) -> None:
        self.max_retries = max_retries
        self.dead_letters: list[dict[str, Any]] = []
        self.checkpoint: str | None = None

    async def process(self, item: dict[str, Any], handler: Any) -> dict[str, Any]:
        attempts = 0
        last_error: str | None = None
        while attempts < self.max_retries:
            attempts += 1
            try:
                result = await handler(item)
                self.checkpoint = str(item.get("id") or item.get("event_id") or "")
                return {"ok": True, "result": result, "attempts": attempts}
            except Exception as exc:
                last_error = str(exc)
        self.dead_letters.append(
            {"item": item, "error": last_error, "at": datetime.now(UTC).isoformat()}
        )
        return {"ok": False, "dead_lettered": True, "attempts": attempts}


class RecoveryWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.last_run_at: datetime | None = None

    async def tick(self) -> dict[str, Any]:
        self.last_run_at = datetime.now(UTC)
        return {"status": "ok", "at": self.last_run_at.isoformat()}


class AnalyticsPublishingWorker:
    def __init__(self, analytics_adapter: Any) -> None:
        self._adapter = analytics_adapter
        self.last_count = 0

    async def tick(self) -> dict[str, Any]:
        self.last_count = len(getattr(self._adapter, "rows", []))
        return {"published_rows": self.last_count}


class IncidentScheduler:
    def __init__(self) -> None:
        self.last_tick_at: datetime | None = None
        self.ticks: dict[str, int] = {
            "deadline": 0,
            "reminder": 0,
            "escalation": 0,
            "notification": 0,
            "lessons": 0,
            "analytics": 0,
            "health": 0,
            "metrics": 0,
        }

    async def tick_all(self) -> dict[str, Any]:
        self.last_tick_at = datetime.now(UTC)
        for key in self.ticks:
            self.ticks[key] += 1
        return {"last_tick_at": self.last_tick_at.isoformat(), "ticks": dict(self.ticks)}
