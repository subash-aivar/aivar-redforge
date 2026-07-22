from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass
class RateWindow:
    window_start: datetime
    action_count: int = 0
    budget: int = 100


@dataclass
class RateLimitTrackingService:
    windows: dict[str, RateWindow] = field(default_factory=dict)
    window_size: timedelta = timedelta(hours=1)

    def consume(self, connector_id: str, *, cost: int = 1) -> int:
        now = datetime.now(UTC)
        win = self.windows.get(connector_id)
        if win is None or now - win.window_start >= self.window_size:
            win = RateWindow(now)
            self.windows[connector_id] = win
        win.action_count += cost
        remaining = max(0, win.budget - win.action_count)
        return remaining

    def budget_remaining(self, connector_id: str) -> int:
        win = self.windows.get(connector_id)
        if win is None:
            return 100
        return max(0, win.budget - win.action_count)
