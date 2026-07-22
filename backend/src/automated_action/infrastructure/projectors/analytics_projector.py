from __future__ import annotations

from typing import Any


class AutomationAnalyticsProjector:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def project(self, event: Any) -> None:
        self.rows.append(
            {
                "event_type": type(event).__name__,
                "tenant_id": getattr(event, "tenant_id", ""),
                "execution_id": getattr(event, "execution_id", ""),
                "payload": event.__dict__ if hasattr(event, "__dict__") else {},
            }
        )
