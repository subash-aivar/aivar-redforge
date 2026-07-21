from __future__ import annotations

from typing import Any


class InMemoryDeadlineAlertNotificationAdapter:
    def __init__(self) -> None:
        self.alerts: list[dict[str, Any]] = []

    async def notify(self, tenant_id: str, message: str, severity: str) -> None:
        self.alerts.append({"tenant_id": tenant_id, "message": message, "severity": severity})
