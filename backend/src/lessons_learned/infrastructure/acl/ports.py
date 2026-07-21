from __future__ import annotations

from typing import Any


class InMemoryCampaignRetargetingEventBus:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def publish(self, event: Any) -> None:
        self.events.append(event)


class InMemoryReportArtifactStore:
    def __init__(self) -> None:
        self.artifacts: dict[str, bytes] = {}

    async def store(self, ref: str, payload: bytes) -> str:
        self.artifacts[ref] = payload
        return ref


class InMemoryPostIncidentReportDeliveryPort:
    def __init__(self) -> None:
        self.deliveries: list[dict[str, str]] = []

    async def deliver_email(self, tenant_id: str, report_id: str, to: str) -> None:
        self.deliveries.append(
            {"channel": "email", "tenant_id": tenant_id, "report_id": report_id, "to": to}
        )

    async def deliver_webhook(self, tenant_id: str, report_id: str, url: str) -> None:
        self.deliveries.append(
            {"channel": "webhook", "tenant_id": tenant_id, "report_id": report_id, "to": url}
        )
