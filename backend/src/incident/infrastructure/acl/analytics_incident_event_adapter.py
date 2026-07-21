from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from incident.domain.ports.outbound_ports import IAnalyticsIncidentEventPort


class InMemoryAnalyticsIncidentEventAdapter(IAnalyticsIncidentEventPort):
    """Publishes into analytics.incident_events projection rows (in-memory)."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def publish_classified(self, event: Any) -> None:
        self.rows.append(
            {
                "event_id": str(uuid4()),
                "tenant_id": event.tenant_id,
                "incident_id": event.incident_id,
                "event_type": "incident_classified",
                "severity": event.severity,
                "classified_at": event.classified_at,
                "closed_at": None,
                "resolution_type": None,
                "event_ts": event.classified_at,
                "payload": {
                    "classification_method": event.classification_method,
                    "trigger_type": event.trigger_type,
                    "source_finding_ref": event.source_finding_ref,
                    "source_investigation_ref": event.source_investigation_ref,
                },
                "ingested_at": datetime.now(UTC).isoformat(),
            }
        )

    async def publish_closed(self, event: Any) -> None:
        self.rows.append(
            {
                "event_id": str(uuid4()),
                "tenant_id": event.tenant_id,
                "incident_id": event.incident_id,
                "event_type": "incident_closed",
                "severity": None,
                "classified_at": event.classified_at,
                "closed_at": event.closed_at,
                "resolution_type": event.resolution_type,
                "event_ts": event.closed_at,
                "payload": {
                    "incident_duration_hours": event.incident_duration_hours,
                },
                "ingested_at": datetime.now(UTC).isoformat(),
            }
        )

    def events_for_tenant(self, tenant_id: str) -> list[dict[str, Any]]:
        return [r for r in self.rows if r["tenant_id"] == tenant_id]
