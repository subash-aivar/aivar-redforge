"""Telemetry ingestion service — M18 customer-owned telemetry.

Accepts normalized ParsedEvent objects (from Suricata/Zeek parsers),
validates sensor ownership and format consistency, and persists them
to `telemetry_events` with idempotency on source_event_id.

Operational safety guarantees:
  - Tenant isolation: sensor must belong to the caller's org
  - Batch size limited at the API layer (max 1000 records per call)
  - Malformed records already filtered by the parser layer
  - Private/internal IPs: enrichment_state='skipped' (no egress)
  - No raw payload storage — only the allowlisted normalised fields
  - No file path ingestion from API input
  - Duplicate events: idempotent upsert, returns created=False
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ulid import ULID

from redforge.infrastructure.telemetry.parsers.suricata_eve import (
    ParsedEvent as SuricataEvent,
)
from redforge.infrastructure.telemetry.parsers.zeek_json import (
    ParsedEvent as ZeekEvent,
)
from redforge.infrastructure.threat_intel.ip_classification import is_public_ip

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession


def _enrichment_state(src_ip: str | None, dst_ip: str | None) -> str:
    """'pending' if any IP is genuinely public (safe for external enrichment),
    'skipped' if all IPs are private/reserved/documentation/loopback."""
    for ip in (src_ip, dst_ip):
        if ip and is_public_ip(ip):
            return "pending"
    return "skipped"


@dataclass(slots=True)
class IngestionSummary:
    sensor_id: str
    total_submitted: int
    created: int
    duplicate: int
    error: int


class TelemetryIngestionService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def ingest_batch(
        self,
        organization_id: str,
        sensor_id: str,
        events: Sequence[SuricataEvent | ZeekEvent],
    ) -> IngestionSummary:
        from redforge.infrastructure.database.models.telemetry import TelemetryEventModel
        from redforge.infrastructure.database.repositories.telemetry_repository import (
            SqlAlchemyTelemetryEventRepository,
            SqlAlchemyTelemetrySensorRepository,
        )

        sensor_repo = SqlAlchemyTelemetrySensorRepository(self._session)
        event_repo = SqlAlchemyTelemetryEventRepository(self._session)

        sensor = await sensor_repo.get_by_id(organization_id, sensor_id)
        if sensor is None:
            raise ValueError(f"sensor {sensor_id!r} not found in org {organization_id!r}")
        if not sensor.enabled:
            raise ValueError(f"sensor {sensor_id!r} is disabled")

        now = datetime.now(UTC)
        created = 0
        duplicate = 0
        errors = 0

        for ev in events:
            state = _enrichment_state(ev.src_ip, ev.dst_ip)
            model = TelemetryEventModel(
                id=str(ULID()),
                organization_id=organization_id,
                sensor_id=sensor_id,
                source_event_id=ev.source_event_id,
                format=ev.format,
                event_type=ev.event_type,
                event_ts=ev.event_ts,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                src_port=ev.src_port,
                dst_port=ev.dst_port,
                protocol=ev.protocol,
                action=ev.action,
                severity=ev.severity,
                signature=ev.signature,
                signature_id=ev.signature_id,
                bytes_in=ev.bytes_in,
                bytes_out=ev.bytes_out,
                packets_in=ev.packets_in,
                packets_out=ev.packets_out,
                enrichment_state=state,
                ingested_at=now,
                updated_at=now,
            )
            try:
                _, was_created = await event_repo.upsert(model)
                if was_created:
                    created += 1
                else:
                    duplicate += 1
            except Exception:
                errors += 1

        return IngestionSummary(
            sensor_id=sensor_id,
            total_submitted=len(events),
            created=created,
            duplicate=duplicate,
            error=errors,
        )
