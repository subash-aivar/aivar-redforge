"""Telemetry query service — M18. Reads from telemetry_events for the
Command Center firewall/IDS wall and bandwidth/traffic panels."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(slots=True)
class SensorDTO:
    id: str
    name: str
    format: str
    description: str
    enabled: bool
    created_at: str


@dataclass(slots=True)
class TelemetryEventDTO:
    id: str
    sensor_id: str
    sensor_name: str
    source_event_id: str
    format: str
    event_type: str
    event_ts: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    action: str | None
    severity: str | None
    signature: str | None
    signature_id: str | None
    bytes_in: int | None
    bytes_out: int | None
    packets_in: int | None
    packets_out: int | None
    enrichment_state: str
    ingested_at: str


@dataclass(slots=True)
class BandwidthSummaryDTO:
    period_hours: int
    total_bytes_in: int | None
    total_bytes_out: int | None
    total_packets_in: int | None
    total_packets_out: int | None
    flow_count: int
    top_talkers: list[dict[str, object]]
    top_destination_ports: list[dict[str, object]]
    has_real_data: bool


class TelemetryQueryService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_sensors(self, organization_id: str) -> list[SensorDTO]:
        from redforge.infrastructure.database.repositories.telemetry_repository import (
            SqlAlchemyTelemetrySensorRepository,
        )

        repo = SqlAlchemyTelemetrySensorRepository(self._session)
        sensors = await repo.list_for_org(organization_id)
        return [
            SensorDTO(
                id=s.id,
                name=s.name,
                format=s.format,
                description=s.description,
                enabled=s.enabled,
                created_at=s.created_at.isoformat(),
            )
            for s in sensors
        ]

    async def list_events(
        self,
        organization_id: str,
        sensor_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TelemetryEventDTO]:
        from redforge.infrastructure.database.repositories.telemetry_repository import (
            SqlAlchemyTelemetryEventRepository,
            SqlAlchemyTelemetrySensorRepository,
        )

        sensor_repo = SqlAlchemyTelemetrySensorRepository(self._session)
        event_repo = SqlAlchemyTelemetryEventRepository(self._session)

        sensors = await sensor_repo.list_for_org(organization_id)
        sensor_map = {s.id: s.name for s in sensors}

        events = await event_repo.list_recent(
            organization_id, sensor_id=sensor_id, event_type=event_type,
            limit=limit, offset=offset
        )
        return [
            TelemetryEventDTO(
                id=e.id,
                sensor_id=e.sensor_id,
                sensor_name=sensor_map.get(e.sensor_id, "unknown"),
                source_event_id=e.source_event_id,
                format=e.format,
                event_type=e.event_type,
                event_ts=e.event_ts.isoformat(),
                src_ip=e.src_ip,
                dst_ip=e.dst_ip,
                src_port=e.src_port,
                dst_port=e.dst_port,
                protocol=e.protocol,
                action=e.action,
                severity=e.severity,
                signature=e.signature,
                signature_id=e.signature_id,
                bytes_in=e.bytes_in,
                bytes_out=e.bytes_out,
                packets_in=e.packets_in,
                packets_out=e.packets_out,
                enrichment_state=e.enrichment_state,
                ingested_at=e.ingested_at.isoformat(),
            )
            for e in events
        ]

    async def get_bandwidth_summary(
        self,
        organization_id: str,
        period_hours: int = 24,
    ) -> BandwidthSummaryDTO:
        from redforge.infrastructure.database.repositories.telemetry_repository import (
            SqlAlchemyTelemetryEventRepository,
        )

        repo = SqlAlchemyTelemetryEventRepository(self._session)
        since = datetime.now(UTC) - timedelta(hours=period_hours)

        summary = await repo.bandwidth_summary(organization_id, since)
        talkers = await repo.top_talkers(organization_id, since)
        top_ports = await repo.top_destination_ports(organization_id, since)

        return BandwidthSummaryDTO(
            period_hours=period_hours,
            total_bytes_in=summary["total_bytes_in"],
            total_bytes_out=summary["total_bytes_out"],
            total_packets_in=summary["total_packets_in"],
            total_packets_out=summary["total_packets_out"],
            flow_count=int(summary["flow_count"] or 0),
            top_talkers=talkers,
            top_destination_ports=top_ports,
            has_real_data=bool(summary["flow_count"]),
        )
