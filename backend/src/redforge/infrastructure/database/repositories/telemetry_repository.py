"""Repositories for the Telemetry Ingestion bounded context — M18."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.telemetry import (
    TelemetryEventModel,
    TelemetrySensorModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyTelemetrySensorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, organization_id: str, sensor_id: str) -> TelemetrySensorModel | None:
        stmt = select(TelemetrySensorModel).where(
            TelemetrySensorModel.organization_id == organization_id,
            TelemetrySensorModel.id == sensor_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_name(
        self, organization_id: str, name: str
    ) -> TelemetrySensorModel | None:
        stmt = select(TelemetrySensorModel).where(
            TelemetrySensorModel.organization_id == organization_id,
            TelemetrySensorModel.name == name,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_org(self, organization_id: str) -> list[TelemetrySensorModel]:
        stmt = (
            select(TelemetrySensorModel)
            .where(TelemetrySensorModel.organization_id == organization_id)
            .order_by(TelemetrySensorModel.created_at.asc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, model: TelemetrySensorModel) -> TelemetrySensorModel:
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
            return model
        except IntegrityError:
            existing = await self.get_by_name(model.organization_id, model.name)
            if existing is None:
                raise
            return existing

    async def delete(self, organization_id: str, sensor_id: str) -> bool:
        model = await self.get_by_id(organization_id, sensor_id)
        if model is None:
            return False
        await self._session.delete(model)
        await self._session.flush()
        return True


class SqlAlchemyTelemetryEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_dedup_key(
        self,
        organization_id: str,
        sensor_id: str,
        source_event_id: str,
    ) -> TelemetryEventModel | None:
        stmt = select(TelemetryEventModel).where(
            TelemetryEventModel.organization_id == organization_id,
            TelemetryEventModel.sensor_id == sensor_id,
            TelemetryEventModel.source_event_id == source_event_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def upsert(self, model: TelemetryEventModel) -> tuple[TelemetryEventModel, bool]:
        """Idempotent upsert on (org, sensor, source_event_id). Returns
        (model, created) where created=False if it already existed."""
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
            return model, True
        except IntegrityError:
            existing = await self.get_by_dedup_key(
                model.organization_id, model.sensor_id, model.source_event_id
            )
            if existing is None:
                raise
            # Update mutable fields on re-ingestion
            existing.updated_at = model.updated_at
            await self._session.flush()
            return existing, False

    async def list_recent(
        self,
        organization_id: str,
        sensor_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TelemetryEventModel]:
        stmt = select(TelemetryEventModel).where(
            TelemetryEventModel.organization_id == organization_id,
        )
        if sensor_id:
            stmt = stmt.where(TelemetryEventModel.sensor_id == sensor_id)
        if event_type:
            stmt = stmt.where(TelemetryEventModel.event_type == event_type)
        stmt = stmt.order_by(TelemetryEventModel.event_ts.desc()).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def bandwidth_summary(
        self,
        organization_id: str,
        since: datetime,
    ) -> dict[str, int | None]:
        """Aggregate byte/packet totals from events with real traffic data."""
        stmt = (
            select(
                func.sum(TelemetryEventModel.bytes_in).label("total_bytes_in"),
                func.sum(TelemetryEventModel.bytes_out).label("total_bytes_out"),
                func.sum(TelemetryEventModel.packets_in).label("total_packets_in"),
                func.sum(TelemetryEventModel.packets_out).label("total_packets_out"),
                func.count(TelemetryEventModel.id).label("flow_count"),
            )
            .where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.event_ts >= since,
                TelemetryEventModel.bytes_in.isnot(None),
            )
        )
        result = await self._session.execute(stmt)
        row = result.one()
        return {
            "total_bytes_in": row.total_bytes_in,
            "total_bytes_out": row.total_bytes_out,
            "total_packets_in": row.total_packets_in,
            "total_packets_out": row.total_packets_out,
            "flow_count": row.flow_count,
        }

    async def top_talkers(
        self,
        organization_id: str,
        since: datetime,
        limit: int = 10,
    ) -> list[dict[str, object]]:
        """Top source IPs by total bytes sent, for events with real traffic data."""
        stmt = (
            select(
                TelemetryEventModel.src_ip,
                func.sum(TelemetryEventModel.bytes_out).label("bytes_sent"),
                func.count(TelemetryEventModel.id).label("flow_count"),
            )
            .where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.event_ts >= since,
                TelemetryEventModel.src_ip.isnot(None),
                TelemetryEventModel.bytes_out.isnot(None),
            )
            .group_by(TelemetryEventModel.src_ip)
            .order_by(func.sum(TelemetryEventModel.bytes_out).desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [
            {"src_ip": r.src_ip, "bytes_sent": r.bytes_sent, "flow_count": r.flow_count}
            for r in result.all()
        ]

    async def top_destination_ports(
        self,
        organization_id: str,
        since: datetime,
        limit: int = 10,
    ) -> list[dict[str, object]]:
        stmt = (
            select(
                TelemetryEventModel.dst_port,
                TelemetryEventModel.protocol,
                func.count(TelemetryEventModel.id).label("event_count"),
            )
            .where(
                TelemetryEventModel.organization_id == organization_id,
                TelemetryEventModel.event_ts >= since,
                TelemetryEventModel.dst_port.isnot(None),
            )
            .group_by(TelemetryEventModel.dst_port, TelemetryEventModel.protocol)
            .order_by(func.count(TelemetryEventModel.id).desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [
            {"dst_port": r.dst_port, "protocol": r.protocol, "event_count": r.event_count}
            for r in result.all()
        ]
