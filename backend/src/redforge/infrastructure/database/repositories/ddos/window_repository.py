"""Observation window repository — M19.

Persists aggregated traffic snapshots. The central feed for the
baseline engine and the traffic-over-time charts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from redforge.infrastructure.database.models.ddos import DDoSObservationWindowModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyObservationWindowRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, model: DDoSObservationWindowModel) -> DDoSObservationWindowModel:
        """Idempotent upsert on (org, resource, window_start_ts).

        If the same window is computed twice (e.g. worker restart), the
        second write overwrites the first — window aggregation is
        deterministic for fixed input data, so this is safe.
        """
        stmt = (
            pg_insert(DDoSObservationWindowModel)
            .values(
                id=model.id,
                organization_id=model.organization_id,
                resource_id=model.resource_id,
                window_start_ts=model.window_start_ts,
                window_end_ts=model.window_end_ts,
                window_seconds=model.window_seconds,
                event_count=model.event_count,
                total_bytes_in=model.total_bytes_in,
                total_bytes_out=model.total_bytes_out,
                total_packets_in=model.total_packets_in,
                total_packets_out=model.total_packets_out,
                unique_src_ips=model.unique_src_ips,
                unique_dst_ports=model.unique_dst_ports,
                protocol_counts=model.protocol_counts,
                alert_count=model.alert_count,
                syn_pattern_alert_count=model.syn_pattern_alert_count,
                detection_fired=model.detection_fired,
                severity=model.severity,
                classification=model.classification,
                matched_signals=model.matched_signals,
                incident_id=model.incident_id,
                computed_at=model.computed_at,
            )
            .on_conflict_do_update(
                constraint="ux_dow_org_resource_window",
                set_={
                    "event_count": model.event_count,
                    "total_bytes_in": model.total_bytes_in,
                    "total_bytes_out": model.total_bytes_out,
                    "total_packets_in": model.total_packets_in,
                    "total_packets_out": model.total_packets_out,
                    "unique_src_ips": model.unique_src_ips,
                    "unique_dst_ports": model.unique_dst_ports,
                    "protocol_counts": model.protocol_counts,
                    "alert_count": model.alert_count,
                    "syn_pattern_alert_count": model.syn_pattern_alert_count,
                    "detection_fired": model.detection_fired,
                    "severity": model.severity,
                    "classification": model.classification,
                    "matched_signals": model.matched_signals,
                    "incident_id": model.incident_id,
                    "computed_at": model.computed_at,
                },
            )
            .returning(DDoSObservationWindowModel)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one()
        return row

    async def list_for_resource(
        self,
        organization_id: str,
        resource_id: str,
        since: datetime,
        limit: int = 500,
    ) -> list[DDoSObservationWindowModel]:
        stmt = (
            select(DDoSObservationWindowModel)
            .where(
                DDoSObservationWindowModel.organization_id == organization_id,
                DDoSObservationWindowModel.resource_id == resource_id,
                DDoSObservationWindowModel.window_start_ts >= since,
            )
            .order_by(DDoSObservationWindowModel.window_start_ts.asc())
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def list_recent_for_org(
        self,
        organization_id: str,
        since: datetime,
        limit: int = 200,
    ) -> list[DDoSObservationWindowModel]:
        stmt = (
            select(DDoSObservationWindowModel)
            .where(
                DDoSObservationWindowModel.organization_id == organization_id,
                DDoSObservationWindowModel.window_start_ts >= since,
            )
            .order_by(DDoSObservationWindowModel.window_start_ts.desc())
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def get_baseline_history(
        self,
        organization_id: str,
        resource_id: str,
        lookback_days: int = 7,
    ) -> list[dict[str, Any]]:
        """Return lightweight baseline history for p75 computation.

        Returns only the metric fields needed by compute_baseline() —
        not the full model — to keep the result set lean.
        """
        since = datetime.now(UTC) - timedelta(days=lookback_days)
        stmt = (
            select(
                DDoSObservationWindowModel.window_seconds,
                DDoSObservationWindowModel.total_bytes_in,
                DDoSObservationWindowModel.total_bytes_out,
                DDoSObservationWindowModel.total_packets_in,
                DDoSObservationWindowModel.total_packets_out,
                DDoSObservationWindowModel.event_count,
                DDoSObservationWindowModel.unique_src_ips,
            )
            .where(
                DDoSObservationWindowModel.organization_id == organization_id,
                DDoSObservationWindowModel.resource_id == resource_id,
                DDoSObservationWindowModel.window_start_ts >= since,
            )
            .order_by(DDoSObservationWindowModel.window_start_ts.asc())
            .limit(10000)
        )
        rows = (await self._session.execute(stmt)).all()
        result = []
        for r in rows:
            ws = r.window_seconds or 60
            total_bytes = (r.total_bytes_in or 0) + (r.total_bytes_out or 0)
            total_pkts = (r.total_packets_in or 0) + (r.total_packets_out or 0)
            result.append({
                "bytes_per_second": total_bytes / ws if total_bytes > 0 else None,
                "packets_per_second": total_pkts / ws if total_pkts > 0 else None,
                "flows_per_second": r.event_count / ws if r.event_count > 0 else 0.0,
                "unique_src_ips": float(r.unique_src_ips),
            })
        return result

    async def mark_window_incident(
        self,
        organization_id: str,
        resource_id: str,
        window_start_ts: datetime,
        incident_id: str,
    ) -> None:
        stmt = select(DDoSObservationWindowModel).where(
            DDoSObservationWindowModel.organization_id == organization_id,
            DDoSObservationWindowModel.resource_id == resource_id,
            DDoSObservationWindowModel.window_start_ts == window_start_ts,
        )
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        if model is not None:
            model.incident_id = incident_id
            await self._session.flush()

    async def aggregate_for_resource_window(
        self,
        organization_id: str,
        resource_id: str,
        window_start: datetime,
        window_end: datetime,
    ) -> dict[str, Any]:
        """Aggregate telemetry_events over a time window for a resource.

        This is the canonical computation: reads raw telemetry_events
        and produces the window metrics used for detection. The resource
        scope filter (scope_type/scope_value) is applied at the caller
        level via the resource model.
        """
        from sqlalchemy import distinct

        from redforge.infrastructure.database.models.telemetry import TelemetryEventModel

        # Aggregate query over telemetry_events
        agg_stmt = select(
            func.count(TelemetryEventModel.id).label("event_count"),
            func.sum(TelemetryEventModel.bytes_in).label("total_bytes_in"),
            func.sum(TelemetryEventModel.bytes_out).label("total_bytes_out"),
            func.sum(TelemetryEventModel.packets_in).label("total_packets_in"),
            func.sum(TelemetryEventModel.packets_out).label("total_packets_out"),
        ).where(
            TelemetryEventModel.organization_id == organization_id,
            TelemetryEventModel.event_ts >= window_start,
            TelemetryEventModel.event_ts < window_end,
        )
        agg_row = (await self._session.execute(agg_stmt)).one()

        # Unique source IPs
        src_stmt = select(
            func.count(distinct(TelemetryEventModel.src_ip)).label("unique_src_ips")
        ).where(
            TelemetryEventModel.organization_id == organization_id,
            TelemetryEventModel.event_ts >= window_start,
            TelemetryEventModel.event_ts < window_end,
            TelemetryEventModel.src_ip.isnot(None),
        )
        src_row = (await self._session.execute(src_stmt)).one()

        # Unique destination ports
        dst_stmt = select(
            func.count(distinct(TelemetryEventModel.dst_port)).label("unique_dst_ports")
        ).where(
            TelemetryEventModel.organization_id == organization_id,
            TelemetryEventModel.event_ts >= window_start,
            TelemetryEventModel.event_ts < window_end,
            TelemetryEventModel.dst_port.isnot(None),
        )
        dst_row = (await self._session.execute(dst_stmt)).one()

        # Protocol distribution
        proto_stmt = select(
            TelemetryEventModel.protocol,
            func.count(TelemetryEventModel.id).label("cnt"),
        ).where(
            TelemetryEventModel.organization_id == organization_id,
            TelemetryEventModel.event_ts >= window_start,
            TelemetryEventModel.event_ts < window_end,
            TelemetryEventModel.protocol.isnot(None),
        ).group_by(TelemetryEventModel.protocol)
        proto_rows = (await self._session.execute(proto_stmt)).all()
        protocol_counts = {r.protocol: r.cnt for r in proto_rows}

        # Alert count + SYN pattern alerts (Suricata alert events)
        alert_stmt = select(
            func.count(TelemetryEventModel.id).label("alert_count"),
        ).where(
            TelemetryEventModel.organization_id == organization_id,
            TelemetryEventModel.event_ts >= window_start,
            TelemetryEventModel.event_ts < window_end,
            TelemetryEventModel.event_type == "suricata_alert",
        )
        alert_row = (await self._session.execute(alert_stmt)).one()

        # SYN flood pattern signatures (case-insensitive keyword match)
        syn_stmt = select(
            func.count(TelemetryEventModel.id).label("syn_count"),
        ).where(
            TelemetryEventModel.organization_id == organization_id,
            TelemetryEventModel.event_ts >= window_start,
            TelemetryEventModel.event_ts < window_end,
            TelemetryEventModel.event_type == "suricata_alert",
            TelemetryEventModel.signature.ilike("%syn%flood%"),
        )
        syn_row = (await self._session.execute(syn_stmt)).one()

        return {
            "event_count": int(agg_row.event_count or 0),
            "total_bytes_in": int(agg_row.total_bytes_in) if agg_row.total_bytes_in else None,
            "total_bytes_out": int(agg_row.total_bytes_out) if agg_row.total_bytes_out else None,
            "total_packets_in": int(agg_row.total_packets_in) if agg_row.total_packets_in else None,
            "total_packets_out": int(agg_row.total_packets_out) if agg_row.total_packets_out else None,
            "unique_src_ips": int(src_row.unique_src_ips or 0),
            "unique_dst_ports": int(dst_row.unique_dst_ports or 0),
            "protocol_counts": protocol_counts,
            "alert_count": int(alert_row.alert_count or 0),
            "syn_pattern_alert_count": int(syn_row.syn_count or 0),
        }
