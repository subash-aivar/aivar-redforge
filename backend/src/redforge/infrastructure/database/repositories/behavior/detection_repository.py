"""Behavioral Security detection repository — M20.

Provides race-safe upsert for detections using the advisory-lock +
partial-unique-index pattern established in M19 DDoS.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from ulid import ULID

from redforge.infrastructure.database.models.behavior import (
    BehaviorDetectionEventModel,
    BehaviorDetectionModel,
    BehaviorEntityBaselineModel,
    BehaviorObservationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyBehaviorDetectionRepository:
    """PostgreSQL-backed repository for behavior detections."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def open_or_update_detection(
        self,
        organization_id: str,
        correlation_key: str,
        entity_type: str,
        entity_id: str,
        detection_type: str,
        severity: str,
        evidence: dict[str, Any],
        secondary_entity_id: str | None,
        now: datetime | None = None,
    ) -> tuple[BehaviorDetectionModel, bool]:
        """Upsert a behavioral detection.

        Uses pg_advisory_xact_lock on (org_id, correlation_key) hash to
        serialise concurrent detection attempts for the same entity.

        Returns (detection, created) where created=True on first open.
        """
        now = now or datetime.now(UTC)
        lock_hash = hash((organization_id, correlation_key)) & 0x7FFFFFFFFFFFFFFF

        await self._session.execute(
            text("SELECT pg_advisory_xact_lock(:h)"), {"h": lock_hash}
        )

        # Check for existing open detection
        result = await self._session.execute(
            select(BehaviorDetectionModel).where(
                BehaviorDetectionModel.organization_id == organization_id,
                BehaviorDetectionModel.correlation_key == correlation_key,
                BehaviorDetectionModel.status.not_in(["RESOLVED", "CLOSED"]),
            )
        )
        existing = result.scalar_one_or_none()

        if existing is not None:
            # Update: refresh evidence, severity, timestamps, increment count
            await self._session.execute(
                update(BehaviorDetectionModel)
                .where(BehaviorDetectionModel.id == existing.id)
                .values(
                    evidence=evidence,
                    severity=severity,
                    last_seen_at=now,
                    observation_count=BehaviorDetectionModel.observation_count + 1,
                    quiet_windows=0,  # reset quiet counter on re-observation
                    updated_at=now,
                    status="ACTIVE",  # promote DETECTED → ACTIVE on re-observation
                )
            )
            await self._session.refresh(existing)
            return existing, False

        # Create new detection
        detection_id = str(ULID())
        row = BehaviorDetectionModel(
            id=detection_id,
            organization_id=organization_id,
            correlation_key=correlation_key,
            entity_type=entity_type,
            entity_id=entity_id,
            detection_type=detection_type,
            status="DETECTED",
            severity=severity,
            evidence=evidence,
            secondary_entity_id=secondary_entity_id,
            detected_at=now,
            last_seen_at=now,
            quiet_windows=0,
            observation_count=1,
            notes="",
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)

        # Timeline event
        event = BehaviorDetectionEventModel(
            id=str(ULID()),
            organization_id=organization_id,
            detection_id=detection_id,
            event_type="DETECTION_OPENED",
            detail=f"Behavioral detection opened: {detection_type} on {entity_id}",
            actor_user_id=None,
            created_at=now,
        )
        self._session.add(event)

        return row, True

    async def get_detection(
        self, organization_id: str, detection_id: str
    ) -> BehaviorDetectionModel | None:
        result = await self._session.execute(
            select(BehaviorDetectionModel).where(
                BehaviorDetectionModel.id == detection_id,
                BehaviorDetectionModel.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def list_detections(
        self,
        organization_id: str,
        status: str | None = None,
        entity_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[BehaviorDetectionModel]:
        q = select(BehaviorDetectionModel).where(
            BehaviorDetectionModel.organization_id == organization_id
        )
        if status:
            q = q.where(BehaviorDetectionModel.status == status)
        if entity_id:
            q = q.where(BehaviorDetectionModel.entity_id == entity_id)
        q = q.order_by(BehaviorDetectionModel.detected_at.desc()).limit(limit).offset(offset)
        result = await self._session.execute(q)
        return list(result.scalars().all())

    async def list_open_detections(
        self,
        organization_id: str,
        limit: int = 200,
    ) -> list[BehaviorDetectionModel]:
        result = await self._session.execute(
            select(BehaviorDetectionModel).where(
                BehaviorDetectionModel.organization_id == organization_id,
                BehaviorDetectionModel.status.not_in(["RESOLVED", "CLOSED"]),
            ).order_by(BehaviorDetectionModel.detected_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def close_detection(
        self,
        organization_id: str,
        detection_id: str,
        actor_user_id: str | None = None,
        notes: str = "",
    ) -> bool:
        now = datetime.now(UTC)
        result = await self._session.execute(
            update(BehaviorDetectionModel)
            .where(
                BehaviorDetectionModel.id == detection_id,
                BehaviorDetectionModel.organization_id == organization_id,
                BehaviorDetectionModel.status.not_in(["RESOLVED", "CLOSED"]),
            )
            .values(status="CLOSED", resolved_at=now, updated_at=now, notes=notes)
            .returning(BehaviorDetectionModel.id)
        )
        changed: bool = result.fetchone() is not None
        if changed:
            self._session.add(BehaviorDetectionEventModel(
                id=str(ULID()),
                organization_id=organization_id,
                detection_id=detection_id,
                event_type="DETECTION_CLOSED",
                detail=notes or "Closed by operator",
                actor_user_id=actor_user_id,
                created_at=now,
            ))
        return changed

    async def get_detection_events(
        self, organization_id: str, detection_id: str
    ) -> list[BehaviorDetectionEventModel]:
        result = await self._session.execute(
            select(BehaviorDetectionEventModel).where(
                BehaviorDetectionEventModel.organization_id == organization_id,
                BehaviorDetectionEventModel.detection_id == detection_id,
            ).order_by(BehaviorDetectionEventModel.created_at)
        )
        return list(result.scalars().all())

    async def count_active_by_severity(
        self, organization_id: str
    ) -> dict[str, int]:
        from sqlalchemy import func

        result = await self._session.execute(
            select(
                BehaviorDetectionModel.severity,
                func.count(BehaviorDetectionModel.id),
            ).where(
                BehaviorDetectionModel.organization_id == organization_id,
                BehaviorDetectionModel.status.not_in(["RESOLVED", "CLOSED"]),
            ).group_by(BehaviorDetectionModel.severity)
        )
        return {row[0]: row[1] for row in result.all()}

    async def count_by_type(
        self, organization_id: str
    ) -> dict[str, int]:
        from sqlalchemy import func

        result = await self._session.execute(
            select(
                BehaviorDetectionModel.detection_type,
                func.count(BehaviorDetectionModel.id),
            ).where(
                BehaviorDetectionModel.organization_id == organization_id,
                BehaviorDetectionModel.status.not_in(["RESOLVED", "CLOSED"]),
            ).group_by(BehaviorDetectionModel.detection_type)
        )
        return {row[0]: row[1] for row in result.all()}


    async def list_detection_events_since(
        self,
        organization_id: str,
        since: datetime,
        limit: int = 200,
    ) -> list[BehaviorDetectionEventModel]:
        """List behavior detection timeline events for stream integration.

        Used by the operational stream to surface behavioral detections
        into the unified security operations feed (source tag "W").
        Only DETECTION_OPENED events are streamed — re-observation
        updates are internal implementation detail, not operational events.
        """
        result = await self._session.execute(
            select(BehaviorDetectionEventModel).where(
                BehaviorDetectionEventModel.organization_id == organization_id,
                BehaviorDetectionEventModel.created_at >= since,
                BehaviorDetectionEventModel.event_type == "DETECTION_OPENED",
            ).order_by(BehaviorDetectionEventModel.created_at).limit(limit)
        )
        return list(result.scalars().all())


class SqlAlchemyBehaviorBaselineRepository:
    """PostgreSQL-backed repository for entity baselines and observations."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_baseline(
        self,
        organization_id: str,
        entity_type: str,
        entity_id: str,
        baseline_confidence: str,
        window_count: int,
        p75_unique_dst_ips: float,
        p75_bytes_out: float | None,
        p75_event_count: float,
        seen_dst_ips: list[str],
        seen_service_pairs: list[list[Any]],
        seen_east_west_pairs: list[list[Any]],
        now: datetime | None = None,
    ) -> BehaviorEntityBaselineModel:
        now = now or datetime.now(UTC)

        result = await self._session.execute(
            select(BehaviorEntityBaselineModel).where(
                BehaviorEntityBaselineModel.organization_id == organization_id,
                BehaviorEntityBaselineModel.entity_type == entity_type,
                BehaviorEntityBaselineModel.entity_id == entity_id,
            )
        )
        existing = result.scalar_one_or_none()

        if existing is not None:
            await self._session.execute(
                update(BehaviorEntityBaselineModel)
                .where(BehaviorEntityBaselineModel.id == existing.id)
                .values(
                    baseline_confidence=baseline_confidence,
                    window_count=window_count,
                    p75_unique_dst_ips=p75_unique_dst_ips,
                    p75_bytes_out=p75_bytes_out,
                    p75_event_count=p75_event_count,
                    seen_dst_ips=seen_dst_ips,
                    seen_service_pairs=seen_service_pairs,
                    seen_east_west_pairs=seen_east_west_pairs,
                    updated_at=now,
                )
            )
            await self._session.refresh(existing)
            return existing

        row = BehaviorEntityBaselineModel(
            id=str(ULID()),
            organization_id=organization_id,
            entity_type=entity_type,
            entity_id=entity_id,
            baseline_confidence=baseline_confidence,
            window_count=window_count,
            p75_unique_dst_ips=p75_unique_dst_ips,
            p75_bytes_out=p75_bytes_out,
            p75_event_count=p75_event_count,
            seen_dst_ips=seen_dst_ips,
            seen_service_pairs=seen_service_pairs,
            seen_east_west_pairs=seen_east_west_pairs,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        return row

    async def get_baseline(
        self, organization_id: str, entity_type: str, entity_id: str
    ) -> BehaviorEntityBaselineModel | None:
        result = await self._session.execute(
            select(BehaviorEntityBaselineModel).where(
                BehaviorEntityBaselineModel.organization_id == organization_id,
                BehaviorEntityBaselineModel.entity_type == entity_type,
                BehaviorEntityBaselineModel.entity_id == entity_id,
            )
        )
        return result.scalar_one_or_none()

    async def upsert_observation(
        self,
        organization_id: str,
        entity_id: str,
        entity_type: str,
        window_start_ts: datetime,
        window_end_ts: datetime,
        window_seconds: int,
        event_count: int,
        unique_dst_ips: int,
        unique_dst_ports: int,
        total_bytes_out: int | None,
        total_bytes_in: int | None,
        dst_ips_seen: list[str],
        now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(UTC)

        stmt = pg_insert(BehaviorObservationModel).values(
            id=str(ULID()),
            organization_id=organization_id,
            entity_id=entity_id,
            entity_type=entity_type,
            window_start_ts=window_start_ts,
            window_end_ts=window_end_ts,
            window_seconds=window_seconds,
            event_count=event_count,
            unique_dst_ips=unique_dst_ips,
            unique_dst_ports=unique_dst_ports,
            total_bytes_out=total_bytes_out,
            total_bytes_in=total_bytes_in,
            dst_ips_seen=dst_ips_seen,
            created_at=now,
        ).on_conflict_do_nothing(
            constraint="ux_bo_org_entity_window"
        )
        await self._session.execute(stmt)

    async def get_recent_observations(
        self,
        organization_id: str,
        entity_id: str,
        limit: int = 30,
    ) -> list[BehaviorObservationModel]:
        result = await self._session.execute(
            select(BehaviorObservationModel).where(
                BehaviorObservationModel.organization_id == organization_id,
                BehaviorObservationModel.entity_id == entity_id,
            ).order_by(BehaviorObservationModel.window_start_ts.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def list_baselines(
        self,
        organization_id: str,
        limit: int = 500,
    ) -> list[BehaviorEntityBaselineModel]:
        result = await self._session.execute(
            select(BehaviorEntityBaselineModel).where(
                BehaviorEntityBaselineModel.organization_id == organization_id,
            ).order_by(BehaviorEntityBaselineModel.updated_at.desc()).limit(limit)
        )
        return list(result.scalars().all())
