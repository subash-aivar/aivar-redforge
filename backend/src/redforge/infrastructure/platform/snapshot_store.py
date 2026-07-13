"""PostgreSQL SnapshotStore implementation — Sprint 25.

Implements the SnapshotStore protocol from application/platform/contracts.py.

Snapshots are immutable once written — no updates, no deletes.
Latest snapshot selection uses MAX(global_position_at_snapshot) per
(aggregate_type, aggregate_id, organization_id).

Multi-tenancy: all queries filter by organization_id.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.platform.events import EventSnapshot
from redforge.domain.platform.value_objects import EventVersion
from redforge.infrastructure.platform.models import PlatformSnapshotModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _model_to_snapshot(row: PlatformSnapshotModel) -> EventSnapshot:
    sv = EventVersion.from_string(row.schema_version) if row.schema_version else EventVersion.v1()
    return EventSnapshot(
        snapshot_id=row.snapshot_id,
        aggregate_type=row.aggregate_type,
        aggregate_id=row.aggregate_id,
        organization_id=row.organization_id,
        state=dict(row.state),
        stream_version_at_snapshot=row.stream_version_at_snapshot,
        global_position_at_snapshot=row.global_position_at_snapshot,
        created_at=(
            row.created_at.replace(tzinfo=UTC)
            if row.created_at.tzinfo is None
            else row.created_at
        ),
        schema_version=sv,
    )


class PostgreSQLSnapshotStore:
    """PostgreSQL-backed SnapshotStore.

    Snapshots are append-only. The latest is selected on read.
    Injected session participates in the caller's transaction.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_snapshot(self, snapshot: EventSnapshot) -> None:
        state: dict[str, Any] = (
            dict(snapshot.state) if isinstance(snapshot.state, dict) else {}
        )
        model = PlatformSnapshotModel(
            snapshot_id=snapshot.snapshot_id,
            aggregate_type=snapshot.aggregate_type,
            aggregate_id=snapshot.aggregate_id,
            organization_id=snapshot.organization_id,
            state=state,
            stream_version_at_snapshot=snapshot.stream_version_at_snapshot,
            global_position_at_snapshot=snapshot.global_position_at_snapshot,
            schema_version=str(snapshot.schema_version),
            created_at=snapshot.created_at,
        )
        self._session.add(model)
        await self._session.flush()

    async def load_latest_snapshot(
        self,
        aggregate_type: str,
        aggregate_id: str,
        organization_id: str,
    ) -> EventSnapshot | None:
        # Select the row with MAX(global_position_at_snapshot) for this aggregate.
        subq = (
            select(func.max(PlatformSnapshotModel.global_position_at_snapshot))
            .where(
                PlatformSnapshotModel.aggregate_type == aggregate_type,
                PlatformSnapshotModel.aggregate_id == aggregate_id,
                PlatformSnapshotModel.organization_id == organization_id,
            )
            .scalar_subquery()
        )
        stmt = select(PlatformSnapshotModel).where(
            PlatformSnapshotModel.aggregate_type == aggregate_type,
            PlatformSnapshotModel.aggregate_id == aggregate_id,
            PlatformSnapshotModel.organization_id == organization_id,
            PlatformSnapshotModel.global_position_at_snapshot == subq,
        )
        result = await self._session.execute(stmt)
        row = result.scalars().first()
        return _model_to_snapshot(row) if row is not None else None

    async def list_snapshots(
        self,
        aggregate_type: str,
        organization_id: str,
    ) -> Sequence[EventSnapshot]:
        stmt = (
            select(PlatformSnapshotModel)
            .where(
                PlatformSnapshotModel.aggregate_type == aggregate_type,
                PlatformSnapshotModel.organization_id == organization_id,
            )
            .order_by(PlatformSnapshotModel.global_position_at_snapshot)
        )
        result = await self._session.execute(stmt)
        return [_model_to_snapshot(r) for r in result.scalars().all()]
