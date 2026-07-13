"""PostgreSQL CheckpointRepository and ReadModelRepository — Sprint 25.

Implements both CheckpointRepository and ProjectionRepository protocols.

Checkpoints are UPSERTED (INSERT OR REPLACE) on projection_id primary key.
Checkpoints are the only platform persistence that is written on every event —
high write frequency. The table is small (one row per projection) and
the PK index makes all writes O(log n) on projection count.

ReadModels use the same UPSERT pattern on (model_type, organization_id) PK.
ReadModel data is stored as a JSONB dict. Serialisation is caller-supplied
via the `serializer` callable (defaults to dataclasses.asdict-style conversion).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.platform.value_objects import (
    ProjectionCheckpoint,
    ProjectionState,
    RetentionPolicy,
)
from redforge.infrastructure.platform.models import (
    PlatformCheckpointModel,
    PlatformReadModelModel,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _model_to_checkpoint(row: PlatformCheckpointModel) -> ProjectionCheckpoint:
    state = ProjectionState(row.state) if row.state in ProjectionState._value2member_map_ \
        else ProjectionState.LIVE
    return ProjectionCheckpoint(
        projection_id=row.projection_id,
        projection_name=row.projection_name,
        last_global_position=row.last_global_position,
        last_processed_at=(
            row.last_processed_at.replace(tzinfo=UTC)
            if row.last_processed_at.tzinfo is None
            else row.last_processed_at
        ),
        state=state,
        error_message=row.error_message,
        events_processed=row.events_processed,
    )


# ── PostgreSQL CheckpointRepository ───────────────────────────────────────


class PostgreSQLCheckpointRepository:
    """Durable checkpoint storage using PostgreSQL UPSERT.

    All writes are UPSERT on projection_id PK. High write frequency is
    handled efficiently by the PK index and minimal row size.

    Session lifecycle: injected, never owned here.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, checkpoint: ProjectionCheckpoint) -> None:
        now = _utc_now()
        stmt = pg_insert(PlatformCheckpointModel).values(
            projection_id=checkpoint.projection_id,
            projection_name=checkpoint.projection_name,
            last_global_position=checkpoint.last_global_position,
            last_processed_at=checkpoint.last_processed_at,
            state=str(checkpoint.state),
            error_message=checkpoint.error_message,
            events_processed=checkpoint.events_processed,
            updated_at=now,
        ).on_conflict_do_update(
            index_elements=["projection_id"],
            set_={
                "projection_name": checkpoint.projection_name,
                "last_global_position": checkpoint.last_global_position,
                "last_processed_at": checkpoint.last_processed_at,
                "state": str(checkpoint.state),
                "error_message": checkpoint.error_message,
                "events_processed": checkpoint.events_processed,
                "updated_at": now,
            },
        )
        await self._session.execute(stmt)
        await self._session.flush()

    async def load(self, projection_id: str) -> ProjectionCheckpoint | None:
        result = await self._session.execute(
            select(PlatformCheckpointModel).where(
                PlatformCheckpointModel.projection_id == projection_id
            )
        )
        row = result.scalars().first()
        return _model_to_checkpoint(row) if row is not None else None

    async def delete(self, projection_id: str) -> None:
        row = await self._session.get(PlatformCheckpointModel, projection_id)
        if row is not None:
            await self._session.delete(row)
            await self._session.flush()

    async def apply_retention(self, policy: RetentionPolicy) -> int:
        # Checkpoints are not subject to retention (they are operational state,
        # not data). Return 0 to satisfy the protocol.
        return 0

    # Aliases for ProjectionRepository protocol compatibility
    async def save_checkpoint(self, checkpoint: ProjectionCheckpoint) -> None:
        await self.save(checkpoint)

    async def load_checkpoint(self, projection_id: str) -> ProjectionCheckpoint | None:
        return await self.load(projection_id)

    async def list_checkpoints(
        self, organization_id: str
    ) -> Sequence[ProjectionCheckpoint]:
        result = await self._session.execute(
            select(PlatformCheckpointModel).order_by(
                PlatformCheckpointModel.projection_id
            )
        )
        return [_model_to_checkpoint(r) for r in result.scalars().all()]


# ── PostgreSQL ReadModelRepository ────────────────────────────────────────


class PostgreSQLReadModelRepository:
    """Durable read model storage using PostgreSQL UPSERT.

    Stores any ReadModel subclass as a JSONB dict. Serialisation is
    provided by the caller (typically dataclasses.asdict or a custom mapper).

    One row per (model_type, organization_id) — this is the composite PK.
    """

    def __init__(
        self,
        session: AsyncSession,
        serializer: Any | None = None,
        deserializer: Any | None = None,
    ) -> None:
        self._session = session
        self._serializer = serializer or _default_serialize
        self._deserializer = deserializer or _default_deserialize

    async def save(self, model: Any) -> None:
        now = _utc_now()
        data: dict[str, Any] = self._serializer(model)
        stmt = pg_insert(PlatformReadModelModel).values(
            model_type=model.model_type,
            organization_id=model.organization_id,
            data=data,
            last_updated_at=now,
            last_event_position=model.last_event_position,
        ).on_conflict_do_update(
            index_elements=["model_type", "organization_id"],
            set_={
                "data": data,
                "last_updated_at": now,
                "last_event_position": model.last_event_position,
            },
        )
        await self._session.execute(stmt)
        await self._session.flush()

    async def load(self, model_type: str, organization_id: str) -> Any | None:
        result = await self._session.execute(
            select(PlatformReadModelModel).where(
                PlatformReadModelModel.model_type == model_type,
                PlatformReadModelModel.organization_id == organization_id,
            )
        )
        row = result.scalars().first()
        if row is None:
            return None
        return self._deserializer(dict(row.data))

    async def list_types(self, organization_id: str) -> Sequence[str]:
        result = await self._session.execute(
            select(PlatformReadModelModel.model_type).where(
                PlatformReadModelModel.organization_id == organization_id
            ).order_by(PlatformReadModelModel.model_type)
        )
        return [row[0] for row in result.all()]


# ── Default serialisation ──────────────────────────────────────────────────


def _default_serialize(model: Any) -> dict[str, Any]:
    """Convert a ReadModel to a JSON-safe dict via __dict__ or dataclass fields."""
    import dataclasses
    if dataclasses.is_dataclass(model) and not isinstance(model, type):
        return dataclasses.asdict(model)
    return dict(vars(model))


def _default_deserialize(data: dict[str, Any]) -> dict[str, Any]:
    """Identity: return raw dict. Callers provide typed deserializers."""
    return data
