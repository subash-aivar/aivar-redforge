"""PgTelemetrySourceRepository — SQLAlchemy implementation."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select, update

from detection.domain.aggregates.telemetry_source import TelemetrySource
from detection.domain.exceptions.domain_exceptions import OptimisticLockConflict
from detection.domain.repositories.i_telemetry_source_repository import (
    ITelemetrySourceRepository,
)
from detection.domain.value_objects.enums import (
    SourceLifecycleState,
    SourceTrustLevel,
    SourceType,
)
from detection.domain.value_objects.identifiers import TelemetrySourceId, TenantId
from detection.domain.value_objects.telemetry import (
    DataLatencyProfile,
    RetentionWindow,
)
from detection.infrastructure.persistence.models.telemetry_source_model import (
    TelemetrySourceModel,
)
from detection.infrastructure.persistence.serialization import (
    connection_from_json,
    connection_to_json,
    health_from_json,
    health_to_json,
    source_schema_from_json,
    source_schema_to_json,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgTelemetrySourceRepository(ITelemetrySourceRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_model(self, source: TelemetrySource) -> TelemetrySourceModel:
        return TelemetrySourceModel(
            id=source.source_id.value,
            tenant_id=source.tenant_id.value,
            name=source.name,
            source_type=source.source_type.value,
            trust_level=source.trust_level.value,
            lifecycle_state=source.lifecycle_state.value,
            description=source.description,
            schema_version=source.schema.schema_version,
            schema_json=source_schema_to_json(source.schema),
            connection_json=connection_to_json(source.connection),
            health_status=source.health.status.value,
            health_json=health_to_json(source.health),
            latency_expected_seconds=source.latency_profile.expected_latency.total_seconds(),
            latency_max_seconds=(
                source.latency_profile.max_acceptable_latency.total_seconds()
                if source.latency_profile.max_acceptable_latency is not None
                else None
            ),
            retention_seconds=source.retention.retention.total_seconds(),
            created_at=source.created_at,
            updated_at=source.updated_at,
            row_version=source.version,
        )

    def _to_domain(self, model: TelemetrySourceModel) -> TelemetrySource:
        max_lat = (
            timedelta(seconds=model.latency_max_seconds)
            if model.latency_max_seconds is not None
            else None
        )
        return TelemetrySource(
            source_id=TelemetrySourceId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            name=model.name,
            source_type=SourceType(model.source_type),
            trust_level=SourceTrustLevel(model.trust_level),
            schema=source_schema_from_json(model.schema_json),
            connection=connection_from_json(model.connection_json),
            health=health_from_json(model.health_json),
            latency_profile=DataLatencyProfile(
                expected_latency=timedelta(seconds=model.latency_expected_seconds),
                max_acceptable_latency=max_lat,
            ),
            retention=RetentionWindow(
                retention=timedelta(seconds=model.retention_seconds)
            ),
            lifecycle_state=SourceLifecycleState(model.lifecycle_state),
            description=model.description,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
        )

    async def save(self, source: TelemetrySource) -> None:
        existing = await self._session.execute(
            select(TelemetrySourceModel).where(
                TelemetrySourceModel.id == source.source_id.value,
            )
        )
        row = existing.scalar_one_or_none()

        if row is None:
            model = self._to_model(source)
            model.row_version = 1
            self._session.add(model)
            await self._session.flush()
            source._version = 1
            return

        if row.tenant_id != source.tenant_id.value:
            raise OptimisticLockConflict(str(source.source_id))

        actual = row.row_version
        if source.version == actual + 1 or source.version == actual:
            expected_version = actual
        else:
            raise OptimisticLockConflict(str(source.source_id))

        result = await self._session.execute(
            update(TelemetrySourceModel)
            .where(
                TelemetrySourceModel.id == source.source_id.value,
                TelemetrySourceModel.tenant_id == source.tenant_id.value,
                TelemetrySourceModel.row_version == expected_version,
            )
            .values(
                name=source.name,
                source_type=source.source_type.value,
                trust_level=source.trust_level.value,
                lifecycle_state=source.lifecycle_state.value,
                description=source.description,
                schema_version=source.schema.schema_version,
                schema_json=source_schema_to_json(source.schema),
                connection_json=connection_to_json(source.connection),
                health_status=source.health.status.value,
                health_json=health_to_json(source.health),
                latency_expected_seconds=(
                    source.latency_profile.expected_latency.total_seconds()
                ),
                latency_max_seconds=(
                    source.latency_profile.max_acceptable_latency.total_seconds()
                    if source.latency_profile.max_acceptable_latency is not None
                    else None
                ),
                retention_seconds=source.retention.retention.total_seconds(),
                updated_at=source.updated_at,
                row_version=expected_version + 1,
            )
            .returning(TelemetrySourceModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            raise OptimisticLockConflict(str(source.source_id))
        source._version = int(new_version)
        await self._session.flush()

    async def find_by_id(
        self,
        source_id: TelemetrySourceId,
        tenant_id: TenantId,
    ) -> TelemetrySource | None:
        stmt = select(TelemetrySourceModel).where(
            TelemetrySourceModel.id == source_id.value,
            TelemetrySourceModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_by_name(
        self,
        name: str,
        tenant_id: TenantId,
    ) -> TelemetrySource | None:
        stmt = select(TelemetrySourceModel).where(
            TelemetrySourceModel.name == name,
            TelemetrySourceModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_active_by_tenant(
        self,
        tenant_id: TenantId,
    ) -> list[TelemetrySource]:
        stmt = select(TelemetrySourceModel).where(
            TelemetrySourceModel.tenant_id == tenant_id.value,
            TelemetrySourceModel.lifecycle_state == SourceLifecycleState.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_by_type(
        self,
        source_type: SourceType,
        tenant_id: TenantId,
    ) -> list[TelemetrySource]:
        stmt = select(TelemetrySourceModel).where(
            TelemetrySourceModel.tenant_id == tenant_id.value,
            TelemetrySourceModel.source_type == source_type.value,
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TelemetrySource]:
        stmt = (
            select(TelemetrySourceModel)
            .where(TelemetrySourceModel.tenant_id == tenant_id.value)
            .order_by(TelemetrySourceModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars().all()]
