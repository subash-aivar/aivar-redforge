"""Postgres-backed projection read-model stores for exposure_reporting.

Same public interface as KpiProjectionStore/TrendProjectionStore
(infrastructure/projections/*.py) so DashboardQueryService and
ProjectionRebuildService work unchanged regardless of which is wired.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy import select

from exposure_reporting.domain.value_objects.identifiers import TenantId
from exposure_reporting.infrastructure.persistence.models.reporting_models import (
    ExposureKpiProjectionModel,
    ExposureTrendProjectionModel,
)
from exposure_reporting.infrastructure.projections.trend_projection_store import TrendPoint

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class PgKpiProjectionStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def upsert(self, tenant_id: TenantId, kpi: dict[str, Any], at: datetime) -> None:
        async with self._session_factory() as session:
            await session.merge(
                ExposureKpiProjectionModel(tenant_id=tenant_id, kpi_json=dict(kpi), updated_at=at)
            )
            await session.commit()

    async def get(self, tenant_id: TenantId) -> dict[str, Any] | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ExposureKpiProjectionModel).where(
                        ExposureKpiProjectionModel.tenant_id == tenant_id
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            return {**row.kpi_json, "updated_at": row.updated_at.isoformat()}

    async def clear(self, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ExposureKpiProjectionModel).where(
                        ExposureKpiProjectionModel.tenant_id == tenant_id
                    )
                )
            ).scalar_one_or_none()
            if row is not None:
                await session.delete(row)
                await session.commit()


class PgTrendProjectionStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def append(
        self,
        tenant_id: TenantId,
        *,
        tenant_exposure_score: float,
        asset_count: int,
        at: datetime,
        score_input_version: str,
    ) -> None:
        async with self._session_factory() as session:
            session.add(
                ExposureTrendProjectionModel(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    tenant_exposure_score=tenant_exposure_score,
                    asset_count=asset_count,
                    score_input_version=score_input_version,
                    computed_at=at,
                )
            )
            await session.commit()

    async def list_points(self, tenant_id: TenantId) -> list[TrendPoint]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ExposureTrendProjectionModel)
                    .where(ExposureTrendProjectionModel.tenant_id == tenant_id)
                    .order_by(ExposureTrendProjectionModel.computed_at)
                )
            ).scalars().all()
            return [
                TrendPoint(
                    computed_at=r.computed_at.isoformat(),
                    tenant_exposure_score=r.tenant_exposure_score,
                    asset_count=r.asset_count,
                    score_input_version=r.score_input_version,
                )
                for r in rows
            ]

    async def clear(self, tenant_id: TenantId) -> None:
        from sqlalchemy import delete

        async with self._session_factory() as session:
            await session.execute(
                delete(ExposureTrendProjectionModel).where(
                    ExposureTrendProjectionModel.tenant_id == tenant_id
                )
            )
            await session.commit()
