"""PostgreSQL repositories for analytics.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across the other converted bounded contexts.

Method names here match analytics_application_service.py's actual calls
(find_by_signal_type, find_all, find_due_for_computation), not the
IAnalyticsDataSetRepository/... ABCs in domain/repositories/ — those ABCs
are stale (find_by_signal, list_for_tenant) and don't match what the
in-memory repositories they were supposedly specifying actually implement
either. Matched the real, in-use behavior rather than the aspirational one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from analytics.domain.aggregates.analytics_dataset import AnalyticsDataSet
from analytics.domain.aggregates.analytics_query import AnalyticsQuery
from analytics.domain.aggregates.anomaly_detection_baseline import AnomalyDetectionBaseline
from analytics.domain.aggregates.security_kpi import SecurityKPI
from analytics.domain.value_objects.enums import (
    AnomalySignalType,
    DataSetStatus,
    DetectionMethod,
    KPIStatus,
    KPIType,
    SecurityDomain,
)
from analytics.domain.value_objects.identifiers import (
    AnalyticsDataSetId,
    AnalyticsQueryId,
    AnomalyDetectionBaselineId,
    SecurityKPIId,
    TenantId,
)
from analytics.infrastructure.persistence.models.orm_models import (
    AnalyticsDataSetModel,
    AnalyticsQueryModel,
    AnomalyDetectionBaselineModel,
    SecurityKPIModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


# ── AnalyticsDataSet ─────────────────────────────────────────────────────────


def _dataset_to_row(ds: AnalyticsDataSet) -> AnalyticsDataSetModel:
    return AnalyticsDataSetModel(
        id=ds.dataset_id.value,
        tenant_id=ds.tenant_id.value,
        domain=ds.domain.value,
        schema_version=ds.schema_version,
        status=ds.status.value,
        checkpoint_event_id=ds.projection_checkpoint,
        created_at=ds.created_at,
        updated_at=ds.updated_at,
        records_ingested=ds.records_ingested,
    )


def _row_to_dataset(row: AnalyticsDataSetModel) -> AnalyticsDataSet:
    return AnalyticsDataSet(
        dataset_id=AnalyticsDataSetId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        domain=SecurityDomain(row.domain),
        schema_version=row.schema_version,
        status=DataSetStatus(row.status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        projection_checkpoint=row.checkpoint_event_id,
        records_ingested=row.records_ingested,
    )


class PgAnalyticsDataSetRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_id(
        self, tenant_id: TenantId, dataset_id: AnalyticsDataSetId
    ) -> AnalyticsDataSet | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AnalyticsDataSetModel).where(
                        AnalyticsDataSetModel.tenant_id == tenant_id.value,
                        AnalyticsDataSetModel.id == dataset_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_dataset(row) if row is not None else None

    async def find_by_domain(
        self, tenant_id: TenantId, domain: SecurityDomain
    ) -> list[AnalyticsDataSet]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(AnalyticsDataSetModel).where(
                        AnalyticsDataSetModel.tenant_id == tenant_id.value,
                        AnalyticsDataSetModel.domain == domain.value,
                    )
                )
            ).scalars().all()
            return [_row_to_dataset(r) for r in rows]

    async def find_all_active(self, tenant_id: TenantId) -> list[AnalyticsDataSet]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(AnalyticsDataSetModel).where(
                        AnalyticsDataSetModel.tenant_id == tenant_id.value,
                        AnalyticsDataSetModel.status == DataSetStatus.ACTIVE.value,
                    )
                )
            ).scalars().all()
            return [_row_to_dataset(r) for r in rows]

    async def save(self, tenant_id: TenantId, dataset: AnalyticsDataSet) -> None:
        async with self._session_factory() as session:
            await session.merge(_dataset_to_row(dataset))
            await session.commit()


# ── SecurityKPI ──────────────────────────────────────────────────────────────


def _kpi_to_row(kpi: SecurityKPI) -> SecurityKPIModel:
    return SecurityKPIModel(
        id=kpi.kpi_id.value,
        tenant_id=kpi.tenant_id.value,
        kpi_type=kpi.kpi_type.value,
        status=kpi.status.value,
        computation_schedule_cron=kpi.computation_schedule_cron,
        latest_value=kpi.latest_value,
        latest_unit=kpi.latest_unit or None,
        definition_version=kpi.definition_version,
        last_computed_at=kpi.last_computed_at,
        created_at=kpi.created_at,
    )


def _row_to_kpi(row: SecurityKPIModel) -> SecurityKPI:
    return SecurityKPI(
        kpi_id=SecurityKPIId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        kpi_type=KPIType(row.kpi_type),
        computation_schedule_cron=row.computation_schedule_cron,
        status=KPIStatus(row.status),
        definition_version=row.definition_version,
        created_at=row.created_at,
        updated_at=row.created_at,
        latest_value=row.latest_value,
        latest_unit=row.latest_unit or "",
        last_computed_at=row.last_computed_at,
    )


class PgSecurityKPIRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_id(self, tenant_id: TenantId, kpi_id: SecurityKPIId) -> SecurityKPI | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(SecurityKPIModel).where(
                        SecurityKPIModel.tenant_id == tenant_id.value,
                        SecurityKPIModel.id == kpi_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_kpi(row) if row is not None else None

    async def find_by_type(self, tenant_id: TenantId, kpi_type: KPIType) -> SecurityKPI | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(SecurityKPIModel).where(
                        SecurityKPIModel.tenant_id == tenant_id.value,
                        SecurityKPIModel.kpi_type == kpi_type.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_kpi(row) if row is not None else None

    async def find_due_for_computation(self, now: datetime) -> list[SecurityKPI]:
        del now  # in-memory repo ignores it too — matched for parity
        async with self._session_factory() as session:
            rows = (await session.execute(select(SecurityKPIModel))).scalars().all()
            return [_row_to_kpi(r) for r in rows]

    async def save(self, tenant_id: TenantId, kpi: SecurityKPI) -> None:
        async with self._session_factory() as session:
            await session.merge(_kpi_to_row(kpi))
            await session.commit()


# ── AnomalyDetectionBaseline ─────────────────────────────────────────────────


def _baseline_to_row(baseline: AnomalyDetectionBaseline) -> AnomalyDetectionBaselineModel:
    return AnomalyDetectionBaselineModel(
        id=baseline.baseline_id.value,
        tenant_id=baseline.tenant_id.value,
        signal_type=baseline.signal_type.value,
        method=baseline.method.value,
        window_days=baseline.window_days,
        bootstrapped=baseline.bootstrapped,
        observation_count=baseline.observation_count,
        params_json={
            "mean": baseline.mean,
            "std_dev": baseline.std_dev,
            "q1": baseline.q1,
            "q3": baseline.q3,
        },
        created_at=baseline.created_at,
    )


def _row_to_baseline(row: AnomalyDetectionBaselineModel) -> AnomalyDetectionBaseline:
    params = row.params_json or {}
    return AnomalyDetectionBaseline(
        baseline_id=AnomalyDetectionBaselineId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        signal_type=AnomalySignalType(row.signal_type),
        method=DetectionMethod(row.method),
        window_days=row.window_days,
        created_at=row.created_at,
        updated_at=row.created_at,
        mean=float(params.get("mean", 0.0)),
        std_dev=float(params.get("std_dev", 0.0)),
        q1=float(params.get("q1", 0.0)),
        q3=float(params.get("q3", 0.0)),
        observation_count=row.observation_count,
        bootstrapped=row.bootstrapped,
    )


class PgAnomalyDetectionBaselineRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_signal_type(
        self, tenant_id: TenantId, signal_type: AnomalySignalType
    ) -> AnomalyDetectionBaseline | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AnomalyDetectionBaselineModel).where(
                        AnomalyDetectionBaselineModel.tenant_id == tenant_id.value,
                        AnomalyDetectionBaselineModel.signal_type == signal_type.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_baseline(row) if row is not None else None

    async def save(self, tenant_id: TenantId, baseline: AnomalyDetectionBaseline) -> None:
        async with self._session_factory() as session:
            await session.merge(_baseline_to_row(baseline))
            await session.commit()


# ── AnalyticsQuery ───────────────────────────────────────────────────────────


def _query_to_row(query: AnalyticsQuery) -> AnalyticsQueryModel:
    return AnalyticsQueryModel(
        id=query.query_id.value,
        tenant_id=query.tenant_id.value,
        name=query.name,
        template=query.query_template,
        domain=query.domain.value,
        parameters_json=list(query.parameter_names),
        created_by=query.created_by,
        created_at=query.created_at,
        status="ACTIVE",
    )


def _row_to_query(row: AnalyticsQueryModel) -> AnalyticsQuery:
    return AnalyticsQuery(
        query_id=AnalyticsQueryId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        name=row.name,
        query_template=row.template,
        domain=SecurityDomain(row.domain),
        parameter_names=list(row.parameters_json or []),
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.created_at,
    )


class PgAnalyticsQueryRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_id(
        self, tenant_id: TenantId, query_id: AnalyticsQueryId
    ) -> AnalyticsQuery | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AnalyticsQueryModel).where(
                        AnalyticsQueryModel.tenant_id == tenant_id.value,
                        AnalyticsQueryModel.id == query_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_query(row) if row is not None else None

    async def find_all(self, tenant_id: TenantId) -> list[AnalyticsQuery]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(AnalyticsQueryModel).where(
                        AnalyticsQueryModel.tenant_id == tenant_id.value
                    )
                )
            ).scalars().all()
            return [_row_to_query(r) for r in rows]

    async def save(self, tenant_id: TenantId, query: AnalyticsQuery) -> None:
        async with self._session_factory() as session:
            await session.merge(_query_to_row(query))
            await session.commit()
