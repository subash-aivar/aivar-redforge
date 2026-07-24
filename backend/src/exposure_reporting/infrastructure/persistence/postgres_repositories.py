"""PostgreSQL repositories for exposure_reporting.

Session-per-call from an injected async_sessionmaker, matching the
incident/posture_forecasting/threat_hunt pattern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from exposure_reporting.domain.aggregates.business_impact_mapping import BusinessImpactMapping
from exposure_reporting.domain.aggregates.exposure_report import ExposureReport
from exposure_reporting.domain.repositories.i_business_impact_mapping_repository import (
    IBusinessImpactMappingRepository,
)
from exposure_reporting.domain.repositories.i_exposure_report_repository import (
    IExposureReportRepository,
)
from exposure_reporting.domain.value_objects.enums import (
    BusinessCriticality,
    ImpactDomain,
    ReportStatus,
    ReportType,
)
from exposure_reporting.domain.value_objects.identifiers import (
    BusinessImpactMappingId,
    ExposureReportId,
    TenantId,
)
from exposure_reporting.infrastructure.persistence.models.reporting_models import (
    BusinessImpactMappingModel,
    ExposureReportModel,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _report_to_row(report: ExposureReport) -> ExposureReportModel:
    return ExposureReportModel(
        id=report.report_id.value,
        tenant_id=report.tenant_id.value,
        report_type=report.report_type.value,
        status=report.status.value,
        template_id=report.template_id,
        narrative=report.narrative,
        content_json=dict(report.content),
        generated_by=report.generated_by,
        generated_at=report.generated_at,
        time_range_start=report.time_range_start,
        time_range_end=report.time_range_end,
        delivered_at=report.delivered_at,
    )


def _row_to_report(row: ExposureReportModel) -> ExposureReport:
    return ExposureReport(
        report_id=ExposureReportId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        report_type=ReportType(row.report_type),
        status=ReportStatus(row.status),
        template_id=row.template_id,
        narrative=row.narrative,
        content=dict(row.content_json),
        generated_by=row.generated_by,
        generated_at=row.generated_at,
        time_range_start=row.time_range_start,
        time_range_end=row.time_range_end,
        delivered_at=row.delivered_at,
    )


class PgExposureReportRepository(IExposureReportRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get(self, tenant_id: TenantId, report_id: ExposureReportId) -> ExposureReport | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ExposureReportModel).where(
                        ExposureReportModel.tenant_id == tenant_id.value,
                        ExposureReportModel.id == report_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_report(row) if row is not None else None

    async def save(self, tenant_id: TenantId, report: ExposureReport) -> None:
        async with self._session_factory() as session:
            await session.merge(_report_to_row(report))
            await session.commit()

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        report_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ExposureReport]:
        async with self._session_factory() as session:
            stmt = select(ExposureReportModel).where(
                ExposureReportModel.tenant_id == tenant_id.value
            )
            if report_type:
                stmt = stmt.where(ExposureReportModel.report_type == report_type)
            if from_dt:
                stmt = stmt.where(ExposureReportModel.generated_at >= from_dt)
            if to_dt:
                stmt = stmt.where(ExposureReportModel.generated_at <= to_dt)
            stmt = stmt.order_by(ExposureReportModel.generated_at.desc())
            rows = (await session.execute(stmt)).scalars().all()
            return [_row_to_report(r) for r in rows]


def _mapping_to_row(mapping: BusinessImpactMapping) -> BusinessImpactMappingModel:
    return BusinessImpactMappingModel(
        id=mapping.mapping_id.value,
        tenant_id=mapping.tenant_id.value,
        asset_ref_id=mapping.asset_ref_id,
        criticality=mapping.criticality.value,
        impact_domain=mapping.impact_domain.value,
        authored_by=mapping.authored_by,
        business_process_ref=mapping.business_process_ref,
        business_unit_ref=mapping.business_unit_ref,
        financial_impact_estimate=mapping.financial_impact_estimate,
        regulatory_scope_json=list(mapping.regulatory_scope),
        created_at=mapping.created_at,
        updated_at=mapping.updated_at,
    )


def _row_to_mapping(row: BusinessImpactMappingModel) -> BusinessImpactMapping:
    return BusinessImpactMapping(
        mapping_id=BusinessImpactMappingId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        asset_ref_id=row.asset_ref_id,
        criticality=BusinessCriticality(row.criticality),
        impact_domain=ImpactDomain(row.impact_domain),
        authored_by=row.authored_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        business_process_ref=row.business_process_ref,
        business_unit_ref=row.business_unit_ref,
        financial_impact_estimate=row.financial_impact_estimate,
        regulatory_scope=list(row.regulatory_scope_json),
    )


class PgBusinessImpactMappingRepository(IBusinessImpactMappingRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get(
        self, tenant_id: TenantId, mapping_id: BusinessImpactMappingId
    ) -> BusinessImpactMapping | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(BusinessImpactMappingModel).where(
                        BusinessImpactMappingModel.tenant_id == tenant_id.value,
                        BusinessImpactMappingModel.id == mapping_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_mapping(row) if row is not None else None

    async def find_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID
    ) -> BusinessImpactMapping | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(BusinessImpactMappingModel).where(
                        BusinessImpactMappingModel.tenant_id == tenant_id.value,
                        BusinessImpactMappingModel.asset_ref_id == asset_ref_id,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_mapping(row) if row is not None else None

    async def save(self, tenant_id: TenantId, mapping: BusinessImpactMapping) -> None:
        async with self._session_factory() as session:
            await session.merge(_mapping_to_row(mapping))
            await session.commit()

    async def list_by_tenant(self, tenant_id: TenantId) -> list[BusinessImpactMapping]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(BusinessImpactMappingModel).where(
                        BusinessImpactMappingModel.tenant_id == tenant_id.value
                    )
                )
            ).scalars().all()
            return [_row_to_mapping(r) for r in rows]
