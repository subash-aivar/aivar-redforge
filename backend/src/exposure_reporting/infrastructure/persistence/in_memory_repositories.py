"""In-memory repositories for exposure_reporting."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure_reporting.domain.repositories.i_business_impact_mapping_repository import (
    IBusinessImpactMappingRepository,
)
from exposure_reporting.domain.repositories.i_exposure_report_repository import (
    IExposureReportRepository,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from exposure_reporting.domain.aggregates.business_impact_mapping import (
        BusinessImpactMapping,
    )
    from exposure_reporting.domain.aggregates.exposure_report import ExposureReport
    from exposure_reporting.domain.value_objects.identifiers import (
        BusinessImpactMappingId,
        ExposureReportId,
        TenantId,
    )


class InMemoryExposureReportRepository(IExposureReportRepository):
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, ExposureReport]] = {}

    async def get(self, tenant_id: TenantId, report_id: ExposureReportId) -> ExposureReport | None:
        return self._rows.get(str(tenant_id), {}).get(str(report_id))

    async def save(self, tenant_id: TenantId, report: ExposureReport) -> None:
        self._rows.setdefault(str(tenant_id), {})[str(report.report_id)] = report

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        report_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ExposureReport]:
        rows = list(self._rows.get(str(tenant_id), {}).values())
        if report_type:
            rows = [r for r in rows if r.report_type.value == report_type]
        if from_dt:
            rows = [r for r in rows if r.generated_at >= from_dt]
        if to_dt:
            rows = [r for r in rows if r.generated_at <= to_dt]
        return sorted(rows, key=lambda r: r.generated_at, reverse=True)


class InMemoryBusinessImpactMappingRepository(IBusinessImpactMappingRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, dict[str, BusinessImpactMapping]] = {}
        self._by_asset: dict[str, dict[str, str]] = {}

    async def get(
        self, tenant_id: TenantId, mapping_id: BusinessImpactMappingId
    ) -> BusinessImpactMapping | None:
        return self._by_id.get(str(tenant_id), {}).get(str(mapping_id))

    async def find_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID
    ) -> BusinessImpactMapping | None:
        mid = self._by_asset.get(str(tenant_id), {}).get(str(asset_ref_id))
        if mid is None:
            return None
        return self._by_id.get(str(tenant_id), {}).get(mid)

    async def save(self, tenant_id: TenantId, mapping: BusinessImpactMapping) -> None:
        tid = str(tenant_id)
        self._by_id.setdefault(tid, {})[str(mapping.mapping_id)] = mapping
        self._by_asset.setdefault(tid, {})[str(mapping.asset_ref_id)] = str(mapping.mapping_id)

    async def list_by_tenant(self, tenant_id: TenantId) -> list[BusinessImpactMapping]:
        return list(self._by_id.get(str(tenant_id), {}).values())
