"""Background workers for reporting projections and scheduled reports."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from exposure_reporting.application.commands.reporting_commands import (
        GenerateExposureReportCommand,
    )
    from exposure_reporting.application.dtos.reporting_dtos import ExposureReportDTO
    from exposure_reporting.application.services.dashboard_query_service import (
        DashboardQueryService,
    )
    from exposure_reporting.application.services.exposure_report_generation_service import (
        ExposureReportGenerationService,
    )
    from exposure_reporting.application.services.projection_rebuild_service import (
        ProjectionRebuildService,
    )


class ReportingBackgroundWorker:
    def __init__(
        self,
        report_service: ExposureReportGenerationService,
        dashboard: DashboardQueryService,
        projections: ProjectionRebuildService,
    ) -> None:
        self._reports = report_service
        self._dashboard = dashboard
        self._projections = projections

    async def generate_report_async(self, cmd: GenerateExposureReportCommand) -> ExposureReportDTO:
        return await self._reports.generate(cmd)

    async def refresh_dashboard(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> dict[str, object]:
        dash = await self._dashboard.get_dashboard(tenant_id, actor_roles)
        return {
            "tenant_exposure_score": dash.tenant_exposure_score,
            "asset_count": dash.asset_count,
            "generated_at": dash.generated_at,
        }

    async def rebuild_projections(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> dict[str, object]:
        return await self._projections.rebuild_read_models(tenant_id, actor_roles)
