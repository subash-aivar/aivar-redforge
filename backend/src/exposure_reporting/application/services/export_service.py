"""Export services for exposure reports (Phase 5)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from exposure_reporting.application._auth import require_at_least
from exposure_reporting.application.exceptions import ApplicationNotFoundError
from exposure_reporting.domain.value_objects.enums import ReportingRole
from exposure_reporting.domain.value_objects.identifiers import (
    ExposureReportId,
    TenantId,
)

if TYPE_CHECKING:
    from uuid import UUID

    from exposure_reporting.domain.repositories.i_exposure_report_repository import (
        IExposureReportRepository,
    )


class ReportExportService:
    def __init__(self, report_repo: IExposureReportRepository) -> None:
        self._reports = report_repo

    async def export_json(
        self, tenant_id: UUID, report_id: UUID, actor_roles: tuple[str, ...]
    ) -> str:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        report = await self._reports.get(TenantId(tenant_id), ExposureReportId(report_id))
        if report is None:
            raise ApplicationNotFoundError(str(report_id))
        payload = {
            "report_id": str(report.report_id),
            "tenant_id": str(report.tenant_id),
            "report_type": report.report_type.value,
            "template_id": report.template_id,
            "narrative": report.narrative,
            "content": report.content,
            "generated_at": report.generated_at.isoformat(),
            "generated_by": report.generated_by,
            "status": report.status.value,
        }
        return json.dumps(payload, sort_keys=True, indent=2)

    async def export_markdown(
        self, tenant_id: UUID, report_id: UUID, actor_roles: tuple[str, ...]
    ) -> str:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        report = await self._reports.get(TenantId(tenant_id), ExposureReportId(report_id))
        if report is None:
            raise ApplicationNotFoundError(str(report_id))
        lines = [
            f"# {report.report_type.value}",
            "",
            f"**Template:** {report.template_id}",
            f"**Generated:** {report.generated_at.isoformat()}",
            f"**By:** {report.generated_by}",
            "",
            "## Narrative",
            "",
            report.narrative,
            "",
            "## Content",
            "",
            "```json",
            json.dumps(report.content, sort_keys=True, indent=2),
            "```",
        ]
        return "\n".join(lines)
