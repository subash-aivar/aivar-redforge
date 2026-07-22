"""Projection rebuild / repair / read-side sync (Phase 5)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from exposure_reporting.application._auth import require_at_least
from exposure_reporting.domain.services.narrative_template_service import (
    compute_dominant_amplifier,
)
from exposure_reporting.domain.value_objects.enums import ReportingRole
from exposure_reporting.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID

    from exposure_reporting.application.ports.i_exposure_data_query_port import (
        IExposureDataQueryPort,
    )
    from exposure_reporting.domain.ports.i_security_graph_write_port import (
        ISecurityGraphWritePort,
    )
    from exposure_reporting.domain.repositories.i_business_impact_mapping_repository import (
        IBusinessImpactMappingRepository,
    )
    from exposure_reporting.domain.repositories.i_exposure_report_repository import (
        IExposureReportRepository,
    )
    from exposure_reporting.infrastructure.projections.kpi_projection_store import (
        IKpiProjectionStore,
    )
    from exposure_reporting.infrastructure.projections.trend_projection_store import (
        ITrendProjectionStore,
    )


class ProjectionRebuildService:
    def __init__(
        self,
        exposure_port: IExposureDataQueryPort,
        mapping_repo: IBusinessImpactMappingRepository,
        report_repo: IExposureReportRepository,
        kpi_store: IKpiProjectionStore,
        trend_store: ITrendProjectionStore,
        graph_port: ISecurityGraphWritePort,
    ) -> None:
        self._exposure = exposure_port
        self._mappings = mapping_repo
        self._reports = report_repo
        self._kpi = kpi_store
        self._trends = trend_store
        self._graph = graph_port

    async def rebuild_read_models(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> dict[str, object]:
        require_at_least(actor_roles, ReportingRole.ADMIN)
        now = datetime.now(UTC)
        snap = await self._exposure.load_snapshot(tenant_id)
        asset_count = len(snap.asset_scores)
        tenant_score = sum(snap.asset_scores.values()) / asset_count if asset_count else 0.0
        dominant = compute_dominant_amplifier(dict(snap.amplifier_weight_prevalence))
        kpi = {
            "tenant_exposure_score": tenant_score,
            "asset_count": asset_count,
            "dominant_amplifier": dominant,
            "score_input_version": snap.score_input_version,
            "rebuilt_at": now.isoformat(),
        }
        await self._kpi.upsert(tenant_id, kpi, now)
        await self._trends.append(
            tenant_id,
            tenant_exposure_score=tenant_score,
            asset_count=asset_count,
            at=now,
            score_input_version=str(snap.score_input_version),
        )
        return {"ok": True, "kpi": kpi}

    async def repair_projections(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> dict[str, object]:
        """Repair: clear KPI then rebuild from live exposure data."""
        require_at_least(actor_roles, ReportingRole.ADMIN)
        await self._kpi.clear(tenant_id)
        result = await self.rebuild_read_models(tenant_id, actor_roles)
        return {"ok": True, "repaired": True, **result}

    async def sync_graph_from_reports(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> dict[str, object]:
        require_at_least(actor_roles, ReportingRole.ADMIN)
        reports = await self._reports.list_by_tenant(TenantId(tenant_id))
        upserted = 0
        for report in reports:
            await self._graph.upsert_exposure_node(
                tenant_id=str(tenant_id),
                node_type="ExposureReport",
                node_key=str(report.report_id),
                properties={
                    "report_type": report.report_type.value,
                    "template_id": report.template_id,
                    "status": report.status.value,
                },
                event_id=f"rebuild-{report.report_id}",
            )
            upserted += 1
        return {"ok": True, "nodes_upserted": upserted}
