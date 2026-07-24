"""Dashboard, KPI, and trend query services (Phase 5 read side)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from exposure_reporting.application._auth import require_at_least
from exposure_reporting.application.dtos.reporting_dtos import (
    DashboardDTO,
    TrendDTO,
    TrendPointDTO,
)
from exposure_reporting.domain.services.narrative_template_service import (
    compute_dominant_amplifier,
)
from exposure_reporting.domain.value_objects.enums import ReportingRole
from exposure_reporting.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:

    from exposure_reporting.application.ports.i_exposure_data_query_port import (
        IExposureDataQueryPort,
    )
    from exposure_reporting.domain.repositories.i_business_impact_mapping_repository import (
        IBusinessImpactMappingRepository,
    )
    from exposure_reporting.infrastructure.projections.kpi_projection_store import (
        IKpiProjectionStore,
    )
    from exposure_reporting.infrastructure.projections.trend_projection_store import (
        ITrendProjectionStore,
    )


class DashboardQueryService:
    def __init__(
        self,
        exposure_port: IExposureDataQueryPort,
        mapping_repo: IBusinessImpactMappingRepository,
        kpi_store: IKpiProjectionStore,
        trend_store: ITrendProjectionStore,
    ) -> None:
        self._exposure = exposure_port
        self._mappings = mapping_repo
        self._kpi = kpi_store
        self._trends = trend_store

    async def get_dashboard(self, tenant_id: TenantId, actor_roles: tuple[str, ...]) -> DashboardDTO:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        now = datetime.now(UTC)
        snap = await self._exposure.load_snapshot(tenant_id)
        mappings = await self._mappings.list_by_tenant(tenant_id)
        mapped_ids = {str(m.asset_ref_id) for m in mappings}
        asset_count = len(snap.asset_scores)
        tenant_score = sum(snap.asset_scores.values()) / asset_count if asset_count else 0.0
        dominant = compute_dominant_amplifier(dict(snap.amplifier_weight_prevalence))
        top = sorted(snap.asset_scores.items(), key=lambda kv: kv[1], reverse=True)[:20]
        kpi = {
            "tenant_exposure_score": tenant_score,
            "asset_count": asset_count,
            "mapped_ratio": (len(mapped_ids) / asset_count) if asset_count else 0.0,
            "dominant_amplifier": dominant,
            "score_input_version": snap.score_input_version,
        }
        await self._kpi.upsert(tenant_id, kpi, now)
        await self._trends.append(
            tenant_id,
            tenant_exposure_score=tenant_score,
            asset_count=asset_count,
            at=now,
            score_input_version=str(snap.score_input_version),
        )
        return DashboardDTO(
            tenant_id=str(tenant_id),
            tenant_exposure_score=tenant_score,
            asset_count=asset_count,
            mapped_asset_count=len(mapped_ids),
            unmapped_asset_count=max(0, asset_count - len(mapped_ids)),
            dominant_amplifier=dominant,
            kpi=kpi,
            top_assets=[
                {
                    "asset_ref_id": aid,
                    "exposure_score": score,
                    "business_criticality": next(
                        (m.criticality.value for m in mappings if str(m.asset_ref_id) == aid),
                        None,
                    ),
                    "business_impact_mapped": aid in mapped_ids,
                }
                for aid, score in top
            ],
            business_impact_mapped=bool(mapped_ids),
            data_freshness_warning=snap.threat_cache_stale,
            generated_at=now.isoformat(),
        )

    async def get_trends(self, tenant_id: TenantId, actor_roles: tuple[str, ...]) -> TrendDTO:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        points = await self._trends.list_points(tenant_id)
        version = points[-1].score_input_version if points else "0"
        return TrendDTO(
            tenant_id=str(tenant_id),
            points=[
                TrendPointDTO(
                    computed_at=p.computed_at,
                    tenant_exposure_score=p.tenant_exposure_score,
                    asset_count=p.asset_count,
                )
                for p in points
            ],
            score_input_version=version,
        )

    async def get_kpis(self, tenant_id: TenantId, actor_roles: tuple[str, ...]) -> dict[str, object]:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        row = await self._kpi.get(tenant_id)
        if row is None:
            dash = await self.get_dashboard(tenant_id, actor_roles)
            return dict(dash.kpi)
        return dict(row)
