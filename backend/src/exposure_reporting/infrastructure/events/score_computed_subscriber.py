"""Event subscriber — synchronize KPI/trend when exposure scores compute."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure_reporting.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:

    from exposure_reporting.application.services.dashboard_query_service import (
        DashboardQueryService,
    )


class ExposureScoreComputedSubscriber:
    """Read-side sync: refresh dashboard projections after score computation."""

    def __init__(self, dashboard: DashboardQueryService) -> None:
        self._dashboard = dashboard

    async def on_exposure_score_computed(
        self, *, tenant_id: TenantId, actor_roles: tuple[str, ...] = ("exposure:admin",)
    ) -> dict[str, object]:
        dash = await self._dashboard.get_dashboard(tenant_id, actor_roles)
        return {
            "ok": True,
            "tenant_exposure_score": dash.tenant_exposure_score,
            "asset_count": dash.asset_count,
        }
