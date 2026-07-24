"""ACL adapter — maps analytics KPI data to reporting port DTOs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reporting.domain.ports.i_analytics_kpi_query_port import (
    AnalyticsKPIBundleDTO,
    AnomalySnapshotDTO,
    IAnalyticsKPIQueryPort,
    KPISnapshotDTO,
)

if TYPE_CHECKING:

    from analytics.domain.repositories.i_analytics_repositories import (
        ISecurityKPIRepository,
    )
    from reporting.domain.value_objects.identifiers import TenantId


class StaticAnalyticsKPIQueryAdapter(IAnalyticsKPIQueryPort):
    """Test/dev stub — no analytics.domain dependency."""

    def __init__(
        self,
        *,
        kpis: tuple[KPISnapshotDTO, ...] | None = None,
        anomalies: tuple[AnomalySnapshotDTO, ...] | None = None,
    ) -> None:
        self._kpis = kpis or (
            KPISnapshotDTO("MTTD", 45.0, "minutes", 2.5, "Active"),
            KPISnapshotDTO("CoveragePct", 72.0, "percent", 0.5, "Active"),
            KPISnapshotDTO("ExposureTrend", 3.2, "score", 1.0, "Active"),
            KPISnapshotDTO("CampaignSuccessRate", 40.0, "percent", 0.8, "Active"),
            KPISnapshotDTO("AIRiskTrend", 1.1, "score", 0.3, "Active"),
        )
        self._anomalies = anomalies or ()

    async def load_kpi_bundle(self, tenant_id: TenantId) -> AnalyticsKPIBundleDTO:
        del tenant_id
        return AnalyticsKPIBundleDTO(kpis=self._kpis, anomalies=self._anomalies)


class AnalyticsKPIQueryAdapter(IAnalyticsKPIQueryPort):
    """Read-only ACL over analytics repositories (imports confined to ACL)."""

    def __init__(self, kpi_repo: ISecurityKPIRepository) -> None:
        self._kpis = kpi_repo

    async def load_kpi_bundle(self, tenant_id: TenantId) -> AnalyticsKPIBundleDTO:
        from analytics.domain.value_objects.enums import KPIType

        tenant = tenant_id  # ATenantId is the identical EntityId alias; no re-wrap needed
        snapshots: list[KPISnapshotDTO] = []
        for kpi_type in KPIType:
            if kpi_type.value == "MTTR":
                continue
            kpi = await self._kpis.find_by_type(tenant, kpi_type)
            if kpi is None:
                continue
            value = kpi.latest_value
            trend = float(value) if value is not None else 0.0
            if kpi_type.value in {"CoveragePct", "CampaignSuccessRate"}:
                trend = max(0.0, 100.0 - float(value or 0.0))
            snapshots.append(
                KPISnapshotDTO(
                    kpi_type=kpi.kpi_type.value,
                    value=value,
                    unit=kpi.latest_unit,
                    trend_delta=trend,
                    status=kpi.status.value,
                )
            )
        return AnalyticsKPIBundleDTO(kpis=tuple(snapshots), anomalies=())
