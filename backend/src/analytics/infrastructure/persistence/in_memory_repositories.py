"""In-memory repositories for analytics aggregates."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from analytics.domain.aggregates.analytics_dataset import AnalyticsDataSet
    from analytics.domain.aggregates.analytics_query import AnalyticsQuery
    from analytics.domain.aggregates.anomaly_detection_baseline import (
        AnomalyDetectionBaseline,
    )
    from analytics.domain.aggregates.security_kpi import SecurityKPI
    from analytics.domain.value_objects.enums import AnomalySignalType, KPIType, SecurityDomain
    from analytics.domain.value_objects.identifiers import (
        AnalyticsDataSetId,
        AnalyticsQueryId,
        SecurityKPIId,
        TenantId,
    )


class InMemoryAnalyticsDataSetRepository:
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, AnalyticsDataSet]] = {}

    async def find_by_id(
        self, tenant_id: TenantId, dataset_id: AnalyticsDataSetId
    ) -> AnalyticsDataSet | None:
        return self._rows.get(str(tenant_id), {}).get(str(dataset_id))

    async def find_by_domain(
        self, tenant_id: TenantId, domain: SecurityDomain
    ) -> list[AnalyticsDataSet]:
        return [d for d in self._rows.get(str(tenant_id), {}).values() if d.domain == domain]

    async def find_all_active(self, tenant_id: TenantId) -> list[AnalyticsDataSet]:
        from analytics.domain.value_objects.enums import DataSetStatus

        return [
            d
            for d in self._rows.get(str(tenant_id), {}).values()
            if d.status == DataSetStatus.ACTIVE
        ]

    async def save(self, tenant_id: TenantId, dataset: AnalyticsDataSet) -> None:
        self._rows.setdefault(str(tenant_id), {})[str(dataset.dataset_id)] = dataset


class InMemorySecurityKPIRepository:
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, SecurityKPI]] = {}
        self._by_type: dict[str, dict[str, str]] = {}

    async def find_by_id(self, tenant_id: TenantId, kpi_id: SecurityKPIId) -> SecurityKPI | None:
        return self._rows.get(str(tenant_id), {}).get(str(kpi_id))

    async def find_by_type(self, tenant_id: TenantId, kpi_type: KPIType) -> SecurityKPI | None:
        mid = self._by_type.get(str(tenant_id), {}).get(kpi_type.value)
        if mid is None:
            return None
        return self._rows.get(str(tenant_id), {}).get(mid)

    async def find_due_for_computation(self, now: datetime) -> list[SecurityKPI]:
        del now
        # Supervisor path — return all active KPIs across tenants
        out: list[SecurityKPI] = []
        for bucket in self._rows.values():
            out.extend(bucket.values())
        return out

    async def save(self, tenant_id: TenantId, kpi: SecurityKPI) -> None:
        tid = str(tenant_id)
        self._rows.setdefault(tid, {})[str(kpi.kpi_id)] = kpi
        self._by_type.setdefault(tid, {})[kpi.kpi_type.value] = str(kpi.kpi_id)


class InMemoryAnomalyDetectionBaselineRepository:
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, AnomalyDetectionBaseline]] = {}

    async def find_by_signal_type(
        self, tenant_id: TenantId, signal_type: AnomalySignalType
    ) -> AnomalyDetectionBaseline | None:
        return self._rows.get(str(tenant_id), {}).get(signal_type.value)

    async def save(self, tenant_id: TenantId, baseline: AnomalyDetectionBaseline) -> None:
        self._rows.setdefault(str(tenant_id), {})[baseline.signal_type.value] = baseline


class InMemoryAnalyticsQueryRepository:
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, AnalyticsQuery]] = {}

    async def find_by_id(
        self, tenant_id: TenantId, query_id: AnalyticsQueryId
    ) -> AnalyticsQuery | None:
        return self._rows.get(str(tenant_id), {}).get(str(query_id))

    async def find_all(self, tenant_id: TenantId) -> list[AnalyticsQuery]:
        return list(self._rows.get(str(tenant_id), {}).values())

    async def save(self, tenant_id: TenantId, query: AnalyticsQuery) -> None:
        self._rows.setdefault(str(tenant_id), {})[str(query.query_id)] = query
