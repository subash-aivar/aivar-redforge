"""Repository interfaces for analytics BC — all tenant-scoped methods require tenant_id."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analytics.domain.aggregates.analytics_dataset import AnalyticsDataSet
    from analytics.domain.aggregates.analytics_query import AnalyticsQuery
    from analytics.domain.aggregates.anomaly_detection_baseline import (
        AnomalyDetectionBaseline,
    )
    from analytics.domain.aggregates.security_kpi import SecurityKPI
    from analytics.domain.value_objects.enums import KPIType, SecurityDomain
    from analytics.domain.value_objects.identifiers import (
        AnalyticsDataSetId,
        AnalyticsQueryId,
        AnomalyDetectionBaselineId,
        SecurityKPIId,
        TenantId,
    )


class IAnalyticsDataSetRepository(ABC):
    @abstractmethod
    async def save(self, tenant_id: TenantId, dataset: AnalyticsDataSet) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, dataset_id: AnalyticsDataSetId
    ) -> AnalyticsDataSet | None: ...

    @abstractmethod
    async def find_by_domain(
        self, tenant_id: TenantId, domain: SecurityDomain
    ) -> list[AnalyticsDataSet]: ...

    @abstractmethod
    async def find_all_active(self, tenant_id: TenantId) -> list[AnalyticsDataSet]: ...


class ISecurityKPIRepository(ABC):
    @abstractmethod
    async def save(self, tenant_id: TenantId, kpi: SecurityKPI) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, kpi_id: SecurityKPIId
    ) -> SecurityKPI | None: ...

    @abstractmethod
    async def find_by_type(self, tenant_id: TenantId, kpi_type: KPIType) -> SecurityKPI | None: ...

    @abstractmethod
    async def list_for_tenant(self, tenant_id: TenantId) -> list[SecurityKPI]: ...


class IAnomalyDetectionBaselineRepository(ABC):
    @abstractmethod
    async def save(self, tenant_id: TenantId, baseline: AnomalyDetectionBaseline) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, baseline_id: AnomalyDetectionBaselineId
    ) -> AnomalyDetectionBaseline | None: ...

    @abstractmethod
    async def find_by_signal(
        self, tenant_id: TenantId, signal_type: str
    ) -> AnomalyDetectionBaseline | None: ...


class IAnalyticsQueryRepository(ABC):
    @abstractmethod
    async def save(self, tenant_id: TenantId, query: AnalyticsQuery) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, query_id: AnalyticsQueryId
    ) -> AnalyticsQuery | None: ...

    @abstractmethod
    async def list_for_tenant(self, tenant_id: TenantId) -> list[AnalyticsQuery]: ...
