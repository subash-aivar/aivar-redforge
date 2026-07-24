"""Analytics scheduler — staggered KPI + retention + partition jobs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from analytics.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:

    from analytics.infrastructure.workers.analytics_workers import (
        KPIComputationWorker,
        PartitionMaintenanceWorker,
        RetentionPolicyWorker,
    )


class AnalyticsScheduler:
    """Cron-equivalent entry points (Finalization worker table)."""

    def __init__(
        self,
        kpi_worker: KPIComputationWorker,
        retention_worker: RetentionPolicyWorker,
        partition_worker: PartitionMaintenanceWorker,
    ) -> None:
        self._kpi = kpi_worker
        self._retention = retention_worker
        self._partition = partition_worker
        self.last_tick_at: str | None = None

    async def daily_tick(self, tenant_id: TenantId) -> dict[str, object]:
        from datetime import UTC, datetime

        kpi = await self._kpi.run_for_tenant(tenant_id)
        retention = await self._retention.run(tenant_id)
        partitions = await self._partition.run()
        self.last_tick_at = datetime.now(UTC).isoformat()
        return {
            "kpi_results": kpi,
            "retention": retention,
            "partitions": partitions,
            "last_tick_at": self.last_tick_at,
        }
