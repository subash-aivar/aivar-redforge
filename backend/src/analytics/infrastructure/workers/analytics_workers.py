"""Analytics workers — Phase 1 + Phase 5 retry/DLQ/metrics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from analytics.application.commands.analytics_commands import (
    IngestAnalyticsEventCommand,
    TriggerKPIComputationCommand,
)
from analytics.domain.value_objects.enums import KPIType
from analytics.domain.value_objects.identifiers import TenantId
from analytics.infrastructure.projections.event_projection_store import DOMAIN_TABLES

if TYPE_CHECKING:

    from analytics.application.services.analytics_application_service import (
        AnalyticsApplicationService,
    )
    from analytics.infrastructure.observability.metrics_store import (
        OperationalMetricsStore,
    )
    from analytics.infrastructure.projections.event_projection_store import (
        EventProjectionStore,
    )


class AnalyticsProjectionWorker:
    """Idempotent event ingestion with retry + dead-letter."""

    def __init__(
        self,
        app: AnalyticsApplicationService,
        *,
        metrics: OperationalMetricsStore | None = None,
        max_retries: int = 3,
    ) -> None:
        self._app = app
        self._metrics = metrics
        self._max_retries = max_retries
        self.dead_letters: list[dict[str, Any]] = []

    async def handle(
        self,
        *,
        tenant_id: TenantId,
        domain: str,
        event_id: str,
        event_type: str,
        event_ts: datetime,
        payload: dict[str, object],
    ) -> dict[str, object]:
        last_error: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                result = await self._app.ingest_event(
                    IngestAnalyticsEventCommand(
                        tenant_id=tenant_id,
                        domain=domain,
                        event_id=event_id,
                        event_type=event_type,
                        event_ts=event_ts,
                        payload=payload,
                        actor_roles=("analytics:engineer",),
                    )
                )
                if self._metrics is not None:
                    self._metrics.mark_worker("AnalyticsProjectionWorker", ok=True)
                return {**result, "attempts": attempt}
            except Exception as exc:
                last_error = exc
                if self._metrics is not None:
                    self._metrics.mark_worker("AnalyticsProjectionWorker", ok=False, error=str(exc))
        self.dead_letters.append(
            {
                "tenant_id": str(tenant_id),
                "event_id": event_id,
                "domain": domain,
                "event_type": event_type,
                "error": str(last_error),
                "failed_at": datetime.now(UTC).isoformat(),
            }
        )
        return {
            "ingested": False,
            "event_id": event_id,
            "dead_lettered": True,
            "error": str(last_error),
        }


class KPIComputationWorker:
    def __init__(
        self,
        app: AnalyticsApplicationService,
        *,
        metrics: OperationalMetricsStore | None = None,
    ) -> None:
        self._app = app
        self._metrics = metrics

    async def run_for_tenant(self, tenant_id: TenantId) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        started = datetime.now(UTC)
        for kpi_type in (
            KPIType.MTTD,
            KPIType.COVERAGE_PCT,
            KPIType.EXPOSURE_TREND,
            KPIType.CAMPAIGN_SUCCESS_RATE,
            KPIType.AI_RISK_TREND,
            KPIType.MTTR,
        ):
            results.append(
                await self._app.trigger_kpi(
                    TriggerKPIComputationCommand(
                        tenant_id=tenant_id,
                        kpi_type=kpi_type.value,
                        actor_roles=("analytics:admin",),
                    )
                )
            )
        if self._metrics is not None:
            elapsed = (datetime.now(UTC) - started).total_seconds() * 1000.0
            self._metrics.record(
                "kpi_computation_batch_ms", elapsed, unit="ms", tenant_id=tenant_id
            )
            self._metrics.mark_worker("KPIComputationWorker", ok=True)
        return results


class RetentionPolicyWorker:
    """Marks rows archived; never physically deletes (Invariant 3)."""

    def __init__(self, store: EventProjectionStore) -> None:
        self._store = store

    async def run(
        self, tenant_id: TenantId, *, event_retention_days: int = 730
    ) -> dict[str, object]:
        before = datetime.now(UTC) - timedelta(days=event_retention_days)
        total = 0
        for domain in DOMAIN_TABLES:
            total += self._store.mark_archived_before(tenant_id, domain, before)
        return {"archived_rows": total, "before": before.isoformat()}


class PartitionMaintenanceWorker:
    def __init__(self) -> None:
        self.last_run_at: str | None = None

    async def run(self) -> dict[str, object]:
        self.last_run_at = datetime.now(UTC).isoformat()
        return {
            "ok": True,
            "planned_month": datetime.now(UTC).strftime("%Y_%m"),
            "last_run_at": self.last_run_at,
        }


class ProjectionRebuildWorker:
    def __init__(self, app: AnalyticsApplicationService) -> None:
        self._app = app

    async def run(self, tenant_id: TenantId, domain: str | None = None) -> dict[str, object]:
        from analytics.application.commands.analytics_commands import (
            TriggerProjectionRebuildCommand,
        )

        return await self._app.trigger_rebuild(
            TriggerProjectionRebuildCommand(
                tenant_id=tenant_id,
                domain=domain,
                actor_roles=("analytics:admin",),
            )
        )
