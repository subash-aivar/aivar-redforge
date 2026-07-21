"""CampaignMetricsSnapshot aggregate root — immutable metrics for trend analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from evaluation.domain.events.evaluation_events import MetricsSnapshotCreated
from evaluation.domain.exceptions.domain_exceptions import MetricsSnapshotSealed

if TYPE_CHECKING:
    from datetime import datetime

    from evaluation.domain.events.base import BaseDomainEvent
    from evaluation.domain.value_objects.evaluation_vos import EvaluationMetrics
    from evaluation.domain.value_objects.identifiers import (
        CampaignMetricsSnapshotId,
        TenantId,
    )


class CampaignMetricsSnapshot:
    """Immutable snapshot created on CampaignEvaluationCompleted.

    Feeds DetectionCoverageTrendView and TechniqueSuccessRateView.
    """

    __slots__ = (
        "_pending_events",
        "_sealed",
        "campaign_id",
        "composite_outcome",
        "metrics",
        "run_number",
        "snapshot_id",
        "snapshot_timestamp",
        "tenant_id",
    )

    def __init__(
        self,
        snapshot_id: CampaignMetricsSnapshotId,
        tenant_id: TenantId,
        campaign_id: str,
        run_number: int,
        snapshot_timestamp: datetime,
        metrics: EvaluationMetrics,
        composite_outcome: str,
        sealed: bool = True,
    ) -> None:
        self.snapshot_id = snapshot_id
        self.tenant_id = tenant_id
        self.campaign_id = campaign_id
        self.run_number = run_number
        self.snapshot_timestamp = snapshot_timestamp
        self.metrics = metrics
        self.composite_outcome = composite_outcome
        self._sealed = sealed
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def create(
        cls,
        snapshot_id: CampaignMetricsSnapshotId,
        tenant_id: TenantId,
        campaign_id: str,
        run_number: int,
        metrics: EvaluationMetrics,
        composite_outcome: str,
        now: datetime,
    ) -> CampaignMetricsSnapshot:
        snapshot = cls(
            snapshot_id=snapshot_id,
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            run_number=run_number,
            snapshot_timestamp=now,
            metrics=metrics,
            composite_outcome=composite_outcome,
            sealed=True,
        )
        snapshot._pending_events.append(
            MetricsSnapshotCreated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(snapshot_id),
                aggregate_type="CampaignMetricsSnapshot",
                campaign_id=campaign_id,
                run_number=run_number,
                detection_coverage_percent=metrics.detection_coverage_percent,
                technique_success_rate=metrics.technique_success_rate,
                composite_outcome=composite_outcome,
            )
        )
        return snapshot

    def mutate(self) -> None:
        """Snapshots are immutable — any mutation attempt is rejected."""
        raise MetricsSnapshotSealed(str(self.snapshot_id))
