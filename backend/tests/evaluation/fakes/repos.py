"""In-memory fakes for evaluation tests."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from evaluation.application.ports.i_event_publisher import IEventPublisher
from evaluation.application.ports.i_unit_of_work import IUnitOfWork
from evaluation.domain.repositories.i_campaign_evaluation_repository import (
    ICampaignEvaluationRepository,
)
from evaluation.domain.repositories.i_campaign_metrics_snapshot_repository import (
    ICampaignMetricsSnapshotRepository,
)
from evaluation.domain.value_objects.identifiers import CampaignEvaluationId

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

    from evaluation.domain.aggregates.campaign_evaluation import CampaignEvaluation
    from evaluation.domain.aggregates.campaign_metrics_snapshot import (
        CampaignMetricsSnapshot,
    )
    from evaluation.domain.events.base import BaseDomainEvent
    from evaluation.domain.value_objects.identifiers import TenantId


class FakeEvaluationRepository(ICampaignEvaluationRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, CampaignEvaluation] = {}
        self._by_instance: dict[str, str] = {}

    async def save(self, evaluation: CampaignEvaluation) -> None:
        key = str(evaluation.evaluation_id)
        self._by_id[key] = evaluation
        self._by_instance[str(evaluation.campaign_instance_ref.instance_id)] = key

    async def find_by_id(
        self,
        evaluation_id: CampaignEvaluationId,
        tenant_id: TenantId,
    ) -> CampaignEvaluation | None:
        ev = self._by_id.get(str(evaluation_id))
        if ev is None or ev.tenant_id != tenant_id:
            return None
        return ev

    async def find_by_campaign_instance(
        self,
        campaign_instance_id: str,
        tenant_id: TenantId,
    ) -> CampaignEvaluation | None:
        key = self._by_instance.get(campaign_instance_id)
        if key is None:
            return None
        return await self.find_by_id(CampaignEvaluationId(UUID(key)), tenant_id)


class FakeMetricsSnapshotRepository(ICampaignMetricsSnapshotRepository):
    def __init__(self) -> None:
        self._items: list[CampaignMetricsSnapshot] = []

    async def save(self, snapshot: CampaignMetricsSnapshot) -> None:
        self._items.append(snapshot)

    async def find_by_campaign(
        self,
        campaign_id: str,
        tenant_id: TenantId,
        limit: int = 50,
    ) -> list[CampaignMetricsSnapshot]:
        matched = [
            s
            for s in self._items
            if s.campaign_id == campaign_id and s.tenant_id == tenant_id
        ]
        matched.sort(key=lambda s: s.run_number, reverse=True)
        return matched[:limit]

    async def find_by_tenant_since(
        self,
        tenant_id: TenantId,
        since: datetime,
    ) -> list[CampaignMetricsSnapshot]:
        return [
            s
            for s in self._items
            if s.tenant_id == tenant_id and s.snapshot_timestamp >= since
        ]


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.events: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.events.extend(events)


class FakeUnitOfWork(IUnitOfWork):
    def __init__(
        self,
        evaluations: FakeEvaluationRepository | None = None,
        snapshots: FakeMetricsSnapshotRepository | None = None,
    ) -> None:
        super().__init__()
        self.evaluations = evaluations or FakeEvaluationRepository()
        self.metrics_snapshots = snapshots or FakeMetricsSnapshotRepository()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        pass

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            await self.rollback()
