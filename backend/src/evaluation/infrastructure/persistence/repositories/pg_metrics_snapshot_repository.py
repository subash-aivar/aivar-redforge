"""PostgreSQL repository for CampaignMetricsSnapshot aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select

from evaluation.domain.aggregates.campaign_metrics_snapshot import CampaignMetricsSnapshot
from evaluation.domain.repositories.i_campaign_metrics_snapshot_repository import (
    ICampaignMetricsSnapshotRepository,
)
from evaluation.domain.value_objects.evaluation_vos import EvaluationMetrics
from evaluation.domain.value_objects.identifiers import (
    CampaignMetricsSnapshotId,
    TenantId,
)
from evaluation.infrastructure.persistence.models.evaluation_models import (
    CampaignMetricsSnapshotModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


def _from_row(row: CampaignMetricsSnapshotModel) -> CampaignMetricsSnapshot:
    metrics = EvaluationMetrics(
        detection_coverage_percent=row.detection_coverage_percent,
        technique_success_rate=row.technique_success_rate,
        evasion_rate=row.evasion_rate,
        mean_time_to_detect_seconds=row.mean_time_to_detect_seconds,
        actions_executed_count=row.actions_executed_count,
        actions_failed_count=row.actions_failed_count,
        objectives_achieved_count=row.objectives_achieved_count,
        objectives_failed_count=row.objectives_failed_count,
        campaign_duration_seconds=row.campaign_duration_seconds,
        kill_chain_phases_covered=tuple(row.kill_chain_phases_covered_json or ()),
    )
    return CampaignMetricsSnapshot(
        snapshot_id=CampaignMetricsSnapshotId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        campaign_id=str(row.campaign_id),
        run_number=row.run_number,
        snapshot_timestamp=row.snapshot_timestamp,
        metrics=metrics,
        composite_outcome=row.composite_outcome,
        sealed=True,
    )


class PgMetricsSnapshotRepository(ICampaignMetricsSnapshotRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, snapshot: CampaignMetricsSnapshot) -> None:
        existing = await self._session.get(CampaignMetricsSnapshotModel, snapshot.snapshot_id.value)
        if existing is not None:
            return  # immutable — ignore re-saves

        m = snapshot.metrics
        row = CampaignMetricsSnapshotModel(
            id=snapshot.snapshot_id.value,
            tenant_id=snapshot.tenant_id.value,
            campaign_id=UUID(snapshot.campaign_id),
            run_number=snapshot.run_number,
            snapshot_timestamp=snapshot.snapshot_timestamp,
            composite_outcome=snapshot.composite_outcome,
            detection_coverage_percent=m.detection_coverage_percent,
            technique_success_rate=m.technique_success_rate,
            evasion_rate=m.evasion_rate,
            mean_time_to_detect_seconds=m.mean_time_to_detect_seconds,
            objectives_achieved_count=m.objectives_achieved_count,
            objectives_failed_count=m.objectives_failed_count,
            actions_executed_count=m.actions_executed_count,
            actions_failed_count=m.actions_failed_count,
            campaign_duration_seconds=m.campaign_duration_seconds,
            kill_chain_phases_covered_json=list(m.kill_chain_phases_covered),
            metrics_json={
                "detection_coverage_percent": m.detection_coverage_percent,
                "technique_success_rate": m.technique_success_rate,
                "evasion_rate": m.evasion_rate,
            },
        )
        self._session.add(row)

    async def find_by_campaign(
        self,
        campaign_id: str,
        tenant_id: TenantId,
        limit: int = 50,
    ) -> list[CampaignMetricsSnapshot]:
        stmt = (
            select(CampaignMetricsSnapshotModel)
            .where(
                CampaignMetricsSnapshotModel.campaign_id == UUID(campaign_id),
                CampaignMetricsSnapshotModel.tenant_id == tenant_id.value,
            )
            .order_by(CampaignMetricsSnapshotModel.run_number.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_from_row(r) for r in result.scalars().all()]

    async def find_by_tenant_since(
        self,
        tenant_id: TenantId,
        since: datetime,
    ) -> list[CampaignMetricsSnapshot]:
        stmt = (
            select(CampaignMetricsSnapshotModel)
            .where(
                CampaignMetricsSnapshotModel.tenant_id == tenant_id.value,
                CampaignMetricsSnapshotModel.snapshot_timestamp >= since,
            )
            .order_by(CampaignMetricsSnapshotModel.snapshot_timestamp.desc())
        )
        result = await self._session.execute(stmt)
        return [_from_row(r) for r in result.scalars().all()]
