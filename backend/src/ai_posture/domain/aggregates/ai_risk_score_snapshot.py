"""AIRiskScoreSnapshot aggregate — immutable cached score."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_posture.domain.events.posture_events import (
    AIRiskScoreComputed,
    AIRiskScoreStalenessExceeded,
)
from ai_posture.domain.exceptions.domain_exceptions import SnapshotImmutable, TenantMismatch
from ai_posture.domain.value_objects.posture_vos import (
    SCORE_INPUT_VERSION,
    compute_composite_score,
)

if TYPE_CHECKING:
    from datetime import datetime

    from ai_posture.domain.events.base import BaseDomainEvent
    from ai_posture.domain.value_objects.identifiers import (
        AIRiskScoreSnapshotId,
        AISystemAssetId,
        TenantId,
    )
    from ai_posture.domain.value_objects.posture_vos import ScoreComponents


class AIRiskScoreSnapshot:
    __slots__ = (
        "_pending_events",
        "ai_system_asset_id",
        "composite_score",
        "computed_at",
        "score_components",
        "score_input_version",
        "snapshot_id",
        "staleness_bound_hours",
        "tenant_id",
    )

    def __init__(
        self,
        snapshot_id: AIRiskScoreSnapshotId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        score_components: ScoreComponents,
        composite_score: float,
        computed_at: datetime,
        staleness_bound_hours: int,
        score_input_version: str,
    ) -> None:
        self.snapshot_id = snapshot_id
        self.tenant_id = tenant_id
        self.ai_system_asset_id = ai_system_asset_id
        self.score_components = score_components
        self.composite_score = composite_score
        self.computed_at = computed_at
        self.staleness_bound_hours = staleness_bound_hours
        self.score_input_version = score_input_version
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def create(
        cls,
        snapshot_id: AIRiskScoreSnapshotId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        components: ScoreComponents,
        now: datetime,
        *,
        staleness_bound_hours: int = 24,
        score_input_version: str = SCORE_INPUT_VERSION,
    ) -> AIRiskScoreSnapshot:
        composite = compute_composite_score(components)
        snap = cls(
            snapshot_id=snapshot_id,
            tenant_id=tenant_id,
            ai_system_asset_id=ai_system_asset_id,
            score_components=components,
            composite_score=composite,
            computed_at=now,
            staleness_bound_hours=staleness_bound_hours,
            score_input_version=score_input_version,
        )
        snap._emit(
            AIRiskScoreComputed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(snapshot_id),
                aggregate_type="AIRiskScoreSnapshot",
                ai_system_asset_id=str(ai_system_asset_id),
                composite_score=composite,
                score_input_version=score_input_version,
            )
        )
        return snap

    def is_stale(self, now: datetime) -> bool:
        from datetime import timedelta

        return now >= self.computed_at + timedelta(hours=self.staleness_bound_hours)

    def emit_staleness_exceeded(self, tenant_id: TenantId, now: datetime) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)
        self._emit(
            AIRiskScoreStalenessExceeded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.snapshot_id),
                aggregate_type="AIRiskScoreSnapshot",
                ai_system_asset_id=str(self.ai_system_asset_id),
                snapshot_id=str(self.snapshot_id),
            )
        )

    def mutate(self) -> None:
        raise SnapshotImmutable()
