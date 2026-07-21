"""ExposureScoreSnapshot — append-only immutable score history."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from exposure.domain.value_objects.exposure_vos import ScoreInputVersion
    from exposure.domain.value_objects.identifiers import (
        ExposureScoreSnapshotId,
        TenantId,
    )


class ExposureScoreSnapshot:
    """Immutable. Never mutate after construction."""

    __slots__ = (
        "asset_ref_id",
        "composite_score",
        "computed_at",
        "job_id",
        "record_scores",
        "score_input_version",
        "snapshot_id",
        "tenant_id",
    )

    def __init__(
        self,
        snapshot_id: ExposureScoreSnapshotId,
        tenant_id: TenantId,
        asset_ref_id: UUID,
        composite_score: float,
        score_input_version: ScoreInputVersion,
        computed_at: datetime,
        job_id: str,
        record_scores: dict[str, float],
    ) -> None:
        self.snapshot_id = snapshot_id
        self.tenant_id = tenant_id
        self.asset_ref_id = asset_ref_id
        self.composite_score = composite_score
        self.score_input_version = score_input_version
        self.computed_at = computed_at
        self.job_id = job_id
        self.record_scores = dict(record_scores)

    @classmethod
    def create(
        cls,
        snapshot_id: ExposureScoreSnapshotId,
        tenant_id: TenantId,
        asset_ref_id: UUID,
        composite_score: float,
        score_input_version: ScoreInputVersion,
        computed_at: datetime,
        job_id: str,
        record_scores: dict[str, float],
    ) -> ExposureScoreSnapshot:
        return cls(
            snapshot_id=snapshot_id,
            tenant_id=tenant_id,
            asset_ref_id=asset_ref_id,
            composite_score=composite_score,
            score_input_version=score_input_version,
            computed_at=computed_at,
            job_id=job_id,
            record_scores=record_scores,
        )
