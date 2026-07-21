from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from ml_pipeline.domain.value_objects.identifiers import (
        MLModelId,
        PredictiveRiskSignalId,
        TenantId,
    )


class PredictiveRiskSignal:
    """Advisory-only signal (ADR-M33-002). Never writes upstream scores."""

    __slots__ = (
        "asset_ref_id",
        "confidence",
        "created_at",
        "expires_at",
        "features",
        "model_id",
        "score",
        "signal_id",
        "signal_type",
        "tenant_id",
    )

    def __init__(
        self,
        signal_id: PredictiveRiskSignalId,
        tenant_id: TenantId,
        model_id: MLModelId,
        asset_ref_id: UUID,
        signal_type: str,
        score: float,
        confidence: float,
        created_at: datetime,
        expires_at: datetime,
        features: dict[str, float],
    ) -> None:
        self.signal_id = signal_id
        self.tenant_id = tenant_id
        self.model_id = model_id
        self.asset_ref_id = asset_ref_id
        self.signal_type = signal_type
        self.score = score
        self.confidence = confidence
        self.created_at = created_at
        self.expires_at = expires_at
        self.features = features

    def is_active(self, now: datetime) -> bool:
        return now < self.expires_at
