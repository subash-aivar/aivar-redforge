"""Read-only port for analytics projection features (no analytics.domain import)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from ml_pipeline.domain.value_objects.enums import MLModelType
    from ml_pipeline.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class TrainingDataset:
    """Feature matrix + labels for in-process sklearn training."""

    feature_names: list[str]
    features: list[list[float]]
    labels: list[float]
    asset_ids: list[UUID] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class InferenceFeatureRow:
    asset_id: UUID
    features: list[float]


class IAnalyticsDataQueryPort(ABC):
    """Reads analytics projection tables via ACL — never imports analytics.domain."""

    @abstractmethod
    async def load_training_dataset(
        self,
        tenant_id: TenantId,
        model_type: MLModelType,
        dataset_id: UUID,
        *,
        min_rows: int = 40,
    ) -> TrainingDataset | None:
        """Return None when insufficient rows (cold-start / INSUFFICIENT_TRAINING_DATA)."""
        ...

    @abstractmethod
    async def load_inference_features(
        self,
        tenant_id: TenantId,
        model_type: MLModelType,
        feature_names: list[str],
    ) -> list[InferenceFeatureRow]: ...
