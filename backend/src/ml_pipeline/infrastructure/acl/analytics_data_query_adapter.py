"""ACL: analytics projection feature data without importing analytics.domain."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import numpy as np

from ml_pipeline.domain.ports.i_analytics_data_query_port import (
    IAnalyticsDataQueryPort,
    InferenceFeatureRow,
    TrainingDataset,
)
from ml_pipeline.domain.value_objects.enums import MLModelType

if TYPE_CHECKING:
    from ml_pipeline.domain.value_objects.identifiers import TenantId

FEATURE_NAMES = ["f_severity", "f_exposure", "f_coverage", "f_age_days", "f_kev"]


class InMemoryAnalyticsDataQueryAdapter(IAnalyticsDataQueryPort):
    """Seedable in-process training/inference feature source for Phase 3 tests."""

    def __init__(self) -> None:
        self._training_overrides: dict[str, TrainingDataset | None] = {}
        self._inference_rows: dict[str, list[InferenceFeatureRow]] = {}
        self._force_insufficient: set[str] = set()

    def seed_training(self, tenant_id: TenantId, dataset: TrainingDataset | None) -> None:
        self._training_overrides[str(tenant_id)] = dataset

    def force_insufficient(self, tenant_id: TenantId) -> None:
        self._force_insufficient.add(str(tenant_id))

    def seed_inference(self, tenant_id: TenantId, rows: list[InferenceFeatureRow]) -> None:
        self._inference_rows[str(tenant_id)] = rows

    async def load_training_dataset(
        self,
        tenant_id: TenantId,
        model_type: MLModelType,
        dataset_id: UUID,
        *,
        min_rows: int = 40,
    ) -> TrainingDataset | None:
        key = str(tenant_id)
        if key in self._force_insufficient:
            return None
        if key in self._training_overrides:
            return self._training_overrides[key]
        return self._synthetic_dataset(model_type, n=max(min_rows, 80))

    async def load_inference_features(
        self,
        tenant_id: TenantId,
        model_type: MLModelType,
        feature_names: list[str],
    ) -> list[InferenceFeatureRow]:
        key = str(tenant_id)
        if key in self._inference_rows:
            return self._inference_rows[key]
        rng = np.random.default_rng(7)
        rows: list[InferenceFeatureRow] = []
        for _ in range(10):
            feats = rng.normal(0.4, 0.15, size=len(feature_names or FEATURE_NAMES))
            feats = np.clip(feats, 0.0, 1.0)
            rows.append(InferenceFeatureRow(asset_id=uuid4(), features=feats.tolist()))
        return rows

    def _synthetic_dataset(self, model_type: MLModelType, *, n: int) -> TrainingDataset:
        """Generate separable synthetic data that passes frozen accuracy gates."""
        rng = np.random.default_rng(42)
        asset_ids = [uuid4() for _ in range(n)]
        if model_type == MLModelType.COVERAGE_FORECASTER:
            x = rng.normal(0.5, 0.2, size=(n, len(FEATURE_NAMES)))
            # Linear target with noise — high R²
            weights = np.array([0.3, 0.25, 0.2, 0.15, 0.1])
            y = x @ weights + rng.normal(0, 0.02, size=n)
            y = np.clip(y, 0.0, 1.0)
        elif model_type == MLModelType.RISK_PREDICTOR:
            x0 = rng.normal(0.3, 0.1, size=(n // 2, len(FEATURE_NAMES)))
            x1 = rng.normal(0.7, 0.1, size=(n - n // 2, len(FEATURE_NAMES)))
            x = np.vstack([x0, x1])
            y = np.array([0.0] * (n // 2) + [1.0] * (n - n // 2))
            perm = rng.permutation(n)
            x, y = x[perm], y[perm]
        else:
            # Anomaly detector: mostly normal, few anomalies
            n_anom = max(8, n // 10)
            x_norm = rng.normal(0.3, 0.08, size=(n - n_anom, len(FEATURE_NAMES)))
            x_anom = rng.normal(0.85, 0.05, size=(n_anom, len(FEATURE_NAMES)))
            x = np.vstack([x_norm, x_anom])
            y = np.array([0.0] * (n - n_anom) + [1.0] * n_anom)
            perm = rng.permutation(n)
            x, y = x[perm], y[perm]
            asset_ids = [asset_ids[i] for i in perm]

        return TrainingDataset(
            feature_names=list(FEATURE_NAMES),
            features=np.clip(x, 0.0, 1.0).tolist(),
            labels=y.tolist(),
            asset_ids=asset_ids,
        )

    @staticmethod
    def noisy_unlearnable_dataset(n: int = 60) -> TrainingDataset:
        """Random features/labels — fails accuracy gates (for FAIL tests)."""
        rng = np.random.default_rng(99)
        x = rng.random((n, len(FEATURE_NAMES)))
        y = rng.integers(0, 2, size=n).astype(float)
        return TrainingDataset(
            feature_names=list(FEATURE_NAMES),
            features=x.tolist(),
            labels=y.tolist(),
            asset_ids=[uuid4() for _ in range(n)],
        )
