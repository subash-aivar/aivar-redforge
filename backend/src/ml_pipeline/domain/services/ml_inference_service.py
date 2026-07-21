from __future__ import annotations

import hashlib
import pickle
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import numpy as np

from ml_pipeline.domain.aggregates.predictive_risk_signal import PredictiveRiskSignal
from ml_pipeline.domain.exceptions.domain_exceptions import ArtifactIntegrityError
from ml_pipeline.domain.value_objects.identifiers import (
    MLModelId,
    PredictiveRiskSignalId,
    TenantId,
)

SIGNAL_TTL_DAYS = 30


@dataclass(frozen=True, slots=True)
class LoadedArtifact:
    model: Any
    algorithm: str
    model_type: str


class MLInferenceService:
    def verify_and_load(self, artifact_bytes: bytes, expected_sha256: str) -> LoadedArtifact:
        digest = hashlib.sha256(artifact_bytes).hexdigest()
        if digest != expected_sha256:
            raise ArtifactIntegrityError("SHA-256 mismatch")
        payload = pickle.loads(artifact_bytes)
        return LoadedArtifact(
            model=payload["model"],
            algorithm=str(payload["algorithm"]),
            model_type=str(payload["model_type"]),
        )

    def predict(
        self,
        loaded: LoadedArtifact,
        *,
        tenant_id: TenantId,
        model_id: MLModelId,
        assets: list[dict[str, Any]],
        now: datetime | None = None,
    ) -> list[PredictiveRiskSignal]:
        now = now or datetime.now(UTC)
        expires = now + timedelta(days=SIGNAL_TTL_DAYS)
        x = np.asarray(
            [
                [
                    float(a.get("exposure_score", 0.0)),
                    float(a.get("vuln_count", 0.0)),
                    float(a.get("detection_gap", 0.0)),
                    float(a.get("ai_risk", 0.0)),
                ]
                for a in assets
            ],
            dtype=float,
        )
        if x.size == 0:
            return []
        model = loaded.model
        if hasattr(model, "decision_function"):
            raw = model.decision_function(x)
            scores = 1.0 / (1.0 + np.exp(raw))  # map to (0,1)-ish
        elif hasattr(model, "predict_proba"):
            scores = model.predict_proba(x)[:, -1]
        else:
            pred = model.predict(x)
            scores = (pred - pred.min()) / (pred.max() - pred.min() + 1e-9)
        signals: list[PredictiveRiskSignal] = []
        for i, asset in enumerate(assets):
            signals.append(
                PredictiveRiskSignal(
                    PredictiveRiskSignalId.generate(),
                    tenant_id,
                    model_id,
                    UUID(str(asset["asset_ref_id"])),
                    loaded.model_type,
                    float(scores[i]),
                    0.8,
                    now,
                    expires,
                    {
                        "exposure_score": float(asset.get("exposure_score", 0.0)),
                        "vuln_count": float(asset.get("vuln_count", 0.0)),
                    },
                )
            )
        return signals
