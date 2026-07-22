from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MLModelTrainingCompletedPayload:
    tenant_id: str
    source_id: str
    severity: str | None = None
    payload: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class ModelTrainingSignal:
    tenant_id: str
    source_id: str
    severity: str | None
    details: dict[str, object]


class M33MlSignalTranslator:
    def translate(self, payload: MLModelTrainingCompletedPayload) -> ModelTrainingSignal | None:
        try:
            return ModelTrainingSignal(
                payload.tenant_id,
                payload.source_id,
                payload.severity,
                dict(payload.payload or {}),
            )
        except Exception:
            return None
