from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AnomalySignalDetectedPayload:
    tenant_id: str
    signal_id: str
    strength: float
    technique_id: str | None = None


@dataclass(frozen=True, slots=True)
class ThreatHuntAnomalySignal:
    tenant_id: str
    signal_id: str
    strength: float
    technique_id: str | None


class M33AnomalyTranslator:
    def translate(self, payload: AnomalySignalDetectedPayload) -> ThreatHuntAnomalySignal | None:
        try:
            return ThreatHuntAnomalySignal(
                payload.tenant_id, payload.signal_id, payload.strength, payload.technique_id
            )
        except Exception:
            return None
