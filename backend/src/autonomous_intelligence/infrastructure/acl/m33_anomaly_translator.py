from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AnomalySignalDetectedPayload:
    tenant_id: str
    source_id: str
    severity: str | None = None
    payload: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class AnomalySignalRef:
    tenant_id: str
    source_id: str
    severity: str | None
    details: dict[str, object]


class M33AnomalyTranslator:
    def translate(self, payload: AnomalySignalDetectedPayload) -> AnomalySignalRef | None:
        try:
            return AnomalySignalRef(
                payload.tenant_id,
                payload.source_id,
                payload.severity,
                dict(payload.payload or {}),
            )
        except Exception:
            return None
