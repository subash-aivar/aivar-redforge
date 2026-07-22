from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExposureScoreUpdatedPayload:
    tenant_id: str
    source_id: str
    severity: str | None = None
    payload: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class ExposureTrendSignal:
    tenant_id: str
    source_id: str
    severity: str | None
    details: dict[str, object]


class M32ExposureTranslator:
    def translate(self, payload: ExposureScoreUpdatedPayload) -> ExposureTrendSignal | None:
        try:
            return ExposureTrendSignal(
                payload.tenant_id,
                payload.source_id,
                payload.severity,
                dict(payload.payload or {}),
            )
        except Exception:
            return None
