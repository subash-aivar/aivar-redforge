from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectionRulePerformanceReportedPayload:
    tenant_id: str
    source_id: str
    severity: str | None = None
    payload: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class DetectionPerformanceSignal:
    tenant_id: str
    source_id: str
    severity: str | None
    details: dict[str, object]


class M28PerformanceTranslator:
    def translate(
        self, payload: DetectionRulePerformanceReportedPayload
    ) -> DetectionPerformanceSignal | None:
        try:
            return DetectionPerformanceSignal(
                payload.tenant_id,
                payload.source_id,
                payload.severity,
                dict(payload.payload or {}),
            )
        except Exception:
            return None
