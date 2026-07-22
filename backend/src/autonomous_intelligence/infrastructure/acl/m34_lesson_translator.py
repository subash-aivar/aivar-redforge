from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IncidentLessonsLearnedPayload:
    tenant_id: str
    source_id: str
    severity: str | None = None
    payload: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class IncidentPatternSignal:
    tenant_id: str
    source_id: str
    severity: str | None
    details: dict[str, object]


class M34LessonTranslator:
    def translate(self, payload: IncidentLessonsLearnedPayload) -> IncidentPatternSignal | None:
        try:
            return IncidentPatternSignal(
                payload.tenant_id,
                payload.source_id,
                payload.severity,
                dict(payload.payload or {}),
            )
        except Exception:
            return None
