"""DetectionMatch — the Detection Engine's application-facing match
record (M44A §5).

**Not an Alert.** `siem_alerting`'s `Alert` aggregate (M43A) is a
human/workflow construct; a `DetectionMatch` is a stateless evaluation
outcome — it has no lifecycle, no dedup/suppression/escalation, and is
never persisted by this bounded context. Turning matches into alerts is
explicitly `siem_alerting`'s job (M42 Phase 8), not this one's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from siem_shared.domain.value_objects.event_severity import EventSeverity


@dataclass(frozen=True, slots=True)
class DetectionMatch:
    rule_id: str
    event_id: str
    matched_at: datetime
    severity: EventSeverity
    confidence: float
    reason: str

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("DetectionMatch.rule_id must be a non-empty string")
        if not self.event_id.strip():
            raise ValueError("DetectionMatch.event_id must be a non-empty string")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"DetectionMatch.confidence must be in [0, 1], got {self.confidence}"
            )
        if not self.reason.strip():
            raise ValueError("DetectionMatch.reason must be a non-empty string")
