"""CorrelationResult — the Correlation Engine's application-facing
match record (M44B §5).

**Not an Alert.** `siem_alerting`'s `Alert` aggregate (M43A) is a
human/workflow construct; a `CorrelationResult` is a stateless
evaluation outcome for one session at one point in time — it is never
persisted by this bounded context. Turning correlation matches into
alerts is explicitly `siem_alerting`'s job (M42 Phase 8), not this
one's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    session_id: str
    correlation_rule_id: str
    correlated_event_ids: tuple[str, ...]
    detection_match_refs: tuple[str, ...]
    confidence: float
    reason: str
    window_started_at: datetime
    window_expires_at: datetime

    def __post_init__(self) -> None:
        if not self.session_id.strip():
            raise ValueError("CorrelationResult.session_id must be a non-empty string")
        if not self.correlation_rule_id.strip():
            raise ValueError("CorrelationResult.correlation_rule_id must be a non-empty string")
        if not self.correlated_event_ids:
            raise ValueError("CorrelationResult.correlated_event_ids must be non-empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"CorrelationResult.confidence must be in [0, 1], got {self.confidence}"
            )
        if not self.reason.strip():
            raise ValueError("CorrelationResult.reason must be a non-empty string")
