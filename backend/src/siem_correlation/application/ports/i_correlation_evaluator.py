"""ICorrelationEvaluator — the one open extension point for correlation
pattern logic (M37 §6/§17). No concrete implementation lives in this
milestone.

Responsible only for correlation logic — `siem_detection` owns the
rule *definition*; this evaluator owns *execution* against a session's
already-accumulated events, per M37 §5 point 2's division of labor,
now realized on the correlation side.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from siem_correlation.application.ports.correlation_evaluation_result import (
        CorrelationEvaluationResult,
    )
    from siem_detection.application.dtos.detection_match import DetectionMatch
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class ICorrelationEvaluator(Protocol):
    """`rule_id` + `schema_version` together are the registry key
    (M44B §4), mirroring `IDetectionEvaluator`'s identical shape (M44A).

    `correlated_event_ids` — not full `CanonicalEvent`s — because
    `CorrelationSession` (M43A) itself only ever tracks event
    identity, never full payloads (a deliberate choice to keep the
    architecture's highest-risk aggregate small and bounded, M37 §6).
    An evaluator that needs full event content for a *new* arrival has
    it via `new_event`; reasoning about the rest of the window is
    necessarily identity-based only, consistent with what the session
    itself actually holds.
    """

    @property
    def rule_id(self) -> str: ...

    @property
    def schema_version(self) -> SchemaVersion: ...

    def evaluate(
        self,
        correlated_event_ids: Sequence[str],
        new_match: DetectionMatch,
        new_event: CanonicalEvent,
    ) -> CorrelationEvaluationResult:
        """Evaluate whether the session's accumulated events (including
        the newly-arrived one, already present in `correlated_event_ids`)
        now constitute a correlation match. Implementations should raise
        on a pattern they cannot execute — the framework translates that
        into a `FAILED` outcome, it does not swallow it."""
        ...
