"""IDetectionEvaluator — the one open extension point for rule
execution (M37 §5's `IDetectionEvaluator`, evaluated per-event or
per-window depending on shape).

No concrete implementation lives in this milestone — no Sigma parser,
no YARA, no compiled rule AST. This is the contract a future rule-shape
implementation (M42 Phase 6+) must satisfy. The evaluator owns rule
*execution* only; `DetectionRule` (M43A) owns the rule *definition* and
lifecycle — the same separation M37 §5 point 2 already draws between
`siem_detection` (definition) and `siem_correlation` (execution) for
correlation-shaped rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_detection.application.ports.detection_evaluation_result import (
        DetectionEvaluationResult,
    )
    from siem_detection.domain.value_objects.enums import DetectionRuleShape
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class IDetectionEvaluator(Protocol):
    """`rule_id` + `schema_version` together are the registry key
    (M44A §4) — `schema_version` is the CEM schema version this
    evaluator was built against, mirroring `IEventNormalizer`'s
    identical shape (M43D)."""

    @property
    def rule_id(self) -> str: ...

    @property
    def shape(self) -> DetectionRuleShape: ...

    @property
    def schema_version(self) -> SchemaVersion: ...

    def evaluate(self, event: CanonicalEvent) -> DetectionEvaluationResult:
        """Evaluate a single event against this evaluator's rule.
        Implementations should raise on a rule/event combination they
        cannot execute — the framework translates that into a
        `FAILED` outcome, it does not swallow it."""
        ...
