"""IInvestigationEvaluator — the one open extension point for deciding
whether an `Alert` should open or update an investigation (M37 §17).
No concrete implementation lives in this milestone.

Responsible only for that decision — never for constructing or
mutating `InvestigationTimeline` itself. That stays
`InvestigationApplicationService`'s job, reusing `.create()`/
`.add_entry()` (M43A) exactly as written.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_alerting.domain.aggregates.alert import Alert
    from siem_investigation.application.ports.investigation_evaluation_result import (
        InvestigationEvaluationResult,
    )
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class IInvestigationEvaluator(Protocol):
    """`rule_id` + `schema_version` together are the registry key
    (M44D §4), mirroring `IDetectionEvaluator`/`ICorrelationEvaluator`/
    `IAlertEvaluator`'s identical shape (M44A/M44B/M44C)."""

    @property
    def rule_id(self) -> str: ...

    @property
    def schema_version(self) -> SchemaVersion: ...

    def evaluate(self, alert: Alert) -> InvestigationEvaluationResult:
        """Decide whether `alert` should open or update an
        investigation. Implementations should raise on an input they
        cannot evaluate — the framework translates that into a
        `FAILED` outcome, it does not swallow it."""
        ...
