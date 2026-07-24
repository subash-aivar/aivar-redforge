"""IAlertEvaluator — the one open extension point for deciding whether
a `CorrelationResult` should become an `Alert` (M37 §17). No concrete
implementation lives in this milestone.

Responsible only for deciding whether an Alert should exist — never
for constructing or mutating the `Alert` aggregate itself. That stays
`AlertApplicationService`'s job, reusing `Alert.raise_alert()`/
`.suppress()`/`.deduplicate()` (M43A) exactly as written.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_alerting.application.ports.alert_evaluation_result import AlertEvaluationResult
    from siem_correlation.application.dtos.correlation_result import CorrelationResult
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class IAlertEvaluator(Protocol):
    """`rule_id` + `schema_version` together are the registry key
    (M44C §4), mirroring `IDetectionEvaluator`/`ICorrelationEvaluator`'s
    identical shape (M44A/M44B)."""

    @property
    def rule_id(self) -> str: ...

    @property
    def schema_version(self) -> SchemaVersion: ...

    def evaluate(self, correlation_result: CorrelationResult) -> AlertEvaluationResult:
        """Decide whether `correlation_result` should become an alert.
        Implementations should raise on an input they cannot evaluate —
        the framework translates that into a `FAILED` outcome, it does
        not swallow it."""
        ...
