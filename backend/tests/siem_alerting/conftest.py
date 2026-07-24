from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from redforge.shared.identifiers import EntityId
from siem_alerting.application.commands.alert_commands import AlertEvaluationInput
from siem_alerting.domain.value_objects.enums import AlertEngineRole, AlertSeverity
from siem_correlation.application.dtos.correlation_result import CorrelationResult
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from collections.abc import Callable

    from siem_alerting.application.ports.alert_evaluation_result import AlertEvaluationResult
    from siem_alerting.domain.aggregates.alert import Alert

EXECUTOR_ROLES = (AlertEngineRole.EXECUTOR.value,)
SCHEMA_V1_0 = SchemaVersion(1, 0)
NOW = datetime.now(UTC)


class FakeAlertEvaluator:
    def __init__(
        self,
        rule_id: str,
        schema_version: SchemaVersion = SCHEMA_V1_0,
        evaluator: Callable[[CorrelationResult], AlertEvaluationResult] | None = None,
    ) -> None:
        self._rule_id = rule_id
        self._schema_version = schema_version
        self._evaluator = evaluator

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def schema_version(self) -> SchemaVersion:
        return self._schema_version

    def evaluate(self, correlation_result: CorrelationResult) -> AlertEvaluationResult:
        if self._evaluator is None:
            raise AssertionError("FakeAlertEvaluator.evaluate called with no evaluator set")
        return self._evaluator(correlation_result)


class InMemoryAlertStore:
    """Test double for both IAlertProvider and IAlertWriter."""

    def __init__(self) -> None:
        self.by_dedup_key: dict[tuple[str, str], Alert] = {}
        self.writes: list[Alert] = []

    def find_by_dedup_key(self, tenant_id: EntityId, dedup_key: str) -> Alert | None:
        return self.by_dedup_key.get((str(tenant_id), dedup_key))

    def write(self, alert: Alert) -> None:
        self.writes.append(alert)
        self.by_dedup_key[(str(alert.tenant_id), alert.dedup_key)] = alert


@pytest.fixture
def alert_store() -> InMemoryAlertStore:
    return InMemoryAlertStore()


def make_correlation_result(
    correlation_rule_id: str = "corr-rule-1", session_id: str | None = None
) -> CorrelationResult:
    return CorrelationResult(
        session_id=session_id or f"session-{EntityId.generate()}",
        correlation_rule_id=correlation_rule_id,
        correlated_event_ids=("event-1", "event-2"),
        detection_match_refs=("detect-rule-1:event-2",),
        confidence=0.85,
        reason="repeated auth failures across window",
        window_started_at=NOW,
        window_expires_at=NOW + timedelta(minutes=15),
    )


def make_alert_evaluation_input(
    alert_rule_id: str = "alert-rule-1",
    correlation_result: CorrelationResult | None = None,
    schema_version_raw: str = "1.0",
) -> AlertEvaluationInput:
    return AlertEvaluationInput(
        alert_rule_id=alert_rule_id,
        correlation_result=correlation_result or make_correlation_result(),
        schema_version_raw=schema_version_raw,
    )


def alerts(reason: str = "confirmed pattern", severity: AlertSeverity = AlertSeverity.HIGH):
    from siem_alerting.application.ports.alert_evaluation_result import AlertEvaluationResult

    return lambda correlation_result: AlertEvaluationResult(
        should_alert=True, severity=severity, reason=reason
    )


def does_not_alert(reason: str = "insufficient confidence"):
    from siem_alerting.application.ports.alert_evaluation_result import AlertEvaluationResult

    return lambda correlation_result: AlertEvaluationResult(
        should_alert=False, severity=AlertSeverity.LOW, reason=reason
    )


def suppresses(reason: str = "known benign", suppression_reason: str = "allowlisted actor"):
    from siem_alerting.application.ports.alert_evaluation_result import AlertEvaluationResult

    return lambda correlation_result: AlertEvaluationResult(
        should_alert=True,
        severity=AlertSeverity.LOW,
        reason=reason,
        suppress=True,
        suppression_reason=suppression_reason,
    )
