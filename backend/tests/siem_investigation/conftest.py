from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from redforge.shared.identifiers import EntityId
from siem_alerting.domain.aggregates.alert import Alert
from siem_alerting.domain.value_objects.enums import AlertSeverity, AlertSourceKind
from siem_alerting.domain.value_objects.identifiers import AlertId
from siem_investigation.application.commands.investigation_commands import (
    InvestigationEvaluationInput,
)
from siem_investigation.domain.value_objects.enums import InvestigationEngineRole, TimelineScopeType
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from collections.abc import Callable

    from siem_investigation.application.ports.investigation_evaluation_result import (
        InvestigationEvaluationResult,
    )
    from siem_investigation.domain.aggregates.investigation_timeline import InvestigationTimeline

EXECUTOR_ROLES = (InvestigationEngineRole.EXECUTOR.value,)
SCHEMA_V1_0 = SchemaVersion(1, 0)
NOW = datetime.now(UTC)


class FakeInvestigationEvaluator:
    def __init__(
        self,
        rule_id: str,
        schema_version: SchemaVersion = SCHEMA_V1_0,
        evaluator: Callable[[Alert], InvestigationEvaluationResult] | None = None,
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

    def evaluate(self, alert: Alert) -> InvestigationEvaluationResult:
        if self._evaluator is None:
            raise AssertionError(
                "FakeInvestigationEvaluator.evaluate called with no evaluator set"
            )
        return self._evaluator(alert)


class InMemoryInvestigationStore:
    """Test double for both IInvestigationProvider and IInvestigationWriter."""

    def __init__(self) -> None:
        self.by_scope: dict[tuple[str, str, str], InvestigationTimeline] = {}
        self.writes: list[InvestigationTimeline] = []

    def find_open_timeline(
        self, tenant_id: EntityId, scope_type: TimelineScopeType, scope_ref: str
    ) -> InvestigationTimeline | None:
        return self.by_scope.get((str(tenant_id), scope_type.value, scope_ref))

    def write(self, timeline: InvestigationTimeline) -> None:
        self.writes.append(timeline)
        key = (str(timeline.tenant_id), timeline.scope_type.value, timeline.scope_ref)
        self.by_scope[key] = timeline


@pytest.fixture
def investigation_store() -> InMemoryInvestigationStore:
    return InMemoryInvestigationStore()


def make_alert(tenant_id: EntityId | None = None, dedup_key: str = "dedup-1") -> Alert:
    return Alert.raise_alert(
        alert_id=AlertId.generate(),
        tenant_id=tenant_id or EntityId.generate(),
        dedup_key=dedup_key,
        severity=AlertSeverity.HIGH,
        source_kind=AlertSourceKind.CORRELATION,
        source_ref="session-1",
        now=NOW,
    )


def make_evaluation_input(
    investigation_rule_id: str = "inv-rule-1",
    alert: Alert | None = None,
    schema_version_raw: str = "1.0",
) -> InvestigationEvaluationInput:
    return InvestigationEvaluationInput(
        investigation_rule_id=investigation_rule_id,
        alert=alert or make_alert(),
        schema_version_raw=schema_version_raw,
    )


def investigates(
    scope_ref: str = "entity-1",
    scope_type: TimelineScopeType = TimelineScopeType.ENTITY,
    summary: str = "suspicious activity",
    reason: str = "high severity correlated alert",
):
    from siem_investigation.application.ports.investigation_evaluation_result import (
        InvestigationEvaluationResult,
    )

    return lambda alert: InvestigationEvaluationResult(
        should_investigate=True,
        scope_type=scope_type,
        scope_ref=scope_ref,
        summary=summary,
        reason=reason,
    )


def does_not_investigate(reason: str = "low severity, not actionable"):
    from siem_investigation.application.ports.investigation_evaluation_result import (
        InvestigationEvaluationResult,
    )

    return lambda alert: InvestigationEvaluationResult(
        should_investigate=False,
        scope_type=TimelineScopeType.ENTITY,
        scope_ref="entity-1",
        summary="n/a",
        reason=reason,
    )
