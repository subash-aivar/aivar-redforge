from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from redforge.shared.identifiers import EntityId
from siem_detection.domain.aggregates.detection_rule import DetectionRule
from siem_detection.domain.value_objects.enums import DetectionRole, DetectionRuleShape
from siem_detection.domain.value_objects.identifiers import DetectionRuleId
from siem_shared.domain.services.canonical_event_factory import build_canonical_event
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_severity import EventSeverity
from siem_shared.domain.value_objects.event_source import EventSource, EventSourceType
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from siem_detection.application.ports.detection_evaluation_result import (
        DetectionEvaluationResult,
    )
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent

EXECUTOR_ROLES = (DetectionRole.EXECUTOR.value,)
SCHEMA_V1_0 = SchemaVersion(1, 0)


class FakeDetectionEvaluator:
    """Test double for IDetectionEvaluator — a stand-in for a future
    real rule-shape implementation (e.g. compiled Sigma), never a real
    one."""

    def __init__(
        self,
        rule_id: str,
        schema_version: SchemaVersion = SCHEMA_V1_0,
        shape: DetectionRuleShape = DetectionRuleShape.SIGMA,
        evaluator: Callable[[CanonicalEvent], DetectionEvaluationResult] | None = None,
    ) -> None:
        self._rule_id = rule_id
        self._schema_version = schema_version
        self._shape = shape
        self._evaluator = evaluator

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def shape(self) -> DetectionRuleShape:
        return self._shape

    @property
    def schema_version(self) -> SchemaVersion:
        return self._schema_version

    def evaluate(self, event: CanonicalEvent) -> DetectionEvaluationResult:
        if self._evaluator is None:
            raise AssertionError("FakeDetectionEvaluator.evaluate called with no evaluator set")
        return self._evaluator(event)


class FakeRuleProvider:
    def __init__(self, rules: Sequence[DetectionRule] = ()) -> None:
        self._rules = list(rules)

    def get_rules(self, tenant_id: EntityId) -> Sequence[DetectionRule]:
        return [r for r in self._rules if r.tenant_id == tenant_id or r.tenant_id is None]


@pytest.fixture
def rule_provider() -> FakeRuleProvider:
    return FakeRuleProvider()


def make_canonical_event(
    *, tenant_id: EntityId | None = None, category: EventCategory = EventCategory.AUTHENTICATION
) -> CanonicalEvent:
    return build_canonical_event(
        tenant_id=tenant_id or EntityId.generate(),
        source=EventSource(source_type=EventSourceType.IDENTITY, vendor="okta"),
        category=category,
        outcome=EventOutcome.SUCCESS,
        occurred_at=datetime.now(UTC),
        schema_version=SCHEMA_V1_0,
    )


def make_active_rule(tenant_id: EntityId | None = None, name: str = "rule-1") -> DetectionRule:
    rule = DetectionRule.draft(
        rule_id=DetectionRuleId.generate(),
        tenant_id=tenant_id,
        name=name,
        shape=DetectionRuleShape.SIGMA,
        rule_body="detection:\n  selection:\n    EventID: 4625",
        now=datetime.now(UTC),
    )
    rule.activate(tenant_id, datetime.now(UTC))
    return rule


def make_draft_rule(tenant_id: EntityId | None = None, name: str = "rule-draft") -> DetectionRule:
    return DetectionRule.draft(
        rule_id=DetectionRuleId.generate(),
        tenant_id=tenant_id,
        name=name,
        shape=DetectionRuleShape.SIGMA,
        rule_body="detection:\n  selection:\n    EventID: 4625",
        now=datetime.now(UTC),
    )


def matched(severity: EventSeverity = EventSeverity.HIGH, confidence: float = 0.9, reason: str = "matched"):
    from siem_detection.application.ports.detection_evaluation_result import (
        DetectionEvaluationResult,
    )

    return lambda event: DetectionEvaluationResult(
        matched=True, severity=severity, confidence=confidence, reason=reason
    )


def not_matched(reason: str = "no match"):
    from siem_detection.application.ports.detection_evaluation_result import (
        DetectionEvaluationResult,
    )

    return lambda event: DetectionEvaluationResult(
        matched=False, severity=EventSeverity.LOW, confidence=0.0, reason=reason
    )
