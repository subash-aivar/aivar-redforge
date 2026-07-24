from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from redforge.shared.identifiers import EntityId
from siem_correlation.application.commands.correlation_commands import CorrelationInput
from siem_correlation.domain.value_objects.enums import CorrelationKind, CorrelationRole
from siem_detection.application.dtos.detection_match import DetectionMatch
from siem_shared.domain.services.canonical_event_factory import build_canonical_event
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_severity import EventSeverity
from siem_shared.domain.value_objects.event_source import EventSource, EventSourceType
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from siem_correlation.application.ports.correlation_evaluation_result import (
        CorrelationEvaluationResult,
    )
    from siem_correlation.domain.aggregates.correlation_session import CorrelationSession
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent

EXECUTOR_ROLES = (CorrelationRole.EXECUTOR.value,)
SCHEMA_V1_0 = SchemaVersion(1, 0)


class FakeCorrelationEvaluator:
    def __init__(
        self,
        rule_id: str,
        schema_version: SchemaVersion = SCHEMA_V1_0,
        evaluator: Callable[..., CorrelationEvaluationResult] | None = None,
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

    def evaluate(
        self,
        correlated_event_ids: Sequence[str],
        new_match: DetectionMatch,
        new_event: CanonicalEvent,
    ) -> CorrelationEvaluationResult:
        if self._evaluator is None:
            raise AssertionError("FakeCorrelationEvaluator.evaluate called with no evaluator set")
        return self._evaluator(correlated_event_ids, new_match, new_event)


class InMemorySessionStore:
    """Test double for both ICorrelationSessionProvider and
    ICorrelationSessionWriter — a plain dict standing in for the future
    real session store."""

    def __init__(self) -> None:
        self.sessions: dict[tuple[str, str], CorrelationSession] = {}
        self.writes: list[CorrelationSession] = []

    def find_open_session(
        self, tenant_id: EntityId, correlation_rule_id: str
    ) -> CorrelationSession | None:
        return self.sessions.get((str(tenant_id), correlation_rule_id))

    def write(self, session: CorrelationSession) -> None:
        self.writes.append(session)
        self.sessions[(str(session.tenant_id), session.rule_id)] = session


@pytest.fixture
def session_store() -> InMemorySessionStore:
    return InMemorySessionStore()


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


def make_detection_match(event: CanonicalEvent, rule_id: str = "detect-rule-1") -> DetectionMatch:
    return DetectionMatch(
        rule_id=rule_id,
        event_id=str(event.identity.event_id),
        matched_at=datetime.now(UTC),
        severity=EventSeverity.HIGH,
        confidence=0.9,
        reason="matched",
    )


def make_input(
    tenant_id: EntityId | None = None,
    correlation_rule_id: str = "corr-rule-1",
    correlation_kind: CorrelationKind = CorrelationKind.ENTITY,
) -> CorrelationInput:
    tenant_id = tenant_id or EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    match = make_detection_match(event)
    return CorrelationInput(
        correlation_rule_id=correlation_rule_id,
        detection_match=match,
        canonical_event=event,
        correlation_kind=correlation_kind,
    )


def correlated(confidence: float = 0.8, reason: str = "pattern matched"):
    from siem_correlation.application.ports.correlation_evaluation_result import (
        CorrelationEvaluationResult,
    )

    return lambda ids, match, event: CorrelationEvaluationResult(
        matched=True, confidence=confidence, reason=reason
    )


def not_correlated(reason: str = "insufficient events"):
    from siem_correlation.application.ports.correlation_evaluation_result import (
        CorrelationEvaluationResult,
    )

    return lambda ids, match, event: CorrelationEvaluationResult(
        matched=False, confidence=0.0, reason=reason
    )
