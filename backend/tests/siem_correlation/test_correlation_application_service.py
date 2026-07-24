from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from redforge.shared.identifiers import EntityId
from siem_correlation.application.commands.correlation_commands import (
    CorrelateBatchCommand,
    CorrelateDetectionMatchCommand,
    CorrelationInput,
)
from siem_correlation.application.dtos.correlation_outcome import CorrelationStatus
from siem_correlation.application.exceptions import (
    ApplicationForbiddenError,
    EmptyBatchCorrelationError,
)
from siem_correlation.application.registry.in_memory_correlation_evaluator_registry import (
    InMemoryCorrelationEvaluatorRegistry,
)
from siem_correlation.application.services.correlation_application_service import (
    CorrelationApplicationService,
)
from siem_correlation.domain.aggregates.correlation_session import CorrelationSession
from siem_correlation.domain.value_objects.enums import CorrelationSessionStatus
from siem_correlation.domain.value_objects.identifiers import CorrelationSessionId

from .conftest import (
    EXECUTOR_ROLES,
    FakeCorrelationEvaluator,
    correlated,
    make_canonical_event,
    make_detection_match,
    make_input,
    not_correlated,
)

NOW = datetime.now(UTC)


def _service(session_store, registry=None, **overrides):
    return CorrelationApplicationService(
        session_provider=session_store,
        session_writer=session_store,
        evaluator_registry=registry or InMemoryCorrelationEvaluatorRegistry(),
        **overrides,
    )


# ---------------------------------------------------------------------------
# single-event correlation
# ---------------------------------------------------------------------------


def test_single_event_no_match_yet(session_store):
    registry = InMemoryCorrelationEvaluatorRegistry()
    registry.register(FakeCorrelationEvaluator("rule-1", evaluator=not_correlated()))
    service = _service(session_store, registry)
    tenant_id = EntityId.generate()
    item = make_input(tenant_id, "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.SUCCEEDED
    assert outcome.result is None
    assert len(session_store.writes) == 1
    assert session_store.writes[0].status == CorrelationSessionStatus.OPEN


def test_single_event_correlation_matches(session_store):
    registry = InMemoryCorrelationEvaluatorRegistry()
    registry.register(FakeCorrelationEvaluator("rule-1", evaluator=correlated()))
    service = _service(session_store, registry)
    tenant_id = EntityId.generate()
    item = make_input(tenant_id, "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.SUCCEEDED
    assert outcome.result is not None
    assert outcome.result.session_id == str(session_store.writes[0].session_id)
    assert session_store.writes[0].status == CorrelationSessionStatus.MATCHED


# ---------------------------------------------------------------------------
# multi-event correlation
# ---------------------------------------------------------------------------


def test_multi_event_correlation_accumulates_into_same_session(session_store):
    seen_counts = []

    def _tracking_evaluator(ids, match, event):
        from siem_correlation.application.ports.correlation_evaluation_result import (
            CorrelationEvaluationResult,
        )

        seen_counts.append(len(ids))
        return CorrelationEvaluationResult(matched=len(ids) >= 2, confidence=0.9, reason="x")

    registry = InMemoryCorrelationEvaluatorRegistry()
    registry.register(FakeCorrelationEvaluator("rule-1", evaluator=_tracking_evaluator))
    service = _service(session_store, registry)
    tenant_id = EntityId.generate()

    first = service.correlate(
        CorrelateDetectionMatchCommand(
            tenant_id=tenant_id, item=make_input(tenant_id, "rule-1"), actor_roles=EXECUTOR_ROLES
        )
    )
    second = service.correlate(
        CorrelateDetectionMatchCommand(
            tenant_id=tenant_id, item=make_input(tenant_id, "rule-1"), actor_roles=EXECUTOR_ROLES
        )
    )

    assert seen_counts == [1, 2]
    assert first.result is None
    assert second.result is not None
    assert len(second.result.correlated_event_ids) == 2


# ---------------------------------------------------------------------------
# duplicate-event rejection
# ---------------------------------------------------------------------------


def test_duplicate_event_is_rejected_not_double_counted(session_store):
    registry = InMemoryCorrelationEvaluatorRegistry()
    registry.register(FakeCorrelationEvaluator("rule-1", evaluator=not_correlated()))
    service = _service(session_store, registry)
    tenant_id = EntityId.generate()
    item = make_input(tenant_id, "rule-1")

    first = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )
    second = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert first.status == CorrelationStatus.SUCCEEDED
    assert second.status == CorrelationStatus.DUPLICATE_EVENT
    session = session_store.find_open_session(tenant_id, "rule-1")
    assert len(session.correlated_event_ids) == 1


# ---------------------------------------------------------------------------
# expired session
# ---------------------------------------------------------------------------


def test_expired_session_is_reported_and_formally_expired(session_store):
    tenant_id = EntityId.generate()
    expired_session = CorrelationSession.open(
        session_id=CorrelationSessionId.generate(),
        tenant_id=tenant_id,
        rule_id="rule-1",
        correlation_kind=make_input(tenant_id, "rule-1").correlation_kind,
        window_started_at=NOW - timedelta(minutes=30),
        window_expires_at=NOW - timedelta(minutes=15),
    )
    session_store.sessions[(str(tenant_id), "rule-1")] = expired_session
    service = _service(session_store)
    item = make_input(tenant_id, "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.SESSION_EXPIRED
    assert session_store.writes[-1].status == CorrelationSessionStatus.EXPIRED


def test_already_expired_session_status_is_reported_without_re_expiring(session_store):
    tenant_id = EntityId.generate()
    session = CorrelationSession.open(
        session_id=CorrelationSessionId.generate(),
        tenant_id=tenant_id,
        rule_id="rule-1",
        correlation_kind=make_input(tenant_id, "rule-1").correlation_kind,
        window_started_at=NOW - timedelta(minutes=30),
        window_expires_at=NOW - timedelta(minutes=15),
    )
    session.expire(tenant_id, NOW - timedelta(minutes=10))
    session_store.sessions[(str(tenant_id), "rule-1")] = session
    service = _service(session_store)
    item = make_input(tenant_id, "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.SESSION_EXPIRED
    assert session_store.writes == []  # no redundant re-expire write


# ---------------------------------------------------------------------------
# closed (matched) session
# ---------------------------------------------------------------------------


def test_matched_session_is_reported_as_closed(session_store):
    tenant_id = EntityId.generate()
    session = CorrelationSession.open(
        session_id=CorrelationSessionId.generate(),
        tenant_id=tenant_id,
        rule_id="rule-1",
        correlation_kind=make_input(tenant_id, "rule-1").correlation_kind,
        window_started_at=NOW,
        window_expires_at=NOW + timedelta(minutes=15),
    )
    session.match(tenant_id, NOW)
    session_store.sessions[(str(tenant_id), "rule-1")] = session
    service = _service(session_store)
    item = make_input(tenant_id, "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.SESSION_CLOSED
    assert session_store.writes == []


# ---------------------------------------------------------------------------
# maximum window / capacity enforcement
# ---------------------------------------------------------------------------


def test_session_at_capacity_is_rejected(session_store):
    tenant_id = EntityId.generate()
    session = CorrelationSession.open(
        session_id=CorrelationSessionId.generate(),
        tenant_id=tenant_id,
        rule_id="rule-1",
        correlation_kind=make_input(tenant_id, "rule-1").correlation_kind,
        window_started_at=NOW,
        window_expires_at=NOW + timedelta(minutes=15),
    )
    session.accumulate(tenant_id, "evt-1", NOW)
    session.accumulate(tenant_id, "evt-2", NOW)
    session_store.sessions[(str(tenant_id), "rule-1")] = session
    service = _service(session_store, max_correlation_size=2)
    item = make_input(tenant_id, "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.SESSION_AT_CAPACITY
    assert len(session.correlated_event_ids) == 2  # unchanged


# ---------------------------------------------------------------------------
# unsupported evaluator
# ---------------------------------------------------------------------------


def test_no_registered_evaluator_is_unsupported(session_store):
    service = _service(session_store)  # empty registry
    tenant_id = EntityId.generate()
    item = make_input(tenant_id, "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.UNSUPPORTED_EVALUATOR
    assert outcome.failures[0].error_type == "UnsupportedEvaluatorError"


def test_evaluator_exception_produces_failed_but_still_accumulates(session_store):
    def _explode(ids, match, event):
        raise RuntimeError("malformed correlation logic")

    registry = InMemoryCorrelationEvaluatorRegistry()
    registry.register(FakeCorrelationEvaluator("rule-1", evaluator=_explode))
    service = _service(session_store, registry)
    tenant_id = EntityId.generate()
    item = make_input(tenant_id, "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.FAILED
    assert outcome.failures[0].error_type == "RuntimeError"
    session = session_store.find_open_session(tenant_id, "rule-1")
    assert len(session.correlated_event_ids) == 1


# ---------------------------------------------------------------------------
# batch correlation
# ---------------------------------------------------------------------------


def test_batch_all_succeed(session_store):
    registry = InMemoryCorrelationEvaluatorRegistry()
    registry.register(FakeCorrelationEvaluator("rule-1", evaluator=not_correlated()))
    service = _service(session_store, registry)
    tenant_id = EntityId.generate()
    items = tuple(make_input(tenant_id, "rule-1") for _ in range(3))

    result = service.correlate_batch(
        CorrelateBatchCommand(tenant_id=tenant_id, items=items, actor_roles=EXECUTOR_ROLES)
    )

    assert result.status == CorrelationStatus.SUCCEEDED
    assert result.succeeded_count == 3


def test_batch_partial_failure(session_store):
    service = _service(session_store)  # empty registry -> unsupported evaluator
    tenant_id = EntityId.generate()
    registry = InMemoryCorrelationEvaluatorRegistry()
    registry.register(FakeCorrelationEvaluator("rule-1", evaluator=not_correlated()))
    service = _service(session_store, registry)
    items = (make_input(tenant_id, "rule-1"), make_input(tenant_id, "rule-unregistered"))

    result = service.correlate_batch(
        CorrelateBatchCommand(tenant_id=tenant_id, items=items, actor_roles=EXECUTOR_ROLES)
    )

    assert result.status == CorrelationStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1
    assert result.failed_count == 1


def test_batch_empty_raises(session_store):
    service = _service(session_store)
    with pytest.raises(EmptyBatchCorrelationError):
        service.correlate_batch(
            CorrelateBatchCommand(
                tenant_id=EntityId.generate(), items=(), actor_roles=EXECUTOR_ROLES
            )
        )


# ---------------------------------------------------------------------------
# authorization
# ---------------------------------------------------------------------------


def test_without_executor_role_raises_forbidden(session_store):
    service = _service(session_store)
    tenant_id = EntityId.generate()
    with pytest.raises(ApplicationForbiddenError):
        service.correlate(
            CorrelateDetectionMatchCommand(
                tenant_id=tenant_id, item=make_input(tenant_id, "rule-1"), actor_roles=()
            )
        )


# ---------------------------------------------------------------------------
# negative cases
# ---------------------------------------------------------------------------


def test_tenant_mismatch_is_rejected(session_store):
    service = _service(session_store)
    tenant_id = EntityId.generate()
    other_tenant_item = make_input(EntityId.generate(), "rule-1")

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(
            tenant_id=tenant_id, item=other_tenant_item, actor_roles=EXECUTOR_ROLES
        )
    )

    assert outcome.status == CorrelationStatus.EVALUATION_REJECTED
    assert outcome.failures[0].error_type == "TenantContextMismatchError"


def test_detection_match_event_mismatch_is_rejected(session_store):
    service = _service(session_store)
    tenant_id = EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    mismatched_match = make_detection_match(make_canonical_event(tenant_id=tenant_id))
    item = CorrelationInput(
        correlation_rule_id="rule-1", detection_match=mismatched_match, canonical_event=event
    )

    outcome = service.correlate(
        CorrelateDetectionMatchCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == CorrelationStatus.EVALUATION_REJECTED
    assert outcome.failures[0].error_type == "DetectionMatchEventMismatchError"


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_correlation_outcome_is_frozen(session_store):
    service = _service(session_store)
    tenant_id = EntityId.generate()
    outcome = service.correlate(
        CorrelateDetectionMatchCommand(
            tenant_id=tenant_id, item=make_input(tenant_id, "rule-1"), actor_roles=EXECUTOR_ROLES
        )
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.status = CorrelationStatus.FAILED  # type: ignore[misc]
