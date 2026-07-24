from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_alerting.application.commands.alert_commands import (
    CreateAlertCommand,
    EvaluateBatchCommand,
    EvaluateCorrelationResultCommand,
)
from siem_alerting.application.dtos.alert_outcome import AlertOutcomeStatus
from siem_alerting.application.exceptions import (
    ApplicationForbiddenError,
    EmptyBatchAlertEvaluationError,
)
from siem_alerting.application.registry.in_memory_alert_evaluator_registry import (
    InMemoryAlertEvaluatorRegistry,
)
from siem_alerting.application.services.alert_application_service import AlertApplicationService
from siem_alerting.domain.value_objects.enums import AlertSeverity, AlertSourceKind, AlertStatus

from .conftest import (
    EXECUTOR_ROLES,
    FakeAlertEvaluator,
    alerts,
    does_not_alert,
    make_alert_evaluation_input,
    make_correlation_result,
    suppresses,
)

NOW = datetime.now(UTC)


def _service(alert_store, registry=None):
    return AlertApplicationService(
        alert_provider=alert_store,
        alert_writer=alert_store,
        evaluator_registry=registry or InMemoryAlertEvaluatorRegistry(),
    )


# ---------------------------------------------------------------------------
# alert creation (direct)
# ---------------------------------------------------------------------------


def test_create_alert_directly(alert_store):
    service = _service(alert_store)
    tenant_id = EntityId.generate()

    outcome = service.create_alert(
        CreateAlertCommand(
            tenant_id=tenant_id,
            dedup_key="dedup-1",
            severity=AlertSeverity.HIGH,
            source_kind=AlertSourceKind.DETECTION,
            source_ref="rule-1",
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert outcome.status == AlertOutcomeStatus.CREATED
    assert outcome.alert_id is not None
    assert alert_store.writes[0].status == AlertStatus.RAISED


def test_create_alert_without_role_raises_forbidden(alert_store):
    service = _service(alert_store)
    with pytest.raises(ApplicationForbiddenError):
        service.create_alert(
            CreateAlertCommand(
                tenant_id=EntityId.generate(),
                dedup_key="dedup-1",
                severity=AlertSeverity.HIGH,
                source_kind=AlertSourceKind.DETECTION,
                source_ref="rule-1",
                actor_roles=(),
            )
        )


def test_create_alert_blank_dedup_key_is_rejected(alert_store):
    service = _service(alert_store)
    outcome = service.create_alert(
        CreateAlertCommand(
            tenant_id=EntityId.generate(),
            dedup_key="   ",
            severity=AlertSeverity.HIGH,
            source_kind=AlertSourceKind.DETECTION,
            source_ref="rule-1",
            actor_roles=EXECUTOR_ROLES,
        )
    )
    assert outcome.status == AlertOutcomeStatus.REJECTED
    assert outcome.failures[0].error_type == "EmptyDedupKeyError"


# ---------------------------------------------------------------------------
# evaluation-driven creation
# ---------------------------------------------------------------------------


def test_evaluation_creates_alert(alert_store):
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("alert-rule-1", evaluator=alerts()))
    service = _service(alert_store, registry)
    tenant_id = EntityId.generate()

    outcome = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(
            tenant_id=tenant_id,
            item=make_alert_evaluation_input(),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert outcome.status == AlertOutcomeStatus.CREATED
    assert outcome.decision_reason == "confirmed pattern"


def test_evaluation_rejects_when_should_not_alert(alert_store):
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("alert-rule-1", evaluator=does_not_alert()))
    service = _service(alert_store, registry)
    tenant_id = EntityId.generate()

    outcome = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(
            tenant_id=tenant_id,
            item=make_alert_evaluation_input(),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert outcome.status == AlertOutcomeStatus.REJECTED
    assert outcome.alert_id is None
    assert alert_store.writes == []


# ---------------------------------------------------------------------------
# suppression
# ---------------------------------------------------------------------------


def test_evaluation_suppresses_alert(alert_store):
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("alert-rule-1", evaluator=suppresses()))
    service = _service(alert_store, registry)
    tenant_id = EntityId.generate()

    outcome = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(
            tenant_id=tenant_id,
            item=make_alert_evaluation_input(),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert outcome.status == AlertOutcomeStatus.SUPPRESSED
    assert alert_store.writes[0].status == AlertStatus.SUPPRESSED
    assert alert_store.writes[0].suppression_reason == "allowlisted actor"


# ---------------------------------------------------------------------------
# deduplication
# ---------------------------------------------------------------------------


def test_second_matching_alert_is_deduplicated_not_double_created(alert_store):
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("alert-rule-1", evaluator=alerts()))
    service = _service(alert_store, registry)
    tenant_id = EntityId.generate()
    correlation_result = make_correlation_result(session_id="session-shared")
    item = make_alert_evaluation_input(correlation_result=correlation_result)

    first = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )
    second = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert first.status == AlertOutcomeStatus.CREATED
    assert second.status == AlertOutcomeStatus.DEDUPLICATED
    assert second.original_alert_id == first.alert_id
    assert alert_store.writes[1].status == AlertStatus.DEDUPLICATED


def test_dedup_key_derivation_is_deterministic(alert_store):
    correlation_result = make_correlation_result(session_id="session-x")
    item_a = make_alert_evaluation_input(correlation_result=correlation_result)
    item_b = make_alert_evaluation_input(correlation_result=correlation_result)
    assert item_a.correlation_result.session_id == item_b.correlation_result.session_id


# ---------------------------------------------------------------------------
# closed alerts
# ---------------------------------------------------------------------------


def test_dedup_against_closed_alert_creates_fresh_alert_instead(alert_store):
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("alert-rule-1", evaluator=alerts()))
    service = _service(alert_store, registry)
    tenant_id = EntityId.generate()
    correlation_result = make_correlation_result(session_id="session-closed-test")
    item = make_alert_evaluation_input(correlation_result=correlation_result)

    first = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )
    first_alert = alert_store.writes[0]
    first_alert.escalate(tenant_id, NOW)
    first_alert.acknowledge(tenant_id, "analyst-1", NOW)
    first_alert.close(tenant_id, "analyst-1", "resolved", NOW)
    alert_store.by_dedup_key[(str(tenant_id), first_alert.dedup_key)] = first_alert

    second = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert first.status == AlertOutcomeStatus.CREATED
    assert second.status == AlertOutcomeStatus.CREATED
    assert second.alert_id != first.alert_id


# ---------------------------------------------------------------------------
# unsupported evaluator / evaluator exceptions
# ---------------------------------------------------------------------------


def test_unsupported_evaluator(alert_store):
    service = _service(alert_store)  # empty registry
    tenant_id = EntityId.generate()

    outcome = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(
            tenant_id=tenant_id, item=make_alert_evaluation_input(), actor_roles=EXECUTOR_ROLES
        )
    )

    assert outcome.status == AlertOutcomeStatus.UNSUPPORTED_EVALUATOR


def test_evaluator_exception_produces_failed_outcome(alert_store):
    def _explode(correlation_result):
        raise RuntimeError("malformed evaluator logic")

    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("alert-rule-1", evaluator=_explode))
    service = _service(alert_store, registry)
    tenant_id = EntityId.generate()

    outcome = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(
            tenant_id=tenant_id, item=make_alert_evaluation_input(), actor_roles=EXECUTOR_ROLES
        )
    )

    assert outcome.status == AlertOutcomeStatus.FAILED
    assert outcome.failures[0].error_type == "RuntimeError"
    assert alert_store.writes == []


def test_malformed_schema_version_is_rejected(alert_store):
    service = _service(alert_store)
    tenant_id = EntityId.generate()
    item = make_alert_evaluation_input(schema_version_raw="garbage")

    outcome = service.evaluate_correlation_result(
        EvaluateCorrelationResultCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == AlertOutcomeStatus.REJECTED


# ---------------------------------------------------------------------------
# batch evaluation
# ---------------------------------------------------------------------------


def test_batch_all_succeed(alert_store):
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("alert-rule-1", evaluator=alerts()))
    service = _service(alert_store, registry)
    tenant_id = EntityId.generate()
    items = tuple(make_alert_evaluation_input() for _ in range(3))

    result = service.evaluate_batch(
        EvaluateBatchCommand(tenant_id=tenant_id, items=items, actor_roles=EXECUTOR_ROLES)
    )

    assert result.status == AlertOutcomeStatus.SUCCEEDED
    assert result.created_count == 3


def test_batch_partial_failure(alert_store):
    registry = InMemoryAlertEvaluatorRegistry()
    registry.register(FakeAlertEvaluator("alert-rule-1", evaluator=alerts()))
    service = _service(alert_store, registry)
    tenant_id = EntityId.generate()
    items = (
        make_alert_evaluation_input(alert_rule_id="alert-rule-1"),
        make_alert_evaluation_input(alert_rule_id="unregistered-rule"),
    )

    result = service.evaluate_batch(
        EvaluateBatchCommand(tenant_id=tenant_id, items=items, actor_roles=EXECUTOR_ROLES)
    )

    assert result.status == AlertOutcomeStatus.PARTIALLY_SUCCEEDED
    assert result.created_count == 1
    assert result.failed_count == 0  # unsupported evaluator, not FAILED


def test_batch_empty_raises(alert_store):
    service = _service(alert_store)
    with pytest.raises(EmptyBatchAlertEvaluationError):
        service.evaluate_batch(
            EvaluateBatchCommand(tenant_id=EntityId.generate(), items=(), actor_roles=EXECUTOR_ROLES)
        )


def test_batch_without_role_raises_forbidden(alert_store):
    service = _service(alert_store)
    with pytest.raises(ApplicationForbiddenError):
        service.evaluate_batch(
            EvaluateBatchCommand(
                tenant_id=EntityId.generate(),
                items=(make_alert_evaluation_input(),),
                actor_roles=(),
            )
        )


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_alert_outcome_is_frozen(alert_store):
    service = _service(alert_store)
    outcome = service.create_alert(
        CreateAlertCommand(
            tenant_id=EntityId.generate(),
            dedup_key="dedup-1",
            severity=AlertSeverity.HIGH,
            source_kind=AlertSourceKind.DETECTION,
            source_ref="rule-1",
            actor_roles=EXECUTOR_ROLES,
        )
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.status = AlertOutcomeStatus.REJECTED  # type: ignore[misc]
