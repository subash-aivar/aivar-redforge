from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from redforge.shared.identifiers import EntityId
from siem_alerting.domain.aggregates.alert import Alert
from siem_alerting.domain.value_objects.enums import AlertSeverity, AlertSourceKind
from siem_alerting.domain.value_objects.identifiers import AlertId
from siem_investigation.application.commands.investigation_commands import (
    AttachAlertCommand,
    EvaluateAlertCommand,
    EvaluateBatchCommand,
    OpenInvestigationCommand,
)
from siem_investigation.application.dtos.investigation_outcome import InvestigationOutcomeStatus
from siem_investigation.application.exceptions import (
    ApplicationForbiddenError,
    EmptyBatchInvestigationError,
)
from siem_investigation.application.registry.in_memory_investigation_evaluator_registry import (
    InMemoryInvestigationEvaluatorRegistry,
)
from siem_investigation.application.services.investigation_application_service import (
    InvestigationApplicationService,
)
from siem_investigation.domain.value_objects.enums import TimelineScopeType

from .conftest import (
    EXECUTOR_ROLES,
    FakeInvestigationEvaluator,
    does_not_investigate,
    investigates,
    make_alert,
    make_evaluation_input,
)

NOW = datetime.now(UTC)


def _service(investigation_store, registry=None):
    return InvestigationApplicationService(
        investigation_provider=investigation_store,
        investigation_writer=investigation_store,
        evaluator_registry=registry or InMemoryInvestigationEvaluatorRegistry(),
    )


# ---------------------------------------------------------------------------
# investigation creation (direct)
# ---------------------------------------------------------------------------


def test_open_investigation_directly(investigation_store):
    service = _service(investigation_store)
    tenant_id = EntityId.generate()

    outcome = service.open_investigation(
        OpenInvestigationCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert outcome.status == InvestigationOutcomeStatus.OPENED
    assert outcome.timeline_id is not None
    assert outcome.entry_count == 0


def test_open_investigation_without_role_raises_forbidden(investigation_store):
    service = _service(investigation_store)
    with pytest.raises(ApplicationForbiddenError):
        service.open_investigation(
            OpenInvestigationCommand(
                tenant_id=EntityId.generate(),
                scope_type=TimelineScopeType.ENTITY,
                scope_ref="entity-1",
                actor_roles=(),
            )
        )


def test_open_investigation_when_already_open_is_rejected(investigation_store):
    service = _service(investigation_store)
    tenant_id = EntityId.generate()
    cmd = OpenInvestigationCommand(
        tenant_id=tenant_id,
        scope_type=TimelineScopeType.ENTITY,
        scope_ref="entity-1",
        actor_roles=EXECUTOR_ROLES,
    )
    first = service.open_investigation(cmd)
    second = service.open_investigation(cmd)

    assert first.status == InvestigationOutcomeStatus.OPENED
    assert second.status == InvestigationOutcomeStatus.REJECTED
    assert second.failures[0].error_type == "InvestigationAlreadyOpenError"


# ---------------------------------------------------------------------------
# alert attachment / timeline ordering
# ---------------------------------------------------------------------------


def test_attach_alert_opens_investigation_when_none_exists(investigation_store):
    service = _service(investigation_store)
    tenant_id = EntityId.generate()
    alert = make_alert(tenant_id)

    outcome = service.attach_alert(
        AttachAlertCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            alert=alert,
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert outcome.status == InvestigationOutcomeStatus.OPENED
    assert outcome.entry_count == 1


def test_attach_second_alert_updates_existing_investigation(investigation_store):
    service = _service(investigation_store)
    tenant_id = EntityId.generate()
    first_alert = make_alert(tenant_id, dedup_key="dedup-1")
    second_alert = make_alert(tenant_id, dedup_key="dedup-2")

    first = service.attach_alert(
        AttachAlertCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            alert=first_alert,
            actor_roles=EXECUTOR_ROLES,
        )
    )
    second = service.attach_alert(
        AttachAlertCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            alert=second_alert,
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert first.status == InvestigationOutcomeStatus.OPENED
    assert second.status == InvestigationOutcomeStatus.UPDATED
    assert second.timeline_id == first.timeline_id
    assert second.entry_count == 2


def test_timeline_entries_are_chronologically_ordered_regardless_of_attach_order(
    investigation_store,
):
    """M44D special review: ordering delegated to InvestigationTimeline
    — attaching alerts out of chronological order must still read back
    in occurred_at order."""
    service = _service(investigation_store)
    tenant_id = EntityId.generate()

    later_alert = Alert.raise_alert(
        alert_id=AlertId.generate(),
        tenant_id=tenant_id,
        dedup_key="dedup-later",
        severity=AlertSeverity.HIGH,
        source_kind=AlertSourceKind.CORRELATION,
        source_ref="session-1",
        now=NOW + timedelta(minutes=10),
    )
    earlier_alert = Alert.raise_alert(
        alert_id=AlertId.generate(),
        tenant_id=tenant_id,
        dedup_key="dedup-earlier",
        severity=AlertSeverity.HIGH,
        source_kind=AlertSourceKind.CORRELATION,
        source_ref="session-1",
        now=NOW,
    )

    service.attach_alert(
        AttachAlertCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            alert=later_alert,
            actor_roles=EXECUTOR_ROLES,
        )
    )
    service.attach_alert(
        AttachAlertCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            alert=earlier_alert,
            actor_roles=EXECUTOR_ROLES,
        )
    )

    timeline = investigation_store.find_open_timeline(tenant_id, TimelineScopeType.ENTITY, "entity-1")
    assert [e.event_id for e in timeline.entries] == [
        str(earlier_alert.alert_id),
        str(later_alert.alert_id),
    ]


def test_attach_alert_tenant_mismatch_is_rejected(investigation_store):
    service = _service(investigation_store)
    tenant_id = EntityId.generate()
    other_tenant_alert = make_alert(EntityId.generate())

    outcome = service.attach_alert(
        AttachAlertCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            alert=other_tenant_alert,
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert outcome.status == InvestigationOutcomeStatus.REJECTED
    assert outcome.failures[0].error_type == "TenantContextMismatchError"


# ---------------------------------------------------------------------------
# duplicate attachment
# ---------------------------------------------------------------------------


def test_attaching_same_alert_twice_is_rejected_not_double_counted(investigation_store):
    service = _service(investigation_store)
    tenant_id = EntityId.generate()
    alert = make_alert(tenant_id)
    cmd = AttachAlertCommand(
        tenant_id=tenant_id,
        scope_type=TimelineScopeType.ENTITY,
        scope_ref="entity-1",
        alert=alert,
        actor_roles=EXECUTOR_ROLES,
    )

    first = service.attach_alert(cmd)
    second = service.attach_alert(cmd)

    assert first.status == InvestigationOutcomeStatus.OPENED
    assert second.status == InvestigationOutcomeStatus.REJECTED
    assert second.failures[0].error_type == "DuplicateTimelineEntryError"
    timeline = investigation_store.find_open_timeline(tenant_id, TimelineScopeType.ENTITY, "entity-1")
    assert len(timeline.entries) == 1


# ---------------------------------------------------------------------------
# evaluation-driven attachment
# ---------------------------------------------------------------------------


def test_evaluation_opens_investigation(investigation_store):
    registry = InMemoryInvestigationEvaluatorRegistry()
    registry.register(FakeInvestigationEvaluator("inv-rule-1", evaluator=investigates()))
    service = _service(investigation_store, registry)
    tenant_id = EntityId.generate()

    outcome = service.evaluate_alert(
        EvaluateAlertCommand(
            tenant_id=tenant_id, item=make_evaluation_input(), actor_roles=EXECUTOR_ROLES
        )
    )

    assert outcome.status == InvestigationOutcomeStatus.OPENED
    assert outcome.decision_reason == "high severity correlated alert"


def test_evaluation_rejects_when_should_not_investigate(investigation_store):
    registry = InMemoryInvestigationEvaluatorRegistry()
    registry.register(FakeInvestigationEvaluator("inv-rule-1", evaluator=does_not_investigate()))
    service = _service(investigation_store, registry)
    tenant_id = EntityId.generate()

    outcome = service.evaluate_alert(
        EvaluateAlertCommand(
            tenant_id=tenant_id, item=make_evaluation_input(), actor_roles=EXECUTOR_ROLES
        )
    )

    assert outcome.status == InvestigationOutcomeStatus.REJECTED
    assert outcome.timeline_id is None
    assert investigation_store.writes == []


# ---------------------------------------------------------------------------
# closed investigation
# ---------------------------------------------------------------------------


def test_attach_after_scope_no_longer_open_creates_fresh_investigation(investigation_store):
    """M44D §7 'closed investigation' validation: IInvestigationProvider
    only ever returns an *open* investigation — once the store no
    longer considers one open for a scope (e.g. it was closed by
    whatever future component owns closing), a new alert for that
    scope opens a fresh one rather than erroring."""
    service = _service(investigation_store)
    tenant_id = EntityId.generate()
    first_alert = make_alert(tenant_id, dedup_key="dedup-1")

    first = service.attach_alert(
        AttachAlertCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            alert=first_alert,
            actor_roles=EXECUTOR_ROLES,
        )
    )
    # Simulate the investigation having been closed elsewhere: the
    # provider no longer returns it as "open".
    investigation_store.by_scope.clear()

    second_alert = make_alert(tenant_id, dedup_key="dedup-2")
    second = service.attach_alert(
        AttachAlertCommand(
            tenant_id=tenant_id,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            alert=second_alert,
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert first.status == InvestigationOutcomeStatus.OPENED
    assert second.status == InvestigationOutcomeStatus.OPENED
    assert second.timeline_id != first.timeline_id


# ---------------------------------------------------------------------------
# unsupported evaluator / evaluator exceptions
# ---------------------------------------------------------------------------


def test_unsupported_evaluator(investigation_store):
    service = _service(investigation_store)  # empty registry
    tenant_id = EntityId.generate()

    outcome = service.evaluate_alert(
        EvaluateAlertCommand(
            tenant_id=tenant_id, item=make_evaluation_input(), actor_roles=EXECUTOR_ROLES
        )
    )

    assert outcome.status == InvestigationOutcomeStatus.UNSUPPORTED_EVALUATOR


def test_evaluator_exception_produces_failed_outcome(investigation_store):
    def _explode(alert):
        raise RuntimeError("malformed evaluator logic")

    registry = InMemoryInvestigationEvaluatorRegistry()
    registry.register(FakeInvestigationEvaluator("inv-rule-1", evaluator=_explode))
    service = _service(investigation_store, registry)
    tenant_id = EntityId.generate()

    outcome = service.evaluate_alert(
        EvaluateAlertCommand(
            tenant_id=tenant_id, item=make_evaluation_input(), actor_roles=EXECUTOR_ROLES
        )
    )

    assert outcome.status == InvestigationOutcomeStatus.FAILED
    assert outcome.failures[0].error_type == "RuntimeError"
    assert investigation_store.writes == []


def test_malformed_schema_version_is_rejected(investigation_store):
    service = _service(investigation_store)
    tenant_id = EntityId.generate()
    item = make_evaluation_input(schema_version_raw="garbage")

    outcome = service.evaluate_alert(
        EvaluateAlertCommand(tenant_id=tenant_id, item=item, actor_roles=EXECUTOR_ROLES)
    )

    assert outcome.status == InvestigationOutcomeStatus.REJECTED


# ---------------------------------------------------------------------------
# batch evaluation
# ---------------------------------------------------------------------------


def test_batch_all_succeed(investigation_store):
    registry = InMemoryInvestigationEvaluatorRegistry()
    registry.register(FakeInvestigationEvaluator("inv-rule-1", evaluator=investigates()))
    service = _service(investigation_store, registry)
    tenant_id = EntityId.generate()
    items = tuple(make_evaluation_input() for _ in range(3))

    result = service.evaluate_batch(
        EvaluateBatchCommand(tenant_id=tenant_id, items=items, actor_roles=EXECUTOR_ROLES)
    )

    assert result.status == InvestigationOutcomeStatus.SUCCEEDED
    assert result.opened_or_updated_count == 3


def test_batch_partial_failure(investigation_store):
    registry = InMemoryInvestigationEvaluatorRegistry()
    registry.register(FakeInvestigationEvaluator("inv-rule-1", evaluator=investigates()))
    service = _service(investigation_store, registry)
    tenant_id = EntityId.generate()
    items = (
        make_evaluation_input(investigation_rule_id="inv-rule-1"),
        make_evaluation_input(investigation_rule_id="unregistered-rule"),
    )

    result = service.evaluate_batch(
        EvaluateBatchCommand(tenant_id=tenant_id, items=items, actor_roles=EXECUTOR_ROLES)
    )

    assert result.status == InvestigationOutcomeStatus.PARTIALLY_SUCCEEDED
    assert result.opened_or_updated_count == 1
    assert result.failed_count == 0  # unsupported evaluator, not FAILED


def test_batch_empty_raises(investigation_store):
    service = _service(investigation_store)
    with pytest.raises(EmptyBatchInvestigationError):
        service.evaluate_batch(
            EvaluateBatchCommand(
                tenant_id=EntityId.generate(), items=(), actor_roles=EXECUTOR_ROLES
            )
        )


def test_batch_without_role_raises_forbidden(investigation_store):
    service = _service(investigation_store)
    with pytest.raises(ApplicationForbiddenError):
        service.evaluate_batch(
            EvaluateBatchCommand(
                tenant_id=EntityId.generate(),
                items=(make_evaluation_input(),),
                actor_roles=(),
            )
        )


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_investigation_outcome_is_frozen(investigation_store):
    service = _service(investigation_store)
    outcome = service.open_investigation(
        OpenInvestigationCommand(
            tenant_id=EntityId.generate(),
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            actor_roles=EXECUTOR_ROLES,
        )
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.status = InvestigationOutcomeStatus.REJECTED  # type: ignore[misc]
