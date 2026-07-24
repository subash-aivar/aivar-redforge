"""Additional automated_action coverage for M35 phase exit criteria."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import (
    CancelExecution,
    TriggerPlaybookExecution,
)
from automated_action.application.ports.lookups import (
    PlaybookLookupView,
    PlaybookStepView,
    PolicyLookupView,
)
from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.aggregates.rollback_record import RollbackRecord
from automated_action.domain.entities.escalation_request import EscalationRequest
from automated_action.domain.exceptions.domain_exceptions import (
    InvalidExecutionTransition,
    PolicyDenied,
)
from automated_action.domain.services.automation_execution_service import AutomationExecutionService
from automated_action.domain.services.execution_evidence_service import ExecutionEvidenceService
from automated_action.domain.services.execution_metrics_service import ExecutionMetricsService
from automated_action.domain.services.execution_policy_service import (
    ExecutionPolicyService,
    PolicySnapshot,
)
from automated_action.domain.services.execution_replay_service import ExecutionReplayService
from automated_action.domain.services.rollback_eligibility_service import RollbackEligibilityService
from automated_action.domain.value_objects.enums import (
    ActionImpactLevel,
    ActionOutcome,
    ActionRecordStatus,
    ConnectorFailureMode,
    EscalationResolution,
    ExecutionStatus,
    RollbackStatus,
)
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    TenantId,
)
from automated_action.domain.value_objects.refs import PlaybookRef, TriggerRef
from automated_action.infrastructure.container import AutomatedActionContainer
from automated_action.infrastructure.projectors.kg_projector import AutomationKGProjector
from redforge.shared.identifiers import EntityId


def _exec(
    *,
    status: ExecutionStatus = ExecutionStatus.PENDING,
    impact: ActionImpactLevel = ActionImpactLevel.LOW,
) -> AutomationExecution:
    return AutomationExecution(
        AutomationExecutionId.generate(),
        TenantId.generate(),
        PlaybookRef(str(uuid4()), 1, "hash"),
        TriggerRef("MANUAL", "manual", "e1"),
        status,
        datetime.now(UTC),
        "op1",
        0,
        2,
        impact,
    )


@pytest.mark.parametrize("status", list(ExecutionStatus))
def test_execution_status_values(status: ExecutionStatus) -> None:
    assert status.value == status.name


@pytest.mark.parametrize("status", list(ActionRecordStatus))
def test_action_record_status(status: ActionRecordStatus) -> None:
    assert status.value == status.name


@pytest.mark.parametrize("outcome", list(ActionOutcome))
def test_action_outcomes(outcome: ActionOutcome) -> None:
    assert outcome.value == outcome.name


@pytest.mark.parametrize("status", list(RollbackStatus))
def test_rollback_statuses(status: RollbackStatus) -> None:
    assert status.value == status.name


@pytest.mark.parametrize("res", list(EscalationResolution))
def test_escalation_resolutions(res: EscalationResolution) -> None:
    assert res.value == res.name


@pytest.mark.parametrize("mode", list(ConnectorFailureMode))
def test_connector_failure_modes(mode: ConnectorFailureMode) -> None:
    assert isinstance(mode.value, str)


@pytest.mark.parametrize(
    ("level", "needs"),
    [
        (ActionImpactLevel.LOW, False),
        (ActionImpactLevel.MEDIUM, False),
        (ActionImpactLevel.HIGH, True),
        (ActionImpactLevel.CRITICAL, True),
    ],
)
def test_needs_runtime_auth(level: ActionImpactLevel, needs: bool) -> None:
    assert AutomationExecutionService().needs_runtime_auth(level) is needs


@pytest.mark.parametrize(
    ("freeze", "maint", "biz", "in_biz", "exc"),
    [
        (True, False, False, True, PolicyDenied),
        (False, True, False, True, PolicyDenied),
        (False, False, True, False, PolicyDenied),
    ],
)
def test_policy_denies(
    freeze: bool, maint: bool, biz: bool, in_biz: bool, exc: type[Exception]
) -> None:
    with pytest.raises(exc):
        ExecutionPolicyService().evaluate(
            PolicySnapshot(
                False,
                5,
                100,
                change_freeze=freeze,
                maintenance_window=maint,
                business_hours_only=biz,
                in_business_hours=in_biz,
            ),
            running_count=0,
            actions_last_hour=0,
        )


def test_execution_start_complete_fail() -> None:
    ex = _exec()
    ex.start()
    assert ex.status == ExecutionStatus.RUNNING
    events = ex.pop_events()
    assert events
    ex.complete(2)
    assert ex.status == ExecutionStatus.COMPLETED


def test_cannot_start_twice() -> None:
    ex = _exec()
    ex.start()
    with pytest.raises(InvalidExecutionTransition):
        ex.start()


def test_escalate_and_expire() -> None:
    ex = _exec()
    ex.start()
    ex.escalate(1, ActionImpactLevel.HIGH, "soc:commander")
    assert ex.status == ExecutionStatus.AWAITING_AUTHORIZATION
    ex.expire_escalation()
    assert ex.status == ExecutionStatus.FAILED
    assert ex.failure_reason == "ESCALATION_TIMEOUT"


def test_outbox_hash_stable() -> None:
    a = AutomatedActionRecord.hash_parameters({"b": 1, "a": 2})
    b = AutomatedActionRecord.hash_parameters({"a": 2, "b": 1})
    assert a == b


def test_record_complete_fail() -> None:
    rec = AutomatedActionRecord.create_pending(
        TenantId.generate(),
        AutomationExecutionId.generate(),
        1,
        "act",
        "COMM_SLACK",
        "t",
        {"x": 1},
    )
    rec.complete(ActionOutcome.SUCCESS, "ext", 5, rollback_available=True)
    assert rec.status == ActionRecordStatus.COMPLETED
    rec2 = AutomatedActionRecord.create_pending(
        TenantId.generate(),
        AutomationExecutionId.generate(),
        1,
        "act",
        "COMM_SLACK",
        "t",
        {},
    )
    rec2.fail(ConnectorFailureMode.TIMEOUT, 9)
    assert rec2.failure_mode == ConnectorFailureMode.TIMEOUT


def test_rollback_record_lifecycle() -> None:
    rb = RollbackRecord.create(
        TenantId.generate(),
        AutomatedActionRecordId.generate(),
        AutomationExecutionId.generate(),
        "op",
    )
    rb.mark_completed()
    assert rb.rollback_status == RollbackStatus.COMPLETED
    rb2 = RollbackRecord.create(
        TenantId.generate(),
        AutomatedActionRecordId.generate(),
        AutomationExecutionId.generate(),
        "op",
    )
    rb2.mark_failed("x")
    assert rb2.failure_reason == "x"


def test_escalation_request_factory() -> None:
    now = datetime.now(UTC)
    esc = EscalationRequest.create(
        1, ActionImpactLevel.CRITICAL, "incident:ciso", "op", now, now + timedelta(hours=1)
    )
    assert esc.required_role == "incident:ciso"


def test_evidence_and_metrics_replay() -> None:
    ev = ExecutionEvidenceService().capture("e1", ["r1", "r2"])
    assert len(ev.record_ids) == 2
    m = ExecutionMetricsService()
    m.incr("x", 2)
    assert m.counters["x"] == 2.0
    ex = _exec(status=ExecutionStatus.FAILED)
    assert ExecutionReplayService().can_replay(ex) is True


def test_rollback_eligibility_window() -> None:
    rec = AutomatedActionRecord.create_pending(
        TenantId.generate(),
        AutomationExecutionId.generate(),
        1,
        "a",
        "EDR_CROWDSTRIKE",
        "h",
        {},
    )
    rec.complete(ActionOutcome.SUCCESS, "ext", 1, rollback_available=True)
    assert RollbackEligibilityService().is_eligible(rec) is True
    rec.completed_at = datetime.now(UTC) - timedelta(hours=48)
    assert RollbackEligibilityService().is_eligible(rec) is False


def test_kg_projector_events() -> None:
    kg = AutomationKGProjector()

    class PlaybookApproved:
        playbook_id = "p1"
        tenant_id = "t1"
        max_impact_level = "LOW"

    class AutomatedActionRecorded:
        playbook_id = "p1"
        tenant_id = "t1"
        record_id = "r1"
        execution_id = "e1"
        action_type = "a"
        connector_type = "COMM_SLACK"
        outcome = "SUCCESS"

    class AutomationRolledBack:
        original_record_id = "r1"
        rollback_id = "rb1"

    kg.project(PlaybookApproved())
    kg.project(AutomatedActionRecorded())
    kg.project(AutomationRolledBack())
    assert kg.graph.nodes


@pytest.mark.asyncio
async def test_cancel_execution() -> None:
    c = AutomatedActionContainer()
    tenant = EntityId.generate()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "evt-c", "op", ("automation:operator",)
        )
    )
    cancelled = await c.app.cancel(
        CancelExecution(tenant, UUID(ex.execution_id), "cmd", "stop", ("soc:commander",))
    )
    assert cancelled.status == "FAILED"


@pytest.mark.asyncio
async def test_list_and_pending_escalations() -> None:
    c = AutomatedActionContainer()
    tenant = EntityId.generate()
    rows = await c.app.list_executions(tenant, ("playbook:analyst",))
    assert rows == []
    pending = await c.app.pending_escalations(tenant, ("soc:commander",))
    assert pending == []


@pytest.mark.asyncio
async def test_failed_connector_step() -> None:
    c = AutomatedActionContainer()
    tenant = EntityId.generate()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    c.connector_port.fail_next = True
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "evt-f", "op", ("automation:operator",)
        )
    )
    done = await c.app.run_pending_step_loop(tenant, UUID(ex.execution_id))
    assert done.status == "FAILED"


@pytest.mark.asyncio
async def test_policy_lookup_defaults() -> None:
    c = AutomatedActionContainer()
    policy = await c.playbook_lookup.get_policy(str(uuid4()))
    assert isinstance(policy, PolicyLookupView)
    assert policy.max_concurrent_executions == 5


@pytest.mark.asyncio
async def test_outbox_recovery_worker() -> None:
    c = AutomatedActionContainer()
    tenant = TenantId.generate()
    rec = AutomatedActionRecord.create_pending(
        tenant,
        AutomationExecutionId.generate(),
        1,
        "a",
        "COMM_SLACK",
        "t",
        {},
    )
    rec.attempted_at = datetime.now(UTC) - timedelta(minutes=10)
    await c.records.append(rec, tenant)
    recovered = await c.outbox_worker.tick()
    assert recovered == 1
