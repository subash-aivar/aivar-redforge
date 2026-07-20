"""Operation aggregate lifecycle, Critical two-party CISO approval, events."""

from __future__ import annotations

from uuid import uuid4

import pytest
from tests.operation.conftest import (
    add_attack_step,
    advance,
    make_operation,
)

from operation.domain.events.operation_events import (
    OperationAborted,
    OperationApproved,
    OperationCompleted,
    OperationCreated,
    OperationQueued,
    OperationStarted,
    OperationSubmittedForApproval,
)
from operation.domain.exceptions.domain_exceptions import (
    ApprovalAuthorityInsufficient,
    EngagementNotActive,
    InvalidArgument,
    InvalidStateTransition,
)
from operation.domain.value_objects.enums import (
    ImpactCeiling,
    OperationRisk,
    OperationState,
)


class TestCreate:
    def test_create_starts_planning(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now)
        assert op.state == OperationState.PLANNING
        assert op.risk == OperationRisk.LOW
        assert isinstance(op.pop_events()[0], OperationCreated)


class TestCriticalTwoPartyCiso:
    def test_critical_requires_two_distinct_ciso_approvers(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(
            op,
            tenant_id=tenant_id,
            now=now,
            impact=ImpactCeiling.DESTRUCT,
            technique_id=None,
        )
        assert op.risk == OperationRisk.CRITICAL
        op.pop_events()
        op.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        assert isinstance(op.pop_events()[0], OperationSubmittedForApproval)

        ciso_a = uuid4()
        ciso_b = uuid4()
        op.approve(
            tenant_id=tenant_id,
            operator_id=ciso_a,
            authority="CISO",
            signature="sig-a",
            now=advance(now, minutes=2),
        )
        assert op.state == OperationState.PENDING_OPERATION_APPROVAL
        assert isinstance(op.pop_events()[0], OperationApproved)

        with pytest.raises(InvalidArgument, match="already approved"):
            op.approve(
                tenant_id=tenant_id,
                operator_id=ciso_a,
                authority="CISO",
                signature="sig-a2",
                now=advance(now, minutes=3),
            )

        op.approve(
            tenant_id=tenant_id,
            operator_id=ciso_b,
            authority="CISO",
            signature="sig-b",
            now=advance(now, minutes=4),
        )
        assert op.state == OperationState.APPROVED

    def test_critical_rejects_non_ciso_authority(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(
            op, tenant_id=tenant_id, now=now, impact=ImpactCeiling.DESTRUCT, technique_id=None
        )
        op.submit_for_approval(tenant_id=tenant_id, now=now)
        with pytest.raises(ApprovalAuthorityInsufficient):
            op.approve(
                tenant_id=tenant_id,
                operator_id=uuid4(),
                authority="Lead",
                signature="sig",
                now=now,
            )


class TestEngagementGate:
    def test_cannot_queue_if_engagement_not_active(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(op, tenant_id=tenant_id, now=now, technique_id=None)
        op.submit_for_approval(tenant_id=tenant_id, now=now)
        op.approve(
            tenant_id=tenant_id,
            operator_id=uuid4(),
            authority="Lead",
            signature="sig",
            now=now,
        )
        with pytest.raises(EngagementNotActive):
            op.queue(
                tenant_id=tenant_id,
                engagement_is_active=False,
                engagement_state="Suspended",
                now=now,
            )

    def test_queue_and_start_when_active(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(op, tenant_id=tenant_id, now=now, technique_id=None)
        op.submit_for_approval(tenant_id=tenant_id, now=now)
        op.approve(
            tenant_id=tenant_id,
            operator_id=uuid4(),
            authority="Lead",
            signature="sig",
            now=now,
        )
        op.pop_events()
        op.queue(
            tenant_id=tenant_id,
            engagement_is_active=True,
            engagement_state="Active",
            now=now,
        )
        assert isinstance(op.pop_events()[0], OperationQueued)
        op.start(
            tenant_id=tenant_id,
            engagement_is_active=True,
            engagement_state="Active",
            now=advance(now, minutes=1),
        )
        assert op.state == OperationState.RUNNING
        assert isinstance(op.pop_events()[0], OperationStarted)


class TestStateMachine:
    def test_invalid_transitions(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvalidStateTransition):
            op.complete(tenant_id=tenant_id, now=now)
        with pytest.raises(InvalidStateTransition):
            op.queue(
                tenant_id=tenant_id,
                engagement_is_active=True,
                engagement_state="Active",
                now=now,
            )

    def test_abort_from_planning(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        op.abort(
            tenant_id=tenant_id,
            reason="cancelled",
            aborting_authority="lead",
            now=now,
        )
        assert op.state == OperationState.ABORTED
        assert isinstance(op.pop_events()[0], OperationAborted)

    def test_complete_emits_event(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(op, tenant_id=tenant_id, now=now, technique_id=None)
        op.submit_for_approval(tenant_id=tenant_id, now=now)
        op.approve(
            tenant_id=tenant_id,
            operator_id=uuid4(),
            authority="Lead",
            signature="sig",
            now=now,
        )
        op.queue(
            tenant_id=tenant_id,
            engagement_is_active=True,
            engagement_state="Active",
            now=now,
        )
        op.start(
            tenant_id=tenant_id,
            engagement_is_active=True,
            engagement_state="Active",
            now=now,
        )
        op.pop_events()
        op.complete(tenant_id=tenant_id, now=now)
        assert isinstance(op.pop_events()[0], OperationCompleted)
