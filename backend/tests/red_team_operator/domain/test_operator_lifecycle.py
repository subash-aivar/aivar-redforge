"""RedTeamOperator lifecycle, approval authority, and domain events."""

from __future__ import annotations

from uuid import uuid4

import pytest
from tests.red_team_operator.conftest import advance, make_operator

from red_team_operator.domain.events.operator_events import (
    OperatorActivated,
    OperatorAddedToEngagement,
    OperatorClearanceLevelChanged,
    OperatorRemovedFromEngagement,
    OperatorRevoked,
    OperatorSuspended,
)
from red_team_operator.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    OperatorNotAuthorized,
    TenantMismatch,
)
from red_team_operator.domain.value_objects.enums import (
    ApprovalScope,
    ImpactCeiling,
    OperatorClearanceLevel,
    OperatorState,
)


class TestActivate:
    def test_activate_emits_event(self, tenant_id, now) -> None:
        op = make_operator(tenant_id=tenant_id, now=now)
        assert op.state == OperatorState.ACTIVE
        events = op.pop_events()
        assert isinstance(events[0], OperatorActivated)
        assert events[0].clearance_level == OperatorClearanceLevel.L3.value

    def test_l1_cannot_hold_engagement_approval_scope(self, tenant_id, now) -> None:
        with pytest.raises(InvalidArgument, match="approval_scopes"):
            make_operator(
                tenant_id=tenant_id,
                now=now,
                clearance=OperatorClearanceLevel.L1,
                scopes=[ApprovalScope.ENGAGEMENT_APPROVAL],
            )


class TestSuspendedCannotApprove:
    def test_suspended_cannot_authorize_or_approve(self, tenant_id, now) -> None:
        op = make_operator(tenant_id=tenant_id, now=now, pop_events=True)
        op.suspend(
            reason="investigation",
            authority="ciso",
            tenant_id=tenant_id,
            now=advance(now, minutes=1),
        )
        assert op.state == OperatorState.SUSPENDED
        assert isinstance(op.pop_events()[0], OperatorSuspended)

        assert op.can_authorize_impact(ImpactCeiling.OBSERVE) is False
        with pytest.raises(OperatorNotAuthorized):
            op.assert_can_approve(ApprovalScope.ENGAGEMENT_APPROVAL)

    def test_active_can_approve_granted_scope(self, tenant_id, now) -> None:
        op = make_operator(tenant_id=tenant_id, now=now, pop_events=True)
        op.assert_can_approve(ApprovalScope.ENGAGEMENT_APPROVAL)
        assert op.can_authorize_impact(ImpactCeiling.EXPLOIT) is True


class TestL1CannotAuthorizeExploit:
    def test_l1_cannot_authorize_exploit(self, tenant_id, now) -> None:
        op = make_operator(
            tenant_id=tenant_id,
            now=now,
            clearance=OperatorClearanceLevel.L1,
            scopes=[],
            pop_events=True,
        )
        assert op.can_authorize_impact(ImpactCeiling.OBSERVE) is True
        assert op.can_authorize_impact(ImpactCeiling.PROBE) is False
        assert op.can_authorize_impact(ImpactCeiling.EXPLOIT) is False
        assert op.can_authorize_impact(ImpactCeiling.DESTRUCT) is False


class TestStateMachine:
    def test_suspend_then_revoke(self, tenant_id, now) -> None:
        op = make_operator(tenant_id=tenant_id, now=now, pop_events=True)
        eng_id = uuid4()
        op.add_to_engagement(engagement_id=eng_id, tenant_id=tenant_id, now=now)
        op.pop_events()

        op.suspend(reason="pause", authority="mgr", tenant_id=tenant_id, now=now)
        with pytest.raises(InvalidStateTransition):
            op.suspend(reason="again", authority="mgr", tenant_id=tenant_id, now=now)

        op.revoke(reason="terminated", authority="hr", tenant_id=tenant_id, now=now)
        assert op.state == OperatorState.REVOKED
        events = op.pop_events()
        assert any(isinstance(e, OperatorRevoked) for e in events)
        assert any(isinstance(e, OperatorRemovedFromEngagement) for e in events)
        assert op.active_engagements.engagement_ids == ()

    def test_revoked_is_terminal(self, tenant_id, now) -> None:
        op = make_operator(tenant_id=tenant_id, now=now, pop_events=True)
        op.revoke(reason="gone", authority="hr", tenant_id=tenant_id, now=now)
        with pytest.raises(InvalidStateTransition):
            op.suspend(reason="x", authority="y", tenant_id=tenant_id, now=now)

    def test_tenant_mismatch(self, tenant_id, other_tenant_id, now) -> None:
        op = make_operator(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(TenantMismatch):
            op.suspend(
                reason="x",
                authority="y",
                tenant_id=other_tenant_id,
                now=now,
            )


class TestEngagementMembership:
    def test_add_and_remove_emit_events(self, tenant_id, now) -> None:
        op = make_operator(tenant_id=tenant_id, now=now, pop_events=True)
        eng_id = uuid4()
        op.add_to_engagement(engagement_id=eng_id, tenant_id=tenant_id, now=now)
        assert isinstance(op.pop_events()[0], OperatorAddedToEngagement)
        op.remove_from_engagement(engagement_id=eng_id, tenant_id=tenant_id, now=now)
        assert isinstance(op.pop_events()[0], OperatorRemovedFromEngagement)

    def test_suspended_cannot_join_engagement(self, tenant_id, now) -> None:
        op = make_operator(tenant_id=tenant_id, now=now, pop_events=True)
        op.suspend(reason="x", authority="y", tenant_id=tenant_id, now=now)
        with pytest.raises(OperatorNotAuthorized):
            op.add_to_engagement(engagement_id=uuid4(), tenant_id=tenant_id, now=now)


class TestClearanceChange:
    def test_clearance_change_emits_and_drops_scopes(self, tenant_id, now) -> None:
        op = make_operator(
            tenant_id=tenant_id,
            now=now,
            clearance=OperatorClearanceLevel.L3,
            pop_events=True,
        )
        op.change_clearance_level(
            new_level=OperatorClearanceLevel.L2,
            authority="ciso",
            tenant_id=tenant_id,
            now=now,
        )
        assert op.clearance_level == OperatorClearanceLevel.L2
        assert op.approval_authority.scopes == ()
        assert isinstance(op.pop_events()[0], OperatorClearanceLevelChanged)
