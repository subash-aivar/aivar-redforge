"""Engagement aggregate lifecycle, quality gates, and domain events."""

from __future__ import annotations

import pytest
from tests.engagement.conftest import (
    activate_engagement,
    advance,
    make_engagement,
    make_policy,
    make_target,
    make_window,
    prepare_ready_for_submit,
)

from engagement.domain.events.engagement_events import (
    EngagementActivated,
    EngagementApprovalGranted,
    EngagementArchived,
    EngagementClosed,
    EngagementCreated,
    EngagementSubmittedForApproval,
    EngagementSuspended,
    KillSwitchReleased,
    KillSwitchTriggered,
    RulesOfEngagementVersioned,
    ScopeExpansionRequested,
)
from engagement.domain.exceptions.domain_exceptions import (
    DuplicateApproval,
    InvalidArgument,
    InvalidStateTransition,
    QuorumNotMet,
    ScopeImmutableViolation,
    TenantMismatch,
)
from engagement.domain.value_objects.engagement_vos import (
    compute_scope_hash,
    serialize_target_scope,
)
from engagement.domain.value_objects.enums import (
    EngagementState,
    KillSwitchState,
)
from engagement.domain.value_objects.identifiers import EngagementId


class TestCreate:
    def test_create_starts_draft_and_emits_event(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now)
        assert eng.state == EngagementState.DRAFT
        assert eng.kill_switch_state == KillSwitchState.RELEASED
        events = eng.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], EngagementCreated)

    def test_create_rejects_blank_name(self, tenant_id, now) -> None:
        with pytest.raises(InvalidArgument, match="name"):
            make_engagement(tenant_id=tenant_id, now=now, name="   ")


class TestActivationGates:
    def test_activation_requires_complete_approval_quorum(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=2, pop_events=True)
        prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now)
        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        eng.grant_approval(tenant_id, "approver-1", "sig-1", advance(now, minutes=10))
        assert eng.state == EngagementState.PENDING_APPROVAL
        with pytest.raises(InvalidStateTransition):
            eng.activate(tenant_id, advance(now, minutes=20))

    def test_activation_requires_signed_roe(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now, sign_roe=False)
        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        eng.grant_approval(tenant_id, "approver-1", "sig-1", advance(now, minutes=10))
        assert eng.state == EngagementState.APPROVED
        with pytest.raises(InvalidArgument, match="signed"):
            eng.activate(tenant_id, advance(now, minutes=20))

    def test_quorum_incomplete_blocks_activation_defensive(self, tenant_id, now) -> None:
        """Direct construction: Approved without quorum raises QuorumNotMet."""
        from engagement.domain.aggregates.engagement import Engagement
        from engagement.domain.entities.engagement_entities import (
            RulesOfEngagement,
            TargetScope,
        )
        from engagement.domain.value_objects.engagement_vos import RoeConstraint

        eid = EngagementId.generate()
        targets = [make_target()]
        serialized = serialize_target_scope(targets)
        scope_hash = compute_scope_hash(serialized, 1, now)
        eng = Engagement(
            engagement_id=eid,
            tenant_id=tenant_id,
            name="forced",
            classification=make_engagement(tenant_id=tenant_id, now=now).classification,
            owner_id="owner-1",
            state=EngagementState.APPROVED,
            approval_policy=make_policy(required=2),
            window=make_window(now),
            objectives=None,
            scope=TargetScope(targets=targets),
            roe=RulesOfEngagement(
                version=1,
                constraints=RoeConstraint(allowed_techniques=["T1059"]),
                signed_by="owner-1",
                signature="sig",
                signed_at=now,
            ),
            approvals=[],
            participants=[],
            phases=[],
            kill_switch_state=KillSwitchState.RELEASED,
            scope_hash=scope_hash,
            engagement_version=1,
            pending_scope_expansion=None,
            created_at=now,
            updated_at=now,
            version=1,
        )
        with pytest.raises(QuorumNotMet):
            eng.activate(tenant_id, advance(now, minutes=1))

    def test_activate_arms_kill_switch_and_emits_event(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now)
        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        eng.grant_approval(tenant_id, "approver-1", "sig-1", advance(now, minutes=10))
        eng.pop_events()
        eng.activate(tenant_id, advance(now, minutes=20))
        assert eng.state == EngagementState.ACTIVE
        assert eng.kill_switch_state == KillSwitchState.ARMED
        events = eng.pop_events()
        assert any(isinstance(e, EngagementActivated) for e in events)


class TestScopeImmutability:
    def test_scope_expansion_after_approval_rejected(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        targets = prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now)
        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        eng.grant_approval(tenant_id, "a1", "sig", advance(now, minutes=10))
        assert eng.state == EngagementState.APPROVED
        with pytest.raises(ScopeImmutableViolation):
            eng.define_scope(tenant_id, [*targets, make_target()], advance(now, minutes=15))

    def test_scope_expansion_via_request_cycle(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        activate_engagement(eng, tenant_id=tenant_id, now=now)
        eng.pop_events()
        extra = make_target(display_name="new-asset")
        eng.request_scope_expansion(tenant_id, [extra], advance(now, hours=1))
        assert eng.state == EngagementState.PENDING_APPROVAL
        assert eng.kill_switch_state == KillSwitchState.TRIGGERED
        events = eng.pop_events()
        assert any(isinstance(e, ScopeExpansionRequested) for e in events)
        assert any(isinstance(e, KillSwitchTriggered) for e in events)


class TestDuplicateApproval:
    def test_duplicate_approval_from_same_approver_rejected(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=2, pop_events=True)
        prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now)
        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        eng.grant_approval(tenant_id, "approver-1", "sig-1", advance(now, minutes=10))
        with pytest.raises(DuplicateApproval):
            eng.grant_approval(tenant_id, "approver-1", "sig-2", advance(now, minutes=11))


class TestStateMachine:
    def test_invalid_transitions_raise(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvalidStateTransition):
            eng.activate(tenant_id, now)
        with pytest.raises(InvalidStateTransition):
            eng.archive(tenant_id, now)

    def test_full_lifecycle_events(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1)
        assert isinstance(eng.pop_events()[0], EngagementCreated)

        prepare_ready_for_submit(eng, tenant_id=tenant_id, now=now)
        roe_events = [e for e in eng.pop_events() if isinstance(e, RulesOfEngagementVersioned)]
        assert any(e.signed for e in roe_events)

        eng.submit_for_approval(tenant_id, advance(now, minutes=5))
        assert isinstance(eng.pop_events()[0], EngagementSubmittedForApproval)

        eng.grant_approval(tenant_id, "a1", "sig", advance(now, minutes=10))
        granted = eng.pop_events()[0]
        assert isinstance(granted, EngagementApprovalGranted)
        assert granted.quorum_met is True

        eng.activate(tenant_id, advance(now, minutes=20))
        assert isinstance(eng.pop_events()[0], EngagementActivated)

        eng.suspend(tenant_id, "incident", "ciso", advance(now, hours=1))
        suspend_events = eng.pop_events()
        assert any(isinstance(e, KillSwitchTriggered) for e in suspend_events)
        assert any(isinstance(e, EngagementSuspended) for e in suspend_events)

        eng.release_kill_switch_and_resume(tenant_id, "ciso", advance(now, hours=2))
        resume_events = eng.pop_events()
        assert any(isinstance(e, KillSwitchReleased) for e in resume_events)
        assert eng.state == EngagementState.ACTIVE
        assert eng.kill_switch_state == KillSwitchState.ARMED

        eng.close(tenant_id, advance(now, hours=3), reason="done")
        assert isinstance(eng.pop_events()[0], EngagementClosed)

        eng.archive(tenant_id, advance(now, hours=4))
        assert isinstance(eng.pop_events()[0], EngagementArchived)
        assert eng.state == EngagementState.ARCHIVED

    def test_tenant_mismatch(self, tenant_id, other_tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(TenantMismatch):
            eng.submit_for_approval(other_tenant_id, now)


class TestKillSwitchOnActive:
    def test_kill_switch_armed_when_active(self, tenant_id, now) -> None:
        eng = make_engagement(tenant_id=tenant_id, now=now, required_approvers=1, pop_events=True)
        activate_engagement(eng, tenant_id=tenant_id, now=now)
        assert eng.state == EngagementState.ACTIVE
        assert eng.kill_switch_state == KillSwitchState.ARMED
        assert eng.allows_new_operations() is True
