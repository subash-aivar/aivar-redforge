"""Campaign lifecycle invariants — state machine, quorum, sealing."""

from __future__ import annotations

from uuid import uuid4

import pytest

from campaign.domain.aggregates.campaign import Campaign
from campaign.domain.events.campaign_events import (
    CampaignApprovalGranted,
    CampaignArchived,
    CampaignCreated,
    CampaignFailed,
    CampaignPaused,
    CampaignResumed,
    CampaignStarted,
    CampaignSubmittedForApproval,
)
from campaign.domain.exceptions.domain_exceptions import (
    ArchivedImmutabilityViolation,
    DuplicateApproval,
    InvalidArgument,
    InvalidStateTransition,
    InvariantViolation,
    ObjectiveSealedViolation,
    TenantMismatch,
)
from campaign.domain.value_objects.enums import CampaignKind, CampaignState
from campaign.domain.value_objects.identifiers import CampaignInstanceId, TenantId
from tests.campaign.conftest import (
    add_target_rule,
    advance,
    make_campaign,
    make_objective,
)


class TestCampaignCreation:
    def test_create_emits_created_event(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now)
        events = campaign.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], CampaignCreated)

    def test_create_starts_in_draft_state(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now)
        assert campaign.state == CampaignState.DRAFT

    def test_create_with_empty_name_raises(self, tenant_id, now) -> None:
        from campaign.domain.aggregates.campaign import Campaign
        from campaign.domain.value_objects.campaign_vos import (
            ApprovalPolicy,
            CampaignSafetyPolicyVO,
            EngagementRef,
        )
        from campaign.domain.value_objects.enums import CampaignClassification
        from campaign.domain.value_objects.identifiers import CampaignId

        with pytest.raises(InvalidArgument, match="name"):
            Campaign.create(
                campaign_id=CampaignId.generate(),
                tenant_id=tenant_id,
                name="   ",
                classification=CampaignClassification.FULL_KILL_CHAIN,
                kind=CampaignKind.ONE_SHOT,
                owner_id="owner",
                safety_policy=CampaignSafetyPolicyVO(
                    max_concurrent_actions=5,
                    auto_abort_on_detection=False,
                    auto_abort_on_objective_failure=False,
                    blast_radius_ceiling="Probe",
                ),
                approval_policy=ApprovalPolicy(required_approver_count=1),
                engagement_ref=EngagementRef(engagement_id=uuid4(), tenant_id=tenant_id.value),
                now=now,
            )


class TestSubmitForApproval:
    def test_submit_seals_objectives(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        objective = make_objective()
        add_target_rule(campaign, tenant_id, now)
        campaign.add_objective(tenant_id=tenant_id, objective=objective, now=now)
        campaign.pop_events()

        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        assert campaign.state == CampaignState.PENDING_APPROVAL
        assert all(obj.sealed for obj in campaign.objectives)
        events = campaign.pop_events()
        assert any(isinstance(e, CampaignSubmittedForApproval) for e in events)

    def test_submit_without_engagement_ref_raises(self, tenant_id, now) -> None:
        from campaign.domain.aggregates.campaign import Campaign
        from campaign.domain.value_objects.campaign_vos import (
            ApprovalPolicy,
            CampaignSafetyPolicyVO,
        )
        from campaign.domain.value_objects.enums import CampaignClassification
        from campaign.domain.value_objects.identifiers import CampaignId

        campaign = Campaign.create(
            campaign_id=CampaignId.generate(),
            tenant_id=tenant_id,
            name="No engagement",
            classification=CampaignClassification.DETECTION_TUNING,
            kind=CampaignKind.ONE_SHOT,
            owner_id="owner",
            safety_policy=CampaignSafetyPolicyVO(
                max_concurrent_actions=5,
                auto_abort_on_detection=False,
                auto_abort_on_objective_failure=False,
                blast_radius_ceiling="Probe",
            ),
            approval_policy=ApprovalPolicy(required_approver_count=1),
            engagement_ref=None,
            now=now,
        )
        add_target_rule(campaign, tenant_id, now)
        with pytest.raises(InvariantViolation, match="engagement_ref"):
            campaign.submit_for_approval(tenant_id=tenant_id, now=now)

    def test_submit_without_target_rules_raises(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvariantViolation, match="target_selection_rules"):
            campaign.submit_for_approval(tenant_id=tenant_id, now=now)

    def test_add_objective_after_sealing_raises(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        add_target_rule(campaign, tenant_id, now)
        obj = make_objective()
        campaign.add_objective(tenant_id=tenant_id, objective=obj, now=now)
        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))

        new_obj = make_objective(description="new objective")
        with pytest.raises(ObjectiveSealedViolation):
            campaign.add_objective(
                tenant_id=tenant_id, objective=new_obj, now=advance(now, minutes=2)
            )


class TestApprovalWorkflow:
    def test_quorum_met_transitions_to_approved(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        add_target_rule(campaign, tenant_id, now)
        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        campaign.pop_events()

        approval = campaign.grant_approval(
            tenant_id=tenant_id,
            approver_id="approver-1",
            signature="sig-1",
            now=advance(now, minutes=2),
        )
        assert approval is not None
        assert campaign.state == CampaignState.APPROVED
        events = campaign.pop_events()
        assert any(isinstance(e, CampaignApprovalGranted) for e in events)

    def test_duplicate_approval_raises(self, tenant_id, now) -> None:
        campaign = make_campaign(
            tenant_id=tenant_id, now=now, required_approver_count=2, pop_events=True
        )
        add_target_rule(campaign, tenant_id, now)
        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        campaign.grant_approval(
            tenant_id=tenant_id,
            approver_id="approver-1",
            signature="sig-1",
            now=advance(now, minutes=2),
        )
        with pytest.raises(DuplicateApproval):
            campaign.grant_approval(
                tenant_id=tenant_id,
                approver_id="approver-1",
                signature="sig-2",
                now=advance(now, minutes=3),
            )

    def test_quorum_requires_two_approvers(self, tenant_id, now) -> None:
        campaign = make_campaign(
            tenant_id=tenant_id, now=now, required_approver_count=2, pop_events=True
        )
        add_target_rule(campaign, tenant_id, now)
        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        campaign.grant_approval(
            tenant_id=tenant_id,
            approver_id="approver-1",
            signature="sig-1",
            now=advance(now, minutes=2),
        )
        assert campaign.state == CampaignState.PENDING_APPROVAL

        campaign.grant_approval(
            tenant_id=tenant_id,
            approver_id="approver-2",
            signature="sig-2",
            now=advance(now, minutes=3),
        )
        assert campaign.state == CampaignState.APPROVED

    def test_revoke_drops_quorum_reverts_to_pending(self, tenant_id, now) -> None:
        campaign = make_campaign(
            tenant_id=tenant_id, now=now, required_approver_count=2, pop_events=True
        )
        add_target_rule(campaign, tenant_id, now)
        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        campaign.grant_approval(
            tenant_id=tenant_id, approver_id="a1", signature="s1", now=advance(now, minutes=2)
        )
        campaign.grant_approval(
            tenant_id=tenant_id, approver_id="a2", signature="s2", now=advance(now, minutes=3)
        )
        assert campaign.state == CampaignState.APPROVED

        campaign.revoke_approval(
            tenant_id=tenant_id,
            approver_id="a1",
            revoked_by="admin",
            now=advance(now, minutes=4),
        )
        assert campaign.state == CampaignState.PENDING_APPROVAL


class TestCampaignExecution:
    def _approved_campaign(self, tenant_id: TenantId, now) -> Campaign:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        add_target_rule(campaign, tenant_id, now)
        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        campaign.grant_approval(
            tenant_id=tenant_id,
            approver_id="approver-1",
            signature="sig-1",
            now=advance(now, minutes=2),
        )
        campaign.pop_events()
        return campaign

    def test_start_instance_transitions_to_running(self, tenant_id, now) -> None:
        campaign = self._approved_campaign(tenant_id, now)
        instance_id = CampaignInstanceId.generate()
        campaign.start_instance(
            tenant_id=tenant_id,
            instance_id=instance_id,
            resolved_target_count=3,
            now=advance(now, minutes=5),
        )
        assert campaign.state == CampaignState.RUNNING
        events = campaign.pop_events()
        started = [e for e in events if isinstance(e, CampaignStarted)]
        assert len(started) == 1
        assert started[0].resolved_target_count == 3

    def test_pause_from_running(self, tenant_id, now) -> None:
        campaign = self._approved_campaign(tenant_id, now)
        campaign.start_instance(
            tenant_id=tenant_id,
            instance_id=CampaignInstanceId.generate(),
            resolved_target_count=1,
            now=advance(now, minutes=5),
        )
        campaign.pop_events()
        campaign.pause(tenant_id=tenant_id, reason="detection found", now=advance(now, minutes=10))
        assert campaign.state == CampaignState.PAUSED
        events = campaign.pop_events()
        assert any(isinstance(e, CampaignPaused) for e in events)

    def test_resume_from_paused(self, tenant_id, now) -> None:
        campaign = self._approved_campaign(tenant_id, now)
        campaign.start_instance(
            tenant_id=tenant_id,
            instance_id=CampaignInstanceId.generate(),
            resolved_target_count=1,
            now=advance(now, minutes=5),
        )
        campaign.pause(tenant_id=tenant_id, reason="paused", now=advance(now, minutes=10))
        campaign.pop_events()
        campaign.resume(tenant_id=tenant_id, now=advance(now, minutes=15))
        assert campaign.state == CampaignState.RUNNING
        assert any(isinstance(e, CampaignResumed) for e in campaign.pop_events())

    def test_fail_from_running(self, tenant_id, now) -> None:
        campaign = self._approved_campaign(tenant_id, now)
        instance_id = CampaignInstanceId.generate()
        campaign.start_instance(
            tenant_id=tenant_id,
            instance_id=instance_id,
            resolved_target_count=1,
            now=advance(now, minutes=5),
        )
        campaign.pop_events()
        campaign.fail(
            tenant_id=tenant_id,
            instance_id=instance_id,
            reason="safety policy violated",
            now=advance(now, minutes=10),
        )
        assert campaign.state == CampaignState.FAILED
        events = campaign.pop_events()
        failed = [e for e in events if isinstance(e, CampaignFailed)]
        assert len(failed) == 1

    def test_archive_from_completed(self, tenant_id, now) -> None:
        campaign = self._approved_campaign(tenant_id, now)
        instance_id = CampaignInstanceId.generate()
        campaign.start_instance(
            tenant_id=tenant_id,
            instance_id=instance_id,
            resolved_target_count=1,
            now=advance(now, minutes=5),
        )
        campaign.complete(
            tenant_id=tenant_id,
            instance_id=instance_id,
            composite_outcome="FullSuccess",
            now=advance(now, minutes=60),
        )
        campaign.pop_events()
        campaign.archive(tenant_id=tenant_id, now=advance(now, hours=2))
        assert campaign.state == CampaignState.ARCHIVED
        assert any(isinstance(e, CampaignArchived) for e in campaign.pop_events())

    def test_archived_campaign_is_immutable(self, tenant_id, now) -> None:
        campaign = self._approved_campaign(tenant_id, now)
        instance_id = CampaignInstanceId.generate()
        campaign.start_instance(
            tenant_id=tenant_id,
            instance_id=instance_id,
            resolved_target_count=1,
            now=advance(now, minutes=5),
        )
        campaign.complete(
            tenant_id=tenant_id,
            instance_id=instance_id,
            composite_outcome="FullSuccess",
            now=advance(now, minutes=60),
        )
        campaign.archive(tenant_id=tenant_id, now=advance(now, hours=2))

        with pytest.raises(ArchivedImmutabilityViolation):
            campaign.archive(tenant_id=tenant_id, now=advance(now, hours=3))


class TestTenantIsolation:
    def test_wrong_tenant_raises(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        other_tenant = TenantId(uuid4())
        with pytest.raises(TenantMismatch):
            add_target_rule(campaign, other_tenant, now)

    def test_grant_approval_wrong_tenant_raises(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        add_target_rule(campaign, tenant_id, now)
        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        other_tenant = TenantId(uuid4())
        with pytest.raises(TenantMismatch):
            campaign.grant_approval(
                tenant_id=other_tenant,
                approver_id="approver-1",
                signature="sig-1",
                now=advance(now, minutes=2),
            )


class TestInvalidTransitions:
    def test_cannot_start_draft_campaign(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvalidStateTransition):
            campaign.start_instance(
                tenant_id=tenant_id,
                instance_id=CampaignInstanceId.generate(),
                resolved_target_count=1,
                now=now,
            )

    def test_cannot_pause_empty_reason(self, tenant_id, now) -> None:
        campaign = make_campaign(tenant_id=tenant_id, now=now, pop_events=True)
        add_target_rule(campaign, tenant_id, now)
        campaign.submit_for_approval(tenant_id=tenant_id, now=advance(now, minutes=1))
        campaign.grant_approval(
            tenant_id=tenant_id,
            approver_id="approver-1",
            signature="sig-1",
            now=advance(now, minutes=2),
        )
        campaign.start_instance(
            tenant_id=tenant_id,
            instance_id=CampaignInstanceId.generate(),
            resolved_target_count=1,
            now=advance(now, minutes=5),
        )
        with pytest.raises(InvalidArgument, match="reason"):
            campaign.pause(tenant_id=tenant_id, reason="  ", now=advance(now, minutes=10))
