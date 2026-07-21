"""Campaign aggregate root — M30 red team campaign orchestration lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from campaign.domain.entities.campaign_entities import (
    CampaignApproval,
    CampaignObjective,
    CampaignSchedule,
)
from campaign.domain.events.campaign_events import (
    CampaignApprovalGranted,
    CampaignApprovalRevoked,
    CampaignArchived,
    CampaignCompleted,
    CampaignCreated,
    CampaignFailed,
    CampaignObjectiveAdded,
    CampaignPaused,
    CampaignResumed,
    CampaignScheduled,
    CampaignScheduleFired,
    CampaignStarted,
    CampaignSubmittedForApproval,
    RecurringCampaignPaused,
    ScheduledFireSkipped,
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
from campaign.domain.value_objects.campaign_vos import (
    ApprovalPolicy,
    ApprovalRecord,
    CampaignSafetyPolicyVO,
    EngagementRef,
    TargetSelectionRule,
)
from campaign.domain.value_objects.enums import (
    CampaignClassification,
    CampaignKind,
    CampaignState,
    ObjectiveState,
    QuorumType,
)
from campaign.domain.value_objects.identifiers import (
    CampaignApprovalId,
    CampaignId,
)

if TYPE_CHECKING:
    from datetime import datetime

    from campaign.domain.events.base import BaseDomainEvent
    from campaign.domain.value_objects.identifiers import (
        CampaignInstanceId,
        TenantId,
    )

_ALLOWED_TRANSITIONS: dict[CampaignState, frozenset[CampaignState]] = {
    CampaignState.DRAFT: frozenset({CampaignState.PENDING_APPROVAL}),
    CampaignState.PENDING_APPROVAL: frozenset({CampaignState.APPROVED, CampaignState.DRAFT}),
    CampaignState.APPROVED: frozenset({CampaignState.SCHEDULED, CampaignState.RUNNING}),
    CampaignState.SCHEDULED: frozenset(
        {CampaignState.RUNNING, CampaignState.APPROVED, CampaignState.PAUSED}
    ),
    CampaignState.RUNNING: frozenset(
        {CampaignState.PAUSED, CampaignState.COMPLETED, CampaignState.FAILED}
    ),
    CampaignState.PAUSED: frozenset(
        {CampaignState.RUNNING, CampaignState.SCHEDULED, CampaignState.FAILED}
    ),
    CampaignState.COMPLETED: frozenset({CampaignState.ARCHIVED}),
    CampaignState.FAILED: frozenset({CampaignState.ARCHIVED}),
    CampaignState.ARCHIVED: frozenset(),
}


class Campaign:
    """Formally authorized, time-bounded adversarial simulation campaign.

    M30 is an orchestration platform — Campaign NEVER executes attacks directly.
    All operations require a valid EngagementRef to M29.
    """

    __slots__ = (
        "_pending_events",
        "_version",
        "approval_policy",
        "approvals",
        "campaign_id",
        "campaign_schedule",
        "classification",
        "created_at",
        "engagement_ref",
        "kind",
        "name",
        "objectives",
        "owner_id",
        "safety_policy",
        "state",
        "target_selection_rules",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        campaign_id: CampaignId,
        tenant_id: TenantId,
        name: str,
        classification: CampaignClassification,
        kind: CampaignKind,
        owner_id: str,
        state: CampaignState,
        safety_policy: CampaignSafetyPolicyVO,
        approval_policy: ApprovalPolicy,
        engagement_ref: EngagementRef | None,
        objectives: list[CampaignObjective],
        approvals: list[CampaignApproval],
        target_selection_rules: list[TargetSelectionRule],
        campaign_schedule: CampaignSchedule | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.campaign_id = campaign_id
        self.tenant_id = tenant_id
        self.name = name
        self.classification = classification
        self.kind = kind
        self.owner_id = owner_id
        self.state = state
        self.safety_policy = safety_policy
        self.approval_policy = approval_policy
        self.engagement_ref = engagement_ref
        self.objectives = list(objectives)
        self.approvals = list(approvals)
        self.target_selection_rules = list(target_selection_rules)
        self.campaign_schedule = campaign_schedule
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_not_archived(self) -> None:
        if self.state == CampaignState.ARCHIVED:
            raise ArchivedImmutabilityViolation(str(self.campaign_id))

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: CampaignState) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                to_state.value,
                str(self.campaign_id),
            )
        self.state = to_state

    def active_approvals(self) -> list[CampaignApproval]:
        return [a for a in self.approvals if not a.revoked]

    def quorum_met(self) -> bool:
        active = self.active_approvals()
        count = len(active)
        required = self.approval_policy.required_approver_count
        if self.approval_policy.quorum_type == QuorumType.UNANIMOUS:
            return count >= required
        return count >= required

    @classmethod
    def create(
        cls,
        campaign_id: CampaignId,
        tenant_id: TenantId,
        name: str,
        classification: CampaignClassification,
        kind: CampaignKind,
        owner_id: str,
        safety_policy: CampaignSafetyPolicyVO,
        approval_policy: ApprovalPolicy,
        engagement_ref: EngagementRef | None,
        now: datetime,
    ) -> Campaign:
        if not name.strip():
            raise InvalidArgument("name", "must not be empty")
        if not owner_id.strip():
            raise InvalidArgument("owner_id", "must not be empty")

        campaign = cls(
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            name=name.strip(),
            classification=classification,
            kind=kind,
            owner_id=owner_id.strip(),
            state=CampaignState.DRAFT,
            safety_policy=safety_policy,
            approval_policy=approval_policy,
            engagement_ref=engagement_ref,
            objectives=[],
            approvals=[],
            target_selection_rules=[],
            campaign_schedule=None,
            created_at=now,
            updated_at=now,
            version=1,
        )
        campaign._emit(
            CampaignCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(campaign_id),
                aggregate_type="Campaign",
                classification=classification.value,
                kind=kind.value,
                owner_id=owner_id.strip(),
            )
        )
        return campaign

    def add_objective(
        self,
        tenant_id: TenantId,
        objective: CampaignObjective,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state not in {CampaignState.DRAFT, CampaignState.PENDING_APPROVAL}:
            raise InvalidStateTransition(self.state.value, "add_objective", str(self.campaign_id))
        for existing in self.objectives:
            if existing.sealed:
                raise ObjectiveSealedViolation(str(existing.id))
        self.objectives.append(objective)
        self._mutate(now)
        self._emit(
            CampaignObjectiveAdded(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                objective_id=str(objective.id),
                objective_type=objective.objective_type.value,
            )
        )

    def set_engagement_ref(
        self,
        tenant_id: TenantId,
        ref: EngagementRef,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state not in {CampaignState.DRAFT, CampaignState.PENDING_APPROVAL}:
            raise InvalidStateTransition(
                self.state.value, "set_engagement_ref", str(self.campaign_id)
            )
        self.engagement_ref = ref
        self._mutate(now)

    def add_target_selection_rule(
        self,
        tenant_id: TenantId,
        rule: TargetSelectionRule,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state not in {CampaignState.DRAFT, CampaignState.PENDING_APPROVAL}:
            raise InvalidStateTransition(
                self.state.value, "add_target_selection_rule", str(self.campaign_id)
            )
        self.target_selection_rules.append(rule)
        self._mutate(now)

    def submit_for_approval(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.engagement_ref is None:
            raise InvariantViolation(
                "engagement_ref", "Campaign must have an EngagementRef before approval"
            )
        if not self.target_selection_rules:
            raise InvariantViolation(
                "target_selection_rules",
                "Campaign must have at least one target selection rule",
            )
        if self.kind == CampaignKind.RECURRING and self.campaign_schedule is None:
            raise InvariantViolation("schedule", "Recurring campaign must have a CampaignSchedule")
        if self.kind == CampaignKind.ONE_SHOT and self.campaign_schedule is not None:
            raise InvariantViolation(
                "schedule", "OneShot campaign must not have a CampaignSchedule"
            )
        for objective in self.objectives:
            objective.seal()
        self._transition(CampaignState.PENDING_APPROVAL)
        self._mutate(now)
        self._emit(
            CampaignSubmittedForApproval(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
            )
        )

    def grant_approval(
        self,
        tenant_id: TenantId,
        approver_id: str,
        signature: str,
        now: datetime,
        approval_scope: str = "campaign",
    ) -> CampaignApproval:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != CampaignState.PENDING_APPROVAL:
            raise InvalidStateTransition(self.state.value, "grant_approval", str(self.campaign_id))
        if not approver_id.strip():
            raise InvalidArgument("approver_id", "must not be empty")
        if not signature.strip():
            raise InvalidArgument("signature", "must not be empty")

        for existing in self.active_approvals():
            if (
                existing.record.approver_id == approver_id.strip()
                and existing.record.approval_scope == approval_scope
            ):
                raise DuplicateApproval(approver_id.strip(), str(self.campaign_id))

        record = ApprovalRecord(
            approver_id=approver_id.strip(),
            timestamp=now,
            signature=signature.strip(),
            approval_scope=approval_scope,
        )
        approval = CampaignApproval(
            id=CampaignApprovalId.generate(),
            record=record,
        )
        self.approvals.append(approval)

        quorum_complete = self.quorum_met()
        if quorum_complete:
            self._transition(CampaignState.APPROVED)

        self._mutate(now)
        self._emit(
            CampaignApprovalGranted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                approver_id=approver_id.strip(),
                signature=signature.strip(),
                quorum_met=quorum_complete,
            )
        )
        return approval

    def revoke_approval(
        self,
        tenant_id: TenantId,
        approver_id: str,
        revoked_by: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state not in {
            CampaignState.PENDING_APPROVAL,
            CampaignState.APPROVED,
        }:
            raise InvalidStateTransition(self.state.value, "revoke_approval", str(self.campaign_id))
        found = False
        for approval in self.approvals:
            if not approval.revoked and approval.record.approver_id == approver_id.strip():
                approval.revoked = True
                approval.revoked_at = now
                approval.revoked_by = revoked_by.strip()
                found = True
                break
        if not found:
            raise InvalidArgument("approver_id", "active approval not found")

        if self.state == CampaignState.APPROVED and not self.quorum_met():
            self.state = CampaignState.PENDING_APPROVAL

        self._mutate(now)
        self._emit(
            CampaignApprovalRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                approver_id=approver_id.strip(),
                revoked_by=revoked_by.strip(),
            )
        )

    def schedule(
        self,
        tenant_id: TenantId,
        cron_expression: str,
        execution_window_hours: int,
        now: datetime,
        max_consecutive_failures: int = 3,
        blackout_periods: list[str] | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != CampaignState.APPROVED:
            raise InvalidStateTransition(self.state.value, "schedule", str(self.campaign_id))
        if self.kind not in {CampaignKind.RECURRING, CampaignKind.CONTINUOUS}:
            raise InvariantViolation(
                "kind",
                "Only Recurring or Continuous campaigns can be scheduled",
            )
        if not cron_expression.strip():
            raise InvalidArgument("cron_expression", "must not be empty")
        if execution_window_hours < 1:
            raise InvalidArgument("execution_window_hours", "must be at least 1")

        self.campaign_schedule = CampaignSchedule(
            cron_expression=cron_expression.strip(),
            execution_window_hours=execution_window_hours,
            max_consecutive_failures=max_consecutive_failures,
            blackout_periods=blackout_periods or [],
        )
        self._transition(CampaignState.SCHEDULED)
        self._mutate(now)
        self._emit(
            CampaignScheduled(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                cron_expression=cron_expression.strip(),
            )
        )

    def schedule_one_shot(
        self,
        tenant_id: TenantId,
        fire_at: datetime,
        now: datetime,
    ) -> None:
        """Schedule a one-shot campaign for an absolute fire time."""
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != CampaignState.APPROVED:
            raise InvalidStateTransition(
                self.state.value, "schedule_one_shot", str(self.campaign_id)
            )
        if self.kind != CampaignKind.ONE_SHOT:
            raise InvariantViolation(
                "kind",
                "Only OneShot campaigns can use schedule_one_shot",
            )
        cron_expression = f"ONESHOT:{fire_at.isoformat()}"
        self.campaign_schedule = CampaignSchedule(
            cron_expression=cron_expression,
            execution_window_hours=1,
            max_consecutive_failures=1,
            blackout_periods=[],
        )
        self._transition(CampaignState.SCHEDULED)
        self._mutate(now)
        self._emit(
            CampaignScheduled(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                cron_expression=cron_expression,
            )
        )

    def cancel_schedule(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != CampaignState.SCHEDULED:
            raise InvalidStateTransition(self.state.value, "cancel_schedule", str(self.campaign_id))
        self.campaign_schedule = None
        self._transition(CampaignState.APPROVED)
        self._mutate(now)

    def start_instance(
        self,
        tenant_id: TenantId,
        instance_id: CampaignInstanceId,
        resolved_target_count: int,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state not in {CampaignState.APPROVED, CampaignState.SCHEDULED}:
            raise InvalidStateTransition(self.state.value, "start_instance", str(self.campaign_id))
        self._transition(CampaignState.RUNNING)
        self._mutate(now)
        self._emit(
            CampaignStarted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                instance_id=str(instance_id),
                resolved_target_count=resolved_target_count,
            )
        )

    def pause(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if not reason.strip():
            raise InvalidArgument("reason", "must not be empty")
        self._transition(CampaignState.PAUSED)
        self._mutate(now)
        self._emit(
            CampaignPaused(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                reason=reason.strip(),
            )
        )

    def resume(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        self._transition(CampaignState.RUNNING)
        self._mutate(now)
        self._emit(
            CampaignResumed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
            )
        )

    def complete(
        self,
        tenant_id: TenantId,
        instance_id: CampaignInstanceId,
        composite_outcome: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        self._transition(CampaignState.COMPLETED)
        self._mutate(now)
        self._emit(
            CampaignCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                instance_id=str(instance_id),
                composite_outcome=composite_outcome,
            )
        )

    def fail(
        self,
        tenant_id: TenantId,
        instance_id: CampaignInstanceId,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        self._transition(CampaignState.FAILED)
        self._mutate(now)
        self._emit(
            CampaignFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                instance_id=str(instance_id),
                reason=reason,
            )
        )

    def archive(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state == CampaignState.ARCHIVED:
            raise ArchivedImmutabilityViolation(str(self.campaign_id))
        self._transition(CampaignState.ARCHIVED)
        self._mutate(now)
        self._emit(
            CampaignArchived(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
            )
        )

    def reset_objective_states(self) -> None:
        for obj in self.objectives:
            obj.state = ObjectiveState.PENDING

    # ── Phase 4: Scheduling methods ───────────────────────────────────────────

    def fire_schedule(
        self,
        tenant_id: TenantId,
        run_number: int,
        scheduled_fire_time: datetime,
        now: datetime,
    ) -> None:
        """Record that the recurring schedule has fired; triggers instance creation."""
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state not in {CampaignState.SCHEDULED, CampaignState.APPROVED}:
            raise InvalidStateTransition(self.state.value, "fire_schedule", str(self.campaign_id))
        policy = self.campaign_schedule
        if policy is None:
            raise InvariantViolation(
                str(self.campaign_id),
                "Campaign has no RecurrencePolicy; cannot fire schedule",
            )
        self._mutate(now)
        self._emit(
            CampaignScheduleFired(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                cron_expression=policy.cron_expression,
                scheduled_fire_time=scheduled_fire_time.isoformat(),
                run_number=run_number,
            )
        )

    def skip_scheduled_fire(
        self,
        tenant_id: TenantId,
        reason: str,
        scheduled_fire_time: datetime,
        consecutive_skips: int,
        now: datetime,
    ) -> None:
        """Record a skipped schedule fire (blackout or running instance overlap)."""
        self._assert_tenant(tenant_id)
        self._mutate(now)
        self._emit(
            ScheduledFireSkipped(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                reason=reason,
                scheduled_fire_time=scheduled_fire_time.isoformat(),
                consecutive_skips=consecutive_skips,
            )
        )

    def pause_recurring_due_to_failures(
        self,
        consecutive_failure_count: int,
        now: datetime,
    ) -> None:
        """Pause recurring campaign after max_consecutive_failures reached."""
        if self.state in {CampaignState.COMPLETED, CampaignState.ARCHIVED}:
            return  # Do not transition terminal campaigns
        policy = self.campaign_schedule
        max_fail = policy.max_consecutive_failures if policy else consecutive_failure_count
        allowed_states = {CampaignState.SCHEDULED, CampaignState.RUNNING, CampaignState.APPROVED}
        if self.state not in allowed_states:
            # Allow from any non-archived state
            self.state = CampaignState.PAUSED
        else:
            self._transition(CampaignState.PAUSED)
        self._mutate(now)
        self._emit(
            RecurringCampaignPaused(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
                consecutive_failure_count=consecutive_failure_count,
                max_consecutive_failures=max_fail,
            )
        )

    def resume_recurring(self, tenant_id: TenantId, now: datetime) -> None:
        """Resume a paused recurring campaign; transitions back to Scheduled."""
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != CampaignState.PAUSED:
            raise InvalidStateTransition(
                self.state.value, "resume_recurring", str(self.campaign_id)
            )
        self._transition(CampaignState.SCHEDULED)
        self._mutate(now)
        self._emit(
            CampaignResumed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.campaign_id),
                aggregate_type="Campaign",
            )
        )
