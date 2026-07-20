"""Engagement aggregate root — red team governance lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from engagement.domain.entities.engagement_entities import (
    EngagementApproval,
    EngagementParticipant,
    EngagementPhase,
    RulesOfEngagement,
    TargetScope,
)
from engagement.domain.events.engagement_events import (
    EngagementActivated,
    EngagementApprovalGranted,
    EngagementApprovalRevoked,
    EngagementArchived,
    EngagementClosed,
    EngagementCreated,
    EngagementSubmittedForApproval,
    EngagementSuspended,
    KillSwitchReleased,
    KillSwitchTriggered,
    ParticipantAdded,
    ParticipantRemoved,
    RulesOfEngagementVersioned,
    ScopeExpansionApproved,
    ScopeExpansionRequested,
)
from engagement.domain.exceptions.domain_exceptions import (
    ArchivedImmutabilityViolation,
    DuplicateApproval,
    InvalidArgument,
    InvalidStateTransition,
    QuorumNotMet,
    ScopeImmutableViolation,
    TenantMismatch,
)
from engagement.domain.value_objects.engagement_vos import (
    ApprovalPolicy,
    ApprovalRecord,
    RoeConstraint,
    ScopeHash,
    compute_scope_hash,
    serialize_target_scope,
)
from engagement.domain.value_objects.enums import (
    EngagementState,
    KillSwitchState,
    QuorumType,
)
from engagement.domain.value_objects.identifiers import (
    EngagementApprovalId,
    EngagementParticipantId,
    EngagementPhaseId,
)

if TYPE_CHECKING:
    from datetime import datetime

    from engagement.domain.events.base import BaseDomainEvent
    from engagement.domain.value_objects.engagement_vos import (
        EngagementObjectives,
        EngagementWindow,
        TargetRef,
    )
    from engagement.domain.value_objects.enums import EngagementClassification
    from engagement.domain.value_objects.identifiers import EngagementId, TenantId

_ALLOWED_TRANSITIONS: dict[EngagementState, frozenset[EngagementState]] = {
    EngagementState.DRAFT: frozenset({EngagementState.PENDING_APPROVAL}),
    EngagementState.PENDING_APPROVAL: frozenset(
        {EngagementState.APPROVED, EngagementState.DRAFT}
    ),
    EngagementState.APPROVED: frozenset(
        {EngagementState.ACTIVE, EngagementState.SUSPENDED}
    ),
    EngagementState.ACTIVE: frozenset(
        {EngagementState.SUSPENDED, EngagementState.CLOSED}
    ),
    EngagementState.SUSPENDED: frozenset(
        {EngagementState.ACTIVE, EngagementState.CLOSED}
    ),
    EngagementState.CLOSED: frozenset({EngagementState.ARCHIVED}),
    EngagementState.ARCHIVED: frozenset(),
}


class Engagement:
    """Formally authorized, time-bounded adversarial simulation program."""

    __slots__ = (
        "_pending_events",
        "_version",
        "approval_policy",
        "approvals",
        "classification",
        "created_at",
        "engagement_id",
        "engagement_version",
        "kill_switch_state",
        "name",
        "objectives",
        "owner_id",
        "participants",
        "pending_scope_expansion",
        "phases",
        "roe",
        "scope",
        "scope_hash",
        "state",
        "tenant_id",
        "updated_at",
        "window",
    )

    def __init__(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
        name: str,
        classification: EngagementClassification,
        owner_id: str,
        state: EngagementState,
        approval_policy: ApprovalPolicy,
        window: EngagementWindow | None,
        objectives: EngagementObjectives | None,
        scope: TargetScope,
        roe: RulesOfEngagement | None,
        approvals: list[EngagementApproval],
        participants: list[EngagementParticipant],
        phases: list[EngagementPhase],
        kill_switch_state: KillSwitchState,
        scope_hash: ScopeHash | None,
        engagement_version: int,
        pending_scope_expansion: list[TargetRef] | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.engagement_id = engagement_id
        self.tenant_id = tenant_id
        self.name = name
        self.classification = classification
        self.owner_id = owner_id
        self.state = state
        self.approval_policy = approval_policy
        self.window = window
        self.objectives = objectives
        self.scope = scope
        self.roe = roe
        self.approvals = list(approvals)
        self.participants = list(participants)
        self.phases = list(phases)
        self.kill_switch_state = kill_switch_state
        self.scope_hash = scope_hash
        self.engagement_version = engagement_version
        self.pending_scope_expansion = list(pending_scope_expansion or [])
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
        if self.state == EngagementState.ARCHIVED:
            raise ArchivedImmutabilityViolation(str(self.engagement_id))

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: EngagementState) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                to_state.value,
                str(self.engagement_id),
            )
        self.state = to_state

    def is_scope_immutable(self) -> bool:
        return self.state in {
            EngagementState.APPROVED,
            EngagementState.ACTIVE,
            EngagementState.SUSPENDED,
            EngagementState.CLOSED,
            EngagementState.ARCHIVED,
        }

    def allows_new_operations(self) -> bool:
        """Suspended blocks new ops; evidence on in-flight ops is permitted elsewhere."""
        return self.state == EngagementState.ACTIVE and (
            self.kill_switch_state == KillSwitchState.ARMED
        )

    def active_approvals(self) -> list[EngagementApproval]:
        return [a for a in self.approvals if not a.revoked]

    def quorum_met(self) -> bool:
        active = self.active_approvals()
        count = len(active)
        required = self.approval_policy.required_approver_count
        if self.approval_policy.quorum_type == QuorumType.UNANIMOUS:
            return count >= required
        # Majority: at least ceil(required/2) but never less than required_approver_count
        # Policy stores the required count explicitly; majority means count >= required.
        return count >= required

    def allowed_technique_ids(self) -> frozenset[str]:
        if self.roe is None:
            return frozenset()
        return frozenset(self.roe.constraints.allowed_techniques)

    @classmethod
    def create(
        cls,
        engagement_id: EngagementId,
        tenant_id: TenantId,
        name: str,
        classification: EngagementClassification,
        owner_id: str,
        approval_policy: ApprovalPolicy,
        now: datetime,
    ) -> Engagement:
        if not name.strip():
            raise InvalidArgument("name", "must not be empty")
        if not owner_id.strip():
            raise InvalidArgument("owner_id", "must not be empty")
        engagement = cls(
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            name=name.strip(),
            classification=classification,
            owner_id=owner_id.strip(),
            state=EngagementState.DRAFT,
            approval_policy=approval_policy,
            window=None,
            objectives=None,
            scope=TargetScope(targets=[]),
            roe=None,
            approvals=[],
            participants=[],
            phases=[],
            kill_switch_state=KillSwitchState.RELEASED,
            scope_hash=None,
            engagement_version=1,
            pending_scope_expansion=None,
            created_at=now,
            updated_at=now,
            version=1,
        )
        engagement._emit(
            EngagementCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(engagement_id),
                aggregate_type="Engagement",
                classification=classification.value,
                owner_id=owner_id.strip(),
            )
        )
        return engagement

    def define_scope(
        self,
        tenant_id: TenantId,
        targets: list[TargetRef],
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.is_scope_immutable():
            raise ScopeImmutableViolation(str(self.engagement_id))
        if self.state not in {EngagementState.DRAFT, EngagementState.PENDING_APPROVAL}:
            raise InvalidStateTransition(
                self.state.value, "define_scope", str(self.engagement_id)
            )
        self.scope = TargetScope(targets=list(targets))
        self.scope_hash = None
        self._mutate(now)

    def set_roe(
        self,
        tenant_id: TenantId,
        constraints: RoeConstraint,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state in {
            EngagementState.ACTIVE,
            EngagementState.CLOSED,
            EngagementState.ARCHIVED,
        }:
            raise InvalidStateTransition(
                self.state.value, "set_roe", str(self.engagement_id)
            )
        next_version = 1 if self.roe is None else self.roe.version + 1
        self.roe = RulesOfEngagement(
            version=next_version,
            constraints=constraints,
            signed_by=None,
            signature=None,
            signed_at=None,
        )
        self._mutate(now)
        self._emit(
            RulesOfEngagementVersioned(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                roe_version=next_version,
                signed=False,
            )
        )

    def sign_roe(
        self,
        tenant_id: TenantId,
        owner_id: str,
        signature: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.roe is None:
            raise InvalidArgument("roe", "RulesOfEngagement must be set before signing")
        if owner_id.strip() != self.owner_id:
            raise InvalidArgument("owner_id", "only engagement owner may sign RoE")
        if not signature.strip():
            raise InvalidArgument("signature", "must not be empty")
        self.roe.signed_by = owner_id.strip()
        self.roe.signature = signature.strip()
        self.roe.signed_at = now
        self._mutate(now)
        self._emit(
            RulesOfEngagementVersioned(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                roe_version=self.roe.version,
                signed=True,
            )
        )

    def set_window(
        self,
        tenant_id: TenantId,
        window: EngagementWindow,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state in {EngagementState.CLOSED, EngagementState.ARCHIVED}:
            raise InvalidStateTransition(
                self.state.value, "set_window", str(self.engagement_id)
            )
        self.window = window
        self._mutate(now)

    def set_objectives(
        self,
        tenant_id: TenantId,
        objectives: EngagementObjectives,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        self.objectives = objectives
        self._mutate(now)

    def set_approval_policy(
        self,
        tenant_id: TenantId,
        policy: ApprovalPolicy,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state not in {EngagementState.DRAFT, EngagementState.PENDING_APPROVAL}:
            raise InvalidStateTransition(
                self.state.value, "set_approval_policy", str(self.engagement_id)
            )
        self.approval_policy = policy
        self._mutate(now)

    def add_participant(
        self,
        tenant_id: TenantId,
        operator_id: str,
        role: str,
        now: datetime,
    ) -> EngagementParticipant:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if not operator_id.strip():
            raise InvalidArgument("operator_id", "must not be empty")
        for existing in self.participants:
            if existing.operator_id == operator_id.strip() and existing.is_active:
                raise InvalidArgument("operator_id", "participant already active")
        participant = EngagementParticipant(
            participant_id=EngagementParticipantId.generate(),
            operator_id=operator_id.strip(),
            role=role.strip(),
            added_at=now,
        )
        self.participants.append(participant)
        self._mutate(now)
        self._emit(
            ParticipantAdded(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                operator_id=operator_id.strip(),
                role=role.strip(),
            )
        )
        return participant

    def remove_participant(
        self,
        tenant_id: TenantId,
        operator_id: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        found = False
        for participant in self.participants:
            if participant.operator_id == operator_id.strip() and participant.is_active:
                participant.removed_at = now
                found = True
                break
        if not found:
            raise InvalidArgument("operator_id", "active participant not found")
        self._mutate(now)
        self._emit(
            ParticipantRemoved(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                operator_id=operator_id.strip(),
            )
        )

    def add_phase(
        self,
        tenant_id: TenantId,
        name: str,
        now: datetime,
        description: str | None = None,
        sort_order: int | None = None,
    ) -> EngagementPhase:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if not name.strip():
            raise InvalidArgument("name", "must not be empty")
        order = sort_order if sort_order is not None else len(self.phases)
        phase = EngagementPhase(
            phase_id=EngagementPhaseId.generate(),
            name=name.strip(),
            description=description,
            sort_order=order,
        )
        self.phases.append(phase)
        self._mutate(now)
        return phase

    def submit_for_approval(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if not self.scope.targets:
            raise InvalidArgument("scope", "target scope must be defined")
        if self.roe is None:
            raise InvalidArgument("roe", "RulesOfEngagement must be set")
        if self.window is None:
            raise InvalidArgument("window", "engagement window must be set")
        self._transition(EngagementState.PENDING_APPROVAL)
        self._mutate(now)
        self._emit(
            EngagementSubmittedForApproval(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
            )
        )

    def grant_approval(
        self,
        tenant_id: TenantId,
        approver_id: str,
        signature: str,
        now: datetime,
        approval_scope: str = "engagement",
    ) -> EngagementApproval:
        """
        Add approval under optimistic locking.

        Quorum completion check runs INSIDE this method (HARDENING §7).
        """
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != EngagementState.PENDING_APPROVAL:
            raise InvalidStateTransition(
                self.state.value, "grant_approval", str(self.engagement_id)
            )
        if not approver_id.strip():
            raise InvalidArgument("approver_id", "must not be empty")
        if not signature.strip():
            raise InvalidArgument("signature", "must not be empty")

        for existing in self.active_approvals():
            if (
                existing.record.approver_id == approver_id.strip()
                and existing.record.approval_scope == approval_scope
            ):
                raise DuplicateApproval(approver_id.strip(), str(self.engagement_id))

        record = ApprovalRecord(
            approver_id=approver_id.strip(),
            timestamp=now,
            signature=signature.strip(),
            approval_scope=approval_scope,
        )
        approval = EngagementApproval(
            approval_id=EngagementApprovalId.generate(),
            record=record,
        )
        self.approvals.append(approval)

        # Quorum check protected by aggregate optimistic lock (version bump below)
        quorum_complete = self.quorum_met()
        scope_hash_value: str | None = None
        if quorum_complete:
            serialized = serialize_target_scope(self.scope.targets)
            self.scope_hash = compute_scope_hash(
                serialized, self.engagement_version, now
            )
            scope_hash_value = self.scope_hash.value
            self._transition(EngagementState.APPROVED)

        self._mutate(now)
        self._emit(
            EngagementApprovalGranted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                approver_id=approver_id.strip(),
                signature=signature.strip(),
                quorum_met=quorum_complete,
                scope_hash=scope_hash_value,
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
            EngagementState.PENDING_APPROVAL,
            EngagementState.APPROVED,
        }:
            raise InvalidStateTransition(
                self.state.value, "revoke_approval", str(self.engagement_id)
            )
        found = False
        for approval in self.approvals:
            if (
                not approval.revoked
                and approval.record.approver_id == approver_id.strip()
            ):
                approval.revoked = True
                approval.revoked_at = now
                approval.revoked_by = revoked_by.strip()
                found = True
                break
        if not found:
            raise InvalidArgument("approver_id", "active approval not found")

        if self.state == EngagementState.APPROVED and not self.quorum_met():
            self._transition(EngagementState.DRAFT)
            self.scope_hash = None

        self._mutate(now)
        self._emit(
            EngagementApprovalRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                approver_id=approver_id.strip(),
                revoked_by=revoked_by.strip(),
            )
        )

    def activate(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != EngagementState.APPROVED:
            raise InvalidStateTransition(
                self.state.value, "activate", str(self.engagement_id)
            )
        if not self.quorum_met():
            raise QuorumNotMet(
                self.approval_policy.required_approver_count,
                len(self.active_approvals()),
                str(self.engagement_id),
            )
        if self.roe is None or not self.roe.is_signed:
            raise InvalidArgument("roe", "RulesOfEngagement must be signed by owner")
        if self.window is None:
            raise InvalidArgument("window", "engagement window required")
        if not self.window.contains(now):
            raise InvalidArgument("window", "activation must be within EngagementWindow")
        if self.scope_hash is None:
            raise InvalidArgument("scope_hash", "signed ScopeHash required")

        self.kill_switch_state = KillSwitchState.ARMED
        self._transition(EngagementState.ACTIVE)
        self._mutate(now)
        self._emit(
            EngagementActivated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                scope_hash=self.scope_hash.value,
            )
        )

    def suspend(
        self,
        tenant_id: TenantId,
        reason: str,
        authority: str,
        now: datetime,
        *,
        trigger_kill_switch: bool = True,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if not reason.strip():
            raise InvalidArgument("reason", "must not be empty")
        self._transition(EngagementState.SUSPENDED)
        if trigger_kill_switch:
            self.kill_switch_state = KillSwitchState.TRIGGERED
            self._emit(
                KillSwitchTriggered(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.engagement_id),
                    aggregate_type="Engagement",
                    authority=authority.strip(),
                    reason=reason.strip(),
                )
            )
        self._mutate(now)
        self._emit(
            EngagementSuspended(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                reason=reason.strip(),
                authority=authority.strip(),
            )
        )

    def release_kill_switch_and_resume(
        self,
        tenant_id: TenantId,
        authority: str,
        now: datetime,
    ) -> None:
        """Release kill switch then resume Active (re-Arms on transition)."""
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != EngagementState.SUSPENDED:
            raise InvalidStateTransition(
                self.state.value, "resume", str(self.engagement_id)
            )
        if self.window is None or not self.window.contains(now):
            raise InvalidArgument("window", "resume must be within EngagementWindow")

        self.kill_switch_state = KillSwitchState.RELEASED
        self._emit(
            KillSwitchReleased(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                authority=authority.strip(),
            )
        )
        self.kill_switch_state = KillSwitchState.ARMED
        self._transition(EngagementState.ACTIVE)
        self._mutate(now)

    def close(
        self,
        tenant_id: TenantId,
        now: datetime,
        reason: str | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        self._transition(EngagementState.CLOSED)
        self._mutate(now)
        self._emit(
            EngagementClosed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                reason=reason,
            )
        )

    def archive(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(EngagementState.ARCHIVED)
        self._mutate(now)
        self._emit(
            EngagementArchived(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
            )
        )

    def request_scope_expansion(
        self,
        tenant_id: TenantId,
        additional_targets: list[TargetRef],
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state not in {
            EngagementState.APPROVED,
            EngagementState.ACTIVE,
            EngagementState.SUSPENDED,
        }:
            raise InvalidStateTransition(
                self.state.value, "request_scope_expansion", str(self.engagement_id)
            )
        if not additional_targets:
            raise InvalidArgument("additional_targets", "must not be empty")
        existing = self.scope.asset_ids()
        new_targets = [t for t in additional_targets if t.asset_id not in existing]
        if not new_targets:
            raise InvalidArgument("additional_targets", "no new targets to add")
        self.pending_scope_expansion = list(new_targets)
        # Return to PendingApproval for expansion cycle
        if self.state == EngagementState.ACTIVE:
            self.kill_switch_state = KillSwitchState.TRIGGERED
        # Expansion requires re-approval: move toward PendingApproval via Draft path
        # For Approved/Active/Suspended, we store pending and transition to PendingApproval
        # by going through a dedicated path: force state to PendingApproval after clearing
        # active approvals for the new scope cycle.
        for approval in self.active_approvals():
            approval.revoked = True
            approval.revoked_at = now
            approval.revoked_by = "scope_expansion"
        if self.state == EngagementState.ACTIVE:
            self.state = EngagementState.SUSPENDED
            self._emit(
                KillSwitchTriggered(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.engagement_id),
                    aggregate_type="Engagement",
                    authority="scope_expansion",
                    reason="scope expansion requested",
                )
            )
        # From Suspended/Approved → we need PendingApproval. Allowed: Suspended→Closed only,
        # Approved→Active|Suspended. So we set state via internal path to Draft then Pending.
        # Architecture: scope expansion requires new approval cycle.
        self.state = EngagementState.PENDING_APPROVAL
        self._mutate(now)
        self._emit(
            ScopeExpansionRequested(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                added_asset_ids=[t.asset_id for t in new_targets],
                engagement_version=self.engagement_version,
            )
        )

    def approve_scope_expansion(
        self,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        """Apply pending expansion after quorum is re-established via grant_approval."""
        self._assert_tenant(tenant_id)
        self._assert_not_archived()
        if self.state != EngagementState.APPROVED:
            raise InvalidStateTransition(
                self.state.value, "approve_scope_expansion", str(self.engagement_id)
            )
        if not self.pending_scope_expansion:
            raise InvalidArgument("pending_scope_expansion", "no pending expansion")
        if not self.quorum_met():
            raise QuorumNotMet(
                self.approval_policy.required_approver_count,
                len(self.active_approvals()),
                str(self.engagement_id),
            )
        merged = list(self.scope.targets) + list(self.pending_scope_expansion)
        self.scope = TargetScope(targets=merged)
        self.pending_scope_expansion = []
        self.engagement_version += 1
        serialized = serialize_target_scope(self.scope.targets)
        self.scope_hash = compute_scope_hash(serialized, self.engagement_version, now)
        self._mutate(now)
        self._emit(
            ScopeExpansionApproved(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.engagement_id),
                aggregate_type="Engagement",
                engagement_version=self.engagement_version,
                scope_hash=self.scope_hash.value,
            )
        )
