"""RedTeamOperator aggregate — clearance, engagement membership, approval authority."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

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
from red_team_operator.domain.value_objects.clearance import (
    can_authorize_ceiling,
    clearance_meets_scope,
    max_impact_ceiling,
    min_clearance_for_scope,
)
from red_team_operator.domain.value_objects.enums import OperatorState
from red_team_operator.domain.value_objects.operator_vos import (
    ActiveEngagementRefs,
    ApprovalAuthority,
    OperatorCertifications,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from red_team_operator.domain.events.base import BaseDomainEvent
    from red_team_operator.domain.value_objects.enums import (
        ApprovalScope,
        ImpactCeiling,
        OperatorClearanceLevel,
    )
    from red_team_operator.domain.value_objects.identifiers import OperatorId, TenantId

_ALLOWED_TRANSITIONS: dict[OperatorState, frozenset[OperatorState]] = {
    OperatorState.ACTIVE: frozenset({OperatorState.SUSPENDED, OperatorState.REVOKED}),
    OperatorState.SUSPENDED: frozenset({OperatorState.REVOKED}),
    OperatorState.REVOKED: frozenset(),
}

_AGGREGATE_TYPE = "RedTeamOperator"


class RedTeamOperator:
    """Authorized red team member with clearance-bounded approval authority."""

    __slots__ = (
        "_pending_events",
        "_version",
        "active_engagements",
        "approval_authority",
        "certifications",
        "clearance_level",
        "created_at",
        "display_name",
        "identity_ref",
        "operator_id",
        "state",
        "status_authority",
        "status_reason",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        operator_id: OperatorId,
        tenant_id: TenantId,
        identity_ref: str,
        display_name: str,
        clearance_level: OperatorClearanceLevel,
        state: OperatorState,
        certifications: OperatorCertifications,
        approval_authority: ApprovalAuthority,
        active_engagements: ActiveEngagementRefs,
        status_reason: str | None,
        status_authority: str | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.operator_id = operator_id
        self.tenant_id = tenant_id
        self.identity_ref = identity_ref
        self.display_name = display_name
        self.clearance_level = clearance_level
        self.state = state
        self.certifications = certifications
        self.approval_authority = approval_authority
        self.active_engagements = active_engagements
        self.status_reason = status_reason
        self.status_authority = status_authority
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def max_impact_ceiling(self) -> ImpactCeiling:
        return max_impact_ceiling(self.clearance_level)

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: OperatorState) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                to_state.value,
                str(self.operator_id),
            )
        self.state = to_state

    def _assert_active_for_mutation(self) -> None:
        if self.state != OperatorState.ACTIVE:
            raise OperatorNotAuthorized(
                f"operator state {self.state.value} may not authorize or execute",
                str(self.operator_id),
            )

    @classmethod
    def activate(
        cls,
        *,
        tenant_id: TenantId,
        identity_ref: str,
        clearance_level: OperatorClearanceLevel,
        now: datetime,
        display_name: str | None = None,
        certifications: OperatorCertifications | list[str] | None = None,
        approval_scopes: list[ApprovalScope] | None = None,
        operator_id: OperatorId | None = None,
    ) -> RedTeamOperator:
        """Factory: create a new Active operator."""
        from red_team_operator.domain.value_objects.identifiers import OperatorId as _Oid

        ref = identity_ref.strip()
        if not ref:
            raise InvalidArgument("identity_ref", "required")

        name = (display_name or ref).strip()
        if not name:
            raise InvalidArgument("display_name", "required")

        certs = (
            certifications
            if isinstance(certifications, OperatorCertifications)
            else OperatorCertifications(tuple(certifications or ()))
        )
        authority = ApprovalAuthority(tuple(approval_scopes or ()))
        for scope in authority.scopes:
            if not clearance_meets_scope(clearance_level, scope):
                raise InvalidArgument(
                    "approval_scopes",
                    f"{scope.value} requires minimum clearance "
                    f"{min_clearance_for_scope(scope).value}",
                )

        oid = operator_id or _Oid.generate()
        op = cls(
            operator_id=oid,
            tenant_id=tenant_id,
            identity_ref=ref,
            display_name=name,
            clearance_level=clearance_level,
            state=OperatorState.ACTIVE,
            certifications=certs,
            approval_authority=authority,
            active_engagements=ActiveEngagementRefs.empty(),
            status_reason=None,
            status_authority=None,
            created_at=now,
            updated_at=now,
            version=0,
        )
        op._emit(
            OperatorActivated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(oid),
                aggregate_type=_AGGREGATE_TYPE,
                identity_ref=ref,
                clearance_level=clearance_level.value,
            )
        )
        return op

    def suspend(
        self,
        *,
        reason: str,
        authority: str,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        cleaned_reason = reason.strip()
        cleaned_authority = authority.strip()
        if not cleaned_reason:
            raise InvalidArgument("reason", "required")
        if not cleaned_authority:
            raise InvalidArgument("authority", "required")

        self._transition(OperatorState.SUSPENDED)
        self.status_reason = cleaned_reason
        self.status_authority = cleaned_authority
        self._mutate(now)
        self._emit(
            OperatorSuspended(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operator_id),
                aggregate_type=_AGGREGATE_TYPE,
                reason=cleaned_reason,
                authority=cleaned_authority,
            )
        )

    def revoke(
        self,
        *,
        reason: str,
        authority: str,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        cleaned_reason = reason.strip()
        cleaned_authority = authority.strip()
        if not cleaned_reason:
            raise InvalidArgument("reason", "required")
        if not cleaned_authority:
            raise InvalidArgument("authority", "required")

        self._transition(OperatorState.REVOKED)
        self.status_reason = cleaned_reason
        self.status_authority = cleaned_authority
        # Revocation clears engagement membership; Phase 4 consumes the remove events.
        removed = list(self.active_engagements.engagement_ids)
        self.active_engagements = ActiveEngagementRefs.empty()
        self.approval_authority = ApprovalAuthority.empty()
        self._mutate(now)
        self._emit(
            OperatorRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operator_id),
                aggregate_type=_AGGREGATE_TYPE,
                reason=cleaned_reason,
                authority=cleaned_authority,
            )
        )
        for engagement_id in removed:
            self._emit(
                OperatorRemovedFromEngagement(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.operator_id),
                    aggregate_type=_AGGREGATE_TYPE,
                    engagement_id=str(engagement_id),
                )
            )

    def change_clearance_level(
        self,
        *,
        new_level: OperatorClearanceLevel,
        authority: str,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_active_for_mutation()
        cleaned_authority = authority.strip()
        if not cleaned_authority:
            raise InvalidArgument("authority", "required")
        if new_level == self.clearance_level:
            raise InvalidArgument("new_level", "must differ from current clearance")

        previous = self.clearance_level
        # Drop approval scopes that the new clearance can no longer hold.
        self.approval_authority = ApprovalAuthority(
            tuple(
                scope
                for scope in self.approval_authority.scopes
                if clearance_meets_scope(new_level, scope)
            )
        )
        self.clearance_level = new_level
        self._mutate(now)
        self._emit(
            OperatorClearanceLevelChanged(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operator_id),
                aggregate_type=_AGGREGATE_TYPE,
                previous_level=previous.value,
                new_level=new_level.value,
                authority=cleaned_authority,
            )
        )

    def add_to_engagement(
        self,
        *,
        engagement_id: UUID,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_active_for_mutation()
        if engagement_id.int == 0:
            raise InvalidArgument("engagement_id", "must not be nil UUID")
        if self.active_engagements.includes(engagement_id):
            raise InvalidArgument("engagement_id", "operator already on engagement")

        self.active_engagements = self.active_engagements.with_added(engagement_id)
        self._mutate(now)
        self._emit(
            OperatorAddedToEngagement(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operator_id),
                aggregate_type=_AGGREGATE_TYPE,
                engagement_id=str(engagement_id),
            )
        )

    def remove_from_engagement(
        self,
        *,
        engagement_id: UUID,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if engagement_id.int == 0:
            raise InvalidArgument("engagement_id", "must not be nil UUID")
        if not self.active_engagements.includes(engagement_id):
            raise InvalidArgument("engagement_id", "operator not on engagement")
        if self.state == OperatorState.REVOKED:
            raise InvalidStateTransition(
                self.state.value,
                "remove_from_engagement",
                str(self.operator_id),
            )

        self.active_engagements = self.active_engagements.with_removed(engagement_id)
        self._mutate(now)
        self._emit(
            OperatorRemovedFromEngagement(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operator_id),
                aggregate_type=_AGGREGATE_TYPE,
                engagement_id=str(engagement_id),
            )
        )

    def grant_approval_authority(
        self,
        *,
        scope: ApprovalScope,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_active_for_mutation()
        if not clearance_meets_scope(self.clearance_level, scope):
            raise OperatorNotAuthorized(
                f"clearance {self.clearance_level.value} insufficient for {scope.value} "
                f"(requires {min_clearance_for_scope(scope).value})",
                str(self.operator_id),
            )
        if self.approval_authority.includes(scope):
            raise InvalidArgument("scope", f"already granted: {scope.value}")

        self.approval_authority = self.approval_authority.with_granted(scope)
        self._mutate(now)

    def revoke_approval_authority(
        self,
        *,
        scope: ApprovalScope,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_active_for_mutation()
        if not self.approval_authority.includes(scope):
            raise InvalidArgument("scope", f"not granted: {scope.value}")

        self.approval_authority = self.approval_authority.with_revoked(scope)
        self._mutate(now)

    def can_authorize_impact(self, impact_ceiling: ImpactCeiling) -> bool:
        """True when Active and clearance permits the impact ceiling."""
        if self.state != OperatorState.ACTIVE:
            return False
        return can_authorize_ceiling(self.clearance_level, impact_ceiling)

    def assert_can_approve(self, scope: ApprovalScope) -> None:
        """Raise if the operator may not approve the given scope."""
        if self.state != OperatorState.ACTIVE:
            raise OperatorNotAuthorized(
                f"operator state {self.state.value} may not authorize or execute",
                str(self.operator_id),
            )
        if not self.approval_authority.includes(scope):
            raise OperatorNotAuthorized(
                f"missing approval authority for {scope.value}",
                str(self.operator_id),
            )
        if not clearance_meets_scope(self.clearance_level, scope):
            raise OperatorNotAuthorized(
                f"clearance {self.clearance_level.value} insufficient for {scope.value}",
                str(self.operator_id),
            )
