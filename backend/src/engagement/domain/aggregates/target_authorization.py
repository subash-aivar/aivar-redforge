"""TargetAuthorization aggregate root — per-target technique authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from engagement.domain.events.authorization_events import (
    TargetAuthorizationExpired,
    TargetAuthorizationGranted,
    TargetAuthorizationRevoked,
    TargetAuthorizationSuspended,
)
from engagement.domain.exceptions.domain_exceptions import (
    AuthorizationReinstatementForbidden,
    InvalidArgument,
    InvalidStateTransition,
    TenantMismatch,
)
from engagement.domain.value_objects.enums import AuthorizationState, ImpactCeiling

if TYPE_CHECKING:
    from datetime import datetime

    from engagement.domain.events.base import BaseDomainEvent
    from engagement.domain.value_objects.engagement_vos import (
        AuthorizationConstraints,
        AuthorizedTechniqueSet,
        TargetRef,
    )
    from engagement.domain.value_objects.identifiers import (
        EngagementId,
        EngagementPhaseId,
        TargetAuthorizationId,
        TenantId,
    )

_ALLOWED_TRANSITIONS: dict[AuthorizationState, frozenset[AuthorizationState]] = {
    AuthorizationState.ACTIVE: frozenset(
        {
            AuthorizationState.SUSPENDED,
            AuthorizationState.REVOKED,
            AuthorizationState.EXPIRED,
        }
    ),
    AuthorizationState.SUSPENDED: frozenset(
        {
            AuthorizationState.ACTIVE,
            AuthorizationState.REVOKED,
            AuthorizationState.EXPIRED,
        }
    ),
    AuthorizationState.REVOKED: frozenset(),
    AuthorizationState.EXPIRED: frozenset(),
}


class TargetAuthorization:
    """Discrete authorization binding a TargetRef to techniques and constraints."""

    __slots__ = (
        "_pending_events",
        "_version",
        "authorization_id",
        "constraints",
        "created_at",
        "destruct_approval_granted",
        "engagement_id",
        "granted_by",
        "phase_id",
        "state",
        "target_ref",
        "techniques",
        "tenant_id",
        "updated_at",
        "valid_until",
    )

    def __init__(
        self,
        authorization_id: TargetAuthorizationId,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        target_ref: TargetRef,
        techniques: AuthorizedTechniqueSet,
        constraints: AuthorizationConstraints,
        granted_by: str,
        valid_until: datetime,
        state: AuthorizationState,
        phase_id: EngagementPhaseId | None,
        destruct_approval_granted: bool,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.authorization_id = authorization_id
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id
        self.target_ref = target_ref
        self.techniques = techniques
        self.constraints = constraints
        self.granted_by = granted_by
        self.valid_until = valid_until
        self.state = state
        self.phase_id = phase_id
        self.destruct_approval_granted = destruct_approval_granted
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

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: AuthorizationState) -> None:
        if self.state == AuthorizationState.REVOKED:
            raise AuthorizationReinstatementForbidden(str(self.authorization_id))
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                to_state.value,
                str(self.authorization_id),
            )
        self.state = to_state

    @classmethod
    def grant(
        cls,
        authorization_id: TargetAuthorizationId,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        target_ref: TargetRef,
        techniques: AuthorizedTechniqueSet,
        constraints: AuthorizationConstraints,
        granted_by: str,
        valid_until: datetime,
        now: datetime,
        *,
        allowed_roe_techniques: frozenset[str] | set[str],
        destruct_approval_granted: bool = False,
        phase_id: EngagementPhaseId | None = None,
    ) -> TargetAuthorization:
        if not granted_by.strip():
            raise InvalidArgument("granted_by", "must not be empty")
        if valid_until <= now:
            raise InvalidArgument("valid_until", "must be in the future")
        if not techniques.is_subset_of(allowed_roe_techniques):
            raise InvalidArgument(
                "techniques",
                "may not authorize techniques absent from parent engagement RoE",
            )
        if (
            constraints.impact_ceiling == ImpactCeiling.DESTRUCT
            and not destruct_approval_granted
        ):
            raise InvalidArgument(
                "destruct_approval_granted",
                "impact_ceiling=Destruct requires separate CISO-level approval gate",
            )

        auth = cls(
            authorization_id=authorization_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            target_ref=target_ref,
            techniques=techniques,
            constraints=constraints,
            granted_by=granted_by.strip(),
            valid_until=valid_until,
            state=AuthorizationState.ACTIVE,
            phase_id=phase_id,
            destruct_approval_granted=destruct_approval_granted,
            created_at=now,
            updated_at=now,
            version=1,
        )
        auth._emit(
            TargetAuthorizationGranted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(authorization_id),
                aggregate_type="TargetAuthorization",
                engagement_id=engagement_id.value,
                asset_id=target_ref.asset_id,
                impact_ceiling=constraints.impact_ceiling.value,
            )
        )
        return auth

    def suspend(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("reason", "must not be empty")
        self._transition(AuthorizationState.SUSPENDED)
        self._mutate(now)
        self._emit(
            TargetAuthorizationSuspended(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.authorization_id),
                aggregate_type="TargetAuthorization",
                reason=reason.strip(),
            )
        )

    def resume(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(AuthorizationState.ACTIVE)
        self._mutate(now)

    def revoke(
        self,
        tenant_id: TenantId,
        reason: str,
        revoked_by: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("reason", "must not be empty")
        self._transition(AuthorizationState.REVOKED)
        self._mutate(now)
        self._emit(
            TargetAuthorizationRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.authorization_id),
                aggregate_type="TargetAuthorization",
                reason=reason.strip(),
                revoked_by=revoked_by.strip(),
            )
        )

    def expire(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if now < self.valid_until and self.state == AuthorizationState.ACTIVE:
            raise InvalidArgument("valid_until", "authorization has not yet expired")
        self._transition(AuthorizationState.EXPIRED)
        self._mutate(now)
        self._emit(
            TargetAuthorizationExpired(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.authorization_id),
                aggregate_type="TargetAuthorization",
            )
        )
