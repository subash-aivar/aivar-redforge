"""DetectionException aggregate root — approved departures from detection defaults."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from detection.domain.events.exception_events import (
    DetectionExceptionApproved,
    DetectionExceptionExpired,
    DetectionExceptionRejected,
    DetectionExceptionRenewed,
    DetectionExceptionRequested,
    DetectionExceptionRevoked,
)
from detection.domain.exceptions.domain_exceptions import (
    ComplianceAcknowledgementRequired,
    ExceptionLifecycleBlocked,
    InvalidArgument,
    InvalidStateTransition,
    TenantMismatch,
)
from detection.domain.value_objects.enums import ExceptionState
from detection.domain.value_objects.exception_vos import ExceptionValidUntil
from detection.domain.value_objects.identifiers import DetectionExceptionId

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.events.base import BaseDomainEvent
    from detection.domain.value_objects.enums import ExceptionType
    from detection.domain.value_objects.exception_vos import (
        AffectedRuleRefs,
        AssetScopeFilter,
        ExceptionApprover,
        ExceptionJustification,
        ExceptionScope,
    )
    from detection.domain.value_objects.identifiers import TenantId

_ALLOWED: dict[ExceptionState, frozenset[ExceptionState]] = {
    ExceptionState.PENDING: frozenset(
        {ExceptionState.ACTIVE, ExceptionState.REJECTED, ExceptionState.REVOKED}
    ),
    ExceptionState.ACTIVE: frozenset(
        {ExceptionState.EXPIRED, ExceptionState.REVOKED, ExceptionState.ACTIVE}
    ),
    ExceptionState.EXPIRED: frozenset({ExceptionState.ACTIVE, ExceptionState.REVOKED}),
    ExceptionState.REVOKED: frozenset(),
    ExceptionState.REJECTED: frozenset(),
}


class DetectionException:
    """Deliberate, approved departure from default detection behavior."""

    __slots__ = (
        "_pending_events",
        "_version",
        "affected_rules",
        "approver",
        "asset_scope",
        "compliance_impact_acknowledged",
        "created_at",
        "exception_id",
        "exception_type",
        "justification",
        "requester",
        "scope",
        "state",
        "tenant_id",
        "updated_at",
        "valid_until",
    )

    def __init__(
        self,
        exception_id: DetectionExceptionId,
        tenant_id: TenantId,
        exception_type: ExceptionType,
        scope: ExceptionScope,
        justification: ExceptionJustification,
        requester: str,
        valid_until: ExceptionValidUntil,
        state: ExceptionState,
        affected_rules: AffectedRuleRefs,
        created_at: datetime,
        updated_at: datetime,
        *,
        asset_scope: AssetScopeFilter | None = None,
        approver: ExceptionApprover | None = None,
        compliance_impact_acknowledged: bool = False,
        version: int = 0,
    ) -> None:
        self.exception_id = exception_id
        self.tenant_id = tenant_id
        self.exception_type = exception_type
        self.scope = scope
        self.justification = justification
        self.requester = requester
        self.valid_until = valid_until
        self.state = state
        self.affected_rules = affected_rules
        self.asset_scope = asset_scope
        self.approver = approver
        self.compliance_impact_acknowledged = compliance_impact_acknowledged
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

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch(str(tenant_id), str(self.tenant_id))

    def _transition(self, target: ExceptionState) -> None:
        allowed = _ALLOWED.get(self.state, frozenset())
        if target not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                target.value,
            )
        self.state = target

    @classmethod
    def request(
        cls,
        *,
        tenant_id: TenantId,
        exception_type: ExceptionType,
        scope: ExceptionScope,
        justification: ExceptionJustification,
        requester: str,
        valid_until: datetime,
        affected_rules: AffectedRuleRefs,
        now: datetime,
        asset_scope: AssetScopeFilter | None = None,
        compliance_mapped: bool = False,
        compliance_impact_acknowledged: bool = False,
        exception_id: DetectionExceptionId | None = None,
    ) -> DetectionException:
        if not requester.strip():
            raise InvalidArgument("requester", "required")
        if valid_until <= now:
            raise InvalidArgument("valid_until", "must be in the future")
        if compliance_mapped and not compliance_impact_acknowledged:
            raise ComplianceAcknowledgementRequired()
        eid = exception_id or DetectionExceptionId.generate()
        aggregate = cls(
            exception_id=eid,
            tenant_id=tenant_id,
            exception_type=exception_type,
            scope=scope,
            justification=justification,
            requester=requester.strip()[:256],
            valid_until=ExceptionValidUntil(expires_at=valid_until),
            state=ExceptionState.PENDING,
            affected_rules=affected_rules,
            asset_scope=asset_scope,
            compliance_impact_acknowledged=compliance_impact_acknowledged,
            created_at=now,
            updated_at=now,
            version=0,
        )
        aggregate._emit(
            DetectionExceptionRequested(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(eid),
                aggregate_type="DetectionException",
                exception_type=exception_type.value,
                requester=aggregate.requester,
            )
        )
        return aggregate

    def approve(
        self,
        *,
        tenant_id: TenantId,
        approver: ExceptionApprover,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ExceptionState.PENDING:
            raise ExceptionLifecycleBlocked("only Pending exceptions can be approved")
        if self.valid_until.is_expired(now):
            raise ExceptionLifecycleBlocked("cannot approve an already-expired request")
        self._transition(ExceptionState.ACTIVE)
        self.approver = approver
        self._mutate(now)
        self._emit(
            DetectionExceptionApproved(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.exception_id),
                aggregate_type="DetectionException",
                approver=approver.identity,
            )
        )

    def reject(
        self,
        *,
        tenant_id: TenantId,
        rejector: str,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ExceptionState.PENDING:
            raise ExceptionLifecycleBlocked("only Pending exceptions can be rejected")
        if not rejector.strip():
            raise InvalidArgument("rejector", "required")
        if not reason.strip():
            raise InvalidArgument("reason", "required")
        self._transition(ExceptionState.REJECTED)
        self._mutate(now)
        self._emit(
            DetectionExceptionRejected(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.exception_id),
                aggregate_type="DetectionException",
                rejector=rejector.strip()[:256],
                reason=reason.strip()[:2048],
            )
        )

    def expire(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ExceptionState.ACTIVE:
            raise ExceptionLifecycleBlocked("only Active exceptions can expire")
        if not self.valid_until.is_expired(now):
            raise ExceptionLifecycleBlocked("exception has not reached valid_until")
        self._transition(ExceptionState.EXPIRED)
        self._mutate(now)
        self._emit(
            DetectionExceptionExpired(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.exception_id),
                aggregate_type="DetectionException",
            )
        )

    def renew(
        self,
        *,
        tenant_id: TenantId,
        renewer: str,
        new_valid_until: datetime,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state not in {ExceptionState.ACTIVE, ExceptionState.EXPIRED}:
            raise ExceptionLifecycleBlocked(
                "only Active or Expired exceptions can be renewed"
            )
        if not renewer.strip():
            raise InvalidArgument("renewer", "required")
        if new_valid_until <= now:
            raise InvalidArgument("new_valid_until", "must be in the future")
        self.valid_until = ExceptionValidUntil(expires_at=new_valid_until)
        if self.state == ExceptionState.EXPIRED:
            self._transition(ExceptionState.ACTIVE)
        else:
            self._transition(ExceptionState.ACTIVE)  # self-transition allowed
        self._mutate(now)
        self._emit(
            DetectionExceptionRenewed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.exception_id),
                aggregate_type="DetectionException",
                renewed_until=new_valid_until.isoformat(),
                renewer=renewer.strip()[:256],
            )
        )

    def revoke(
        self,
        *,
        tenant_id: TenantId,
        revoker: str,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state in {ExceptionState.REVOKED, ExceptionState.REJECTED}:
            raise ExceptionLifecycleBlocked("exception already terminal")
        if not revoker.strip():
            raise InvalidArgument("revoker", "required")
        if not reason.strip():
            raise InvalidArgument("reason", "required")
        self._transition(ExceptionState.REVOKED)
        self._mutate(now)
        self._emit(
            DetectionExceptionRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.exception_id),
                aggregate_type="DetectionException",
                revoker=revoker.strip()[:256],
                reason=reason.strip()[:2048],
            )
        )
