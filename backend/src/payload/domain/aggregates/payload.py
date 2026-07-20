"""Payload aggregate — governance registry for offensive artifacts."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from payload.domain.events.payload_events import (
    PayloadApproved,
    PayloadDeprecated,
    PayloadHashMismatchDetected,
    PayloadHashVerified,
    PayloadRegistered,
    PayloadRevoked,
    PayloadVersionPublished,
)
from payload.domain.exceptions.domain_exceptions import (
    CisoApprovalRequired,
    InvalidArgument,
    InvalidStateTransition,
    PayloadHashMismatch,
    PayloadNotApproved,
    PayloadRevokedError,
    TenantMismatch,
)
from payload.domain.value_objects.enums import ImpactCeiling, PayloadApprovalState
from payload.domain.value_objects.identifiers import PayloadId
from payload.domain.value_objects.payload_vos import (
    ApprovedForEngagementClasses,
    PayloadHash,
    PayloadSignature,
    PayloadVersionSnapshot,
)

if TYPE_CHECKING:
    from datetime import datetime

    from payload.domain.events.base import BaseDomainEvent
    from payload.domain.value_objects.enums import PayloadType
    from payload.domain.value_objects.identifiers import OperatorId, TenantId
    from payload.domain.value_objects.payload_vos import (
        PayloadCapabilities,
        PayloadKey,
        PayloadStorageRef,
        PayloadVersionRef,
    )

_ALLOWED: dict[PayloadApprovalState, frozenset[PayloadApprovalState]] = {
    PayloadApprovalState.SUBMITTED: frozenset(
        {
            PayloadApprovalState.UNDER_REVIEW,
            PayloadApprovalState.APPROVED,
            PayloadApprovalState.REVOKED,
        }
    ),
    PayloadApprovalState.UNDER_REVIEW: frozenset(
        {
            PayloadApprovalState.APPROVED,
            PayloadApprovalState.REVOKED,
            PayloadApprovalState.DEPRECATED,
        }
    ),
    PayloadApprovalState.APPROVED: frozenset(
        {
            PayloadApprovalState.DEPRECATED,
            PayloadApprovalState.REVOKED,
        }
    ),
    PayloadApprovalState.DEPRECATED: frozenset(
        {
            PayloadApprovalState.REVOKED,
        }
    ),
    PayloadApprovalState.REVOKED: frozenset(),
}

_AGGREGATE = "Payload"


class Payload:
    """Registered payload with versioned hash-verified artifacts."""

    __slots__ = (
        "_pending_events",
        "_version",
        "approval_state",
        "approved_for",
        "created_at",
        "current_version",
        "impact_ceiling",
        "payload_id",
        "payload_key",
        "payload_type",
        "signature",
        "tenant_id",
        "updated_at",
        "versions",
    )

    def __init__(
        self,
        payload_id: PayloadId,
        tenant_id: TenantId,
        payload_key: PayloadKey,
        payload_type: PayloadType,
        impact_ceiling: ImpactCeiling,
        approval_state: PayloadApprovalState,
        versions: list[PayloadVersionSnapshot],
        current_version: PayloadVersionRef | None,
        approved_for: ApprovedForEngagementClasses,
        signature: PayloadSignature | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.payload_id = payload_id
        self.tenant_id = tenant_id
        self.payload_key = payload_key
        self.payload_type = payload_type
        self.impact_ceiling = impact_ceiling
        self.approval_state = approval_state
        self.versions = list(versions)
        self.current_version = current_version
        self.approved_for = approved_for
        self.signature = signature
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def id(self) -> PayloadId:
        return self.payload_id

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
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _transition(self, to_state: PayloadApprovalState) -> None:
        allowed = _ALLOWED.get(self.approval_state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.approval_state.value,
                to_state.value,
                str(self.payload_id),
            )
        self.approval_state = to_state

    def _current_snapshot(self) -> PayloadVersionSnapshot:
        if self.current_version is None or not self.versions:
            raise InvalidArgument("payload has no published version")
        for snap in reversed(self.versions):
            if snap.version == self.current_version:
                return snap
        raise InvalidArgument("current_version not found in versions")

    @classmethod
    def register(
        cls,
        *,
        tenant_id: TenantId,
        payload_key: PayloadKey,
        payload_type: PayloadType,
        impact_ceiling: ImpactCeiling,
        approved_for: ApprovedForEngagementClasses,
        now: datetime,
    ) -> Payload:
        payload_id = PayloadId.generate()
        payload = cls(
            payload_id=payload_id,
            tenant_id=tenant_id,
            payload_key=payload_key,
            payload_type=payload_type,
            impact_ceiling=impact_ceiling,
            approval_state=PayloadApprovalState.SUBMITTED,
            versions=[],
            current_version=None,
            approved_for=approved_for,
            signature=None,
            created_at=now,
            updated_at=now,
            version=0,
        )
        payload._emit(
            PayloadRegistered(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(payload_id),
                aggregate_type=_AGGREGATE,
                payload_key=payload_key.value,
                payload_type=payload_type.value,
                impact_ceiling=impact_ceiling.value,
            )
        )
        return payload

    def publish_version(
        self,
        *,
        tenant_id: TenantId,
        version: PayloadVersionRef,
        payload_hash: PayloadHash,
        storage_ref: PayloadStorageRef,
        capabilities: PayloadCapabilities,
        now: datetime,
        vulnerability_refs: tuple[str, ...] = (),
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.approval_state == PayloadApprovalState.REVOKED:
            raise PayloadRevokedError(str(self.payload_id))
        for existing in self.versions:
            if existing.version == version:
                raise InvalidArgument(f"version already published: {version}")
        snap = PayloadVersionSnapshot(
            version=version,
            payload_hash=payload_hash,
            storage_ref=storage_ref,
            capabilities=capabilities,
            published_at=now,
            vulnerability_refs=vulnerability_refs,
        )
        self.versions.append(snap)
        self.current_version = version
        if self.approval_state == PayloadApprovalState.SUBMITTED:
            self._transition(PayloadApprovalState.UNDER_REVIEW)
        self._mutate(now)
        self._emit(
            PayloadVersionPublished(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.payload_id),
                aggregate_type=_AGGREGATE,
                version=version.value,
                payload_hash=payload_hash.value,
                storage_ref=storage_ref.value,
            )
        )

    def approve(
        self,
        *,
        tenant_id: TenantId,
        approved_by: OperatorId,
        signature: PayloadSignature,
        now: datetime,
        ciso_approved: bool = False,
        engagement_classes: tuple[str, ...] | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.current_version is None:
            raise InvalidArgument("cannot approve payload without a published version")
        if self.impact_ceiling == ImpactCeiling.DESTRUCT and not ciso_approved:
            raise CisoApprovalRequired(str(self.payload_id))
        self._transition(PayloadApprovalState.APPROVED)
        self.signature = signature
        if engagement_classes is not None:
            self.approved_for = ApprovedForEngagementClasses(engagement_classes)
        self._mutate(now)
        self._emit(
            PayloadApproved(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.payload_id),
                aggregate_type=_AGGREGATE,
                version=self.current_version.value,
                approved_by=str(approved_by),
                ciso_approved=ciso_approved,
            )
        )

    def deprecate(
        self,
        *,
        tenant_id: TenantId,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason:
            raise InvalidArgument("deprecation reason must not be empty")
        self._transition(PayloadApprovalState.DEPRECATED)
        self._mutate(now)
        self._emit(
            PayloadDeprecated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.payload_id),
                aggregate_type=_AGGREGATE,
                reason=reason,
            )
        )

    def revoke(
        self,
        *,
        tenant_id: TenantId,
        reason: str,
        revoked_by: OperatorId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason:
            raise InvalidArgument("revocation reason must not be empty")
        self._transition(PayloadApprovalState.REVOKED)
        self._mutate(now)
        self._emit(
            PayloadRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.payload_id),
                aggregate_type=_AGGREGATE,
                reason=reason,
                revoked_by=str(revoked_by),
            )
        )

    def verify_hash(
        self,
        *,
        tenant_id: TenantId,
        computed_hash: PayloadHash,
        now: datetime,
    ) -> None:
        """Verify artifact hash against current version; emit mismatch security event."""
        self._assert_tenant(tenant_id)
        if self.approval_state == PayloadApprovalState.REVOKED:
            raise PayloadRevokedError(str(self.payload_id))
        if self.approval_state != PayloadApprovalState.APPROVED:
            raise PayloadNotApproved(str(self.payload_id), self.approval_state.value)
        snap = self._current_snapshot()
        if computed_hash.value == snap.payload_hash.value:
            self._emit(
                PayloadHashVerified(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.payload_id),
                    aggregate_type=_AGGREGATE,
                    version=snap.version.value,
                    payload_hash=snap.payload_hash.value,
                )
            )
            return
        self._emit(
            PayloadHashMismatchDetected(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.payload_id),
                aggregate_type=_AGGREGATE,
                version=snap.version.value,
                expected_hash=snap.payload_hash.value,
                computed_hash=computed_hash.value,
            )
        )
        raise PayloadHashMismatch(
            str(self.payload_id),
            snap.payload_hash.value,
            computed_hash.value,
        )

    def assert_dispatchable(self) -> PayloadVersionSnapshot:
        """Pre-dispatch gate: must be Approved with a current version."""
        if self.approval_state == PayloadApprovalState.REVOKED:
            raise PayloadRevokedError(str(self.payload_id))
        if self.approval_state != PayloadApprovalState.APPROVED:
            raise PayloadNotApproved(str(self.payload_id), self.approval_state.value)
        return self._current_snapshot()
