"""CredentialAssociation aggregate — links a `CloudAccount` and a
`CloudProviderRegistration` to a `CloudCredentialReference` already
managed by the (external, out-of-scope) Credential Vault (M45D).

This aggregate never stores, encrypts, or resolves secret material —
`CloudCredentialReference` is opaque (an id + a type tag) by design
(M45A). It owns association lifecycle (attach/replace/detach) and
rotation-history *metadata* only: which reference is currently active,
which one it replaced, and when. Referencing `CloudAccount`/
`CloudProviderRegistration` by id only, never by object reference —
the same cross-aggregate-reference-by-id discipline every other
`cloud_security` aggregate follows."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.domain.events.credential_association_events import (
    CredentialAttached,
    CredentialDetached,
    CredentialReplaced,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidCredentialAssociationTransition,
    RedundantCredentialReferenceError,
    TenantMismatch,
)
from cloud_security.domain.value_objects.enums import CredentialAssociationStatus

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.events.base import BaseDomainEvent
    from cloud_security.domain.value_objects.cloud_credential_reference import (
        CloudCredentialReference,
    )
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        CredentialAssociationId,
        ProviderId,
        TenantId,
    )

_REPLACE_FROM = {CredentialAssociationStatus.ACTIVE}
_DETACH_FROM = {CredentialAssociationStatus.ACTIVE}


class CredentialAssociation:
    __slots__ = (
        "_pending_events",
        "account_id",
        "active_reference",
        "association_id",
        "attached_at",
        "previous_reference",
        "provider_id",
        "rotated_at",
        "status",
        "tenant_id",
    )

    def __init__(
        self,
        association_id: CredentialAssociationId,
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        active_reference: CloudCredentialReference,
        status: CredentialAssociationStatus,
        attached_at: datetime,
        previous_reference: CloudCredentialReference | None = None,
        rotated_at: datetime | None = None,
    ) -> None:
        self.association_id = association_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.provider_id = provider_id
        self.active_reference = active_reference
        self.status = status
        self.attached_at = attached_at
        self.previous_reference = previous_reference
        self.rotated_at = rotated_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def attach(
        cls,
        association_id: CredentialAssociationId,
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        reference: CloudCredentialReference,
        now: datetime,
    ) -> CredentialAssociation:
        association = cls(
            association_id=association_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider_id=provider_id,
            active_reference=reference,
            status=CredentialAssociationStatus.ACTIVE,
            attached_at=now,
        )
        association._emit(
            CredentialAttached(
                tenant_id=str(tenant_id),
                aggregate_id=str(association_id),
                aggregate_type="CredentialAssociation",
                occurred_at=now,
                account_id=str(account_id),
                provider_id=str(provider_id),
                credential_type=reference.credential_type,
            )
        )
        return association

    def replace(
        self, tenant_id: TenantId, new_reference: CloudCredentialReference, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _REPLACE_FROM:
            raise InvalidCredentialAssociationTransition(self.status.value, "replaced")
        if new_reference.credential_id == self.active_reference.credential_id:
            raise RedundantCredentialReferenceError()

        previous = self.active_reference
        self.previous_reference = previous
        self.active_reference = new_reference
        self.rotated_at = now
        self._emit(
            CredentialReplaced(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.association_id),
                aggregate_type="CredentialAssociation",
                occurred_at=now,
                previous_credential_type=previous.credential_type,
                new_credential_type=new_reference.credential_type,
            )
        )

    def detach(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _DETACH_FROM:
            raise InvalidCredentialAssociationTransition(
                self.status.value, CredentialAssociationStatus.DETACHED.value
            )
        self.status = CredentialAssociationStatus.DETACHED
        self._emit(
            CredentialDetached(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.association_id),
                aggregate_type="CredentialAssociation",
                occurred_at=now,
            )
        )
