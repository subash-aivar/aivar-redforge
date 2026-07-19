"""Credential aggregate root."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from credential_vault.domain.events.credential_events import (
    CredentialCreated,
    CredentialDeleted,
    CredentialDisabled,
    CredentialEnabled,
    CredentialExpired,
    CredentialMetadataUpdated,
    CredentialRecovered,
    CredentialRenewed,
    CredentialRevoked,
    CredentialRotated,
    CredentialRotationStarted,
    CredentialVersionCreated,
    EmergencyRevoked,
    ExpirationPolicyAttached,
    ExpirationPolicyDetached,
    RotationAborted,
    RotationPolicyAttached,
    RotationPolicyDetached,
    VersionRolledBack,
)
from credential_vault.domain.exceptions.domain_exceptions import (
    ConcurrentRotationConflict,
    InvalidArgument,
    InvalidStateTransition,
    NoPolicyAttached,
    TenantMismatch,
)
from credential_vault.domain.value_objects.states import CredentialState

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.events.base import BaseDomainEvent
    from credential_vault.domain.value_objects.credential_name import CredentialName
    from credential_vault.domain.value_objects.credential_type import CredentialType
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        ExpirationPolicyId,
        PrincipalId,
        RotationPolicyId,
        TenantId,
        VaultBackendId,
        VersionId,
    )
    from credential_vault.domain.value_objects.rotation_context import RotationContext


class Credential:
    """Credential aggregate root — lifecycle, policies, and version pointer."""

    __slots__ = (
        "_pending_events",
        "_pending_new_version_id",
        "_pending_rotation_context",
        "_version",
        "active_version_id",
        "created_at",
        "credential_id",
        "credential_type",
        "description",
        "expiration_policy_id",
        "name",
        "owner_principal",
        "rotation_policy_id",
        "state",
        "tags",
        "tenant_id",
        "updated_at",
        "vault_backend_id",
    )

    def __init__(
        self,
        credential_id: CredentialId,
        tenant_id: TenantId,
        name: CredentialName,
        credential_type: CredentialType,
        state: CredentialState,
        owner_principal: PrincipalId,
        active_version_id: VersionId | None,
        rotation_policy_id: RotationPolicyId | None,
        expiration_policy_id: ExpirationPolicyId | None,
        vault_backend_id: VaultBackendId,
        description: str | None,
        tags: dict[str, str],
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.credential_id = credential_id
        self.tenant_id = tenant_id
        self.name = name
        self.credential_type = credential_type
        self.state = state
        self.owner_principal = owner_principal
        self.active_version_id = active_version_id
        self.rotation_policy_id = rotation_policy_id
        self.expiration_policy_id = expiration_policy_id
        self.vault_backend_id = vault_backend_id
        self.description = description
        self.tags = dict(tags)
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []
        self._pending_new_version_id: VersionId | None = None
        self._pending_rotation_context: RotationContext | None = None

    @classmethod
    def create(
        cls,
        credential_id: CredentialId,
        tenant_id: TenantId,
        name: CredentialName,
        credential_type: CredentialType,
        owner_principal: PrincipalId,
        vault_backend_id: VaultBackendId,
        description: str | None,
        tags: dict[str, str],
        now: datetime,
    ) -> Credential:
        cls._validate_metadata(description, tags)
        credential = cls(
            credential_id=credential_id,
            tenant_id=tenant_id,
            name=name,
            credential_type=credential_type,
            state=CredentialState.PENDING,
            owner_principal=owner_principal,
            active_version_id=None,
            rotation_policy_id=None,
            expiration_policy_id=None,
            vault_backend_id=vault_backend_id,
            description=description,
            tags=tags,
            created_at=now,
            updated_at=now,
            version=0,
        )
        credential._emit(
            CredentialCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(credential_id),
                aggregate_type="Credential",
                credential_id=credential_id,
                name=name,
                credential_type=credential_type,
                owner_principal=owner_principal,
                vault_backend_id=vault_backend_id,
                tags=dict(tags),
            )
        )
        return credential

    @staticmethod
    def _validate_metadata(description: str | None, tags: dict[str, str]) -> None:
        if len(tags) > 50:
            raise InvalidArgument("tags", "max 50 tags")
        for key, value in tags.items():
            if len(key) > 100:
                raise InvalidArgument("tags", "tag key max 100 chars")
            if len(value) > 1000:
                raise InvalidArgument("tags", "tag value max 1000 chars")
        if description is not None and len(description) > 2048:
            raise InvalidArgument("description", "max 2048 chars")

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch(expected=self.tenant_id, actual=tenant_id)

    def _assert_not_deleted(self, attempted: str) -> None:
        if self.state == CredentialState.DELETED:
            raise InvalidStateTransition(
                current=self.state.value,
                attempted=attempted,
                credential_id=self.credential_id,
            )

    def _require_state(self, allowed: set[CredentialState], attempted: str) -> None:
        if self.state not in allowed:
            raise InvalidStateTransition(
                current=self.state.value,
                attempted=attempted,
                credential_id=self.credential_id,
            )

    def _mutate(self, now: datetime) -> None:
        self._version += 1
        self.updated_at = now

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def record_domain_event(self, event: BaseDomainEvent) -> None:
        """Append an externally produced domain event (e.g. access audit)."""
        self._pending_events.append(event)

    def activate(
        self, tenant_id: TenantId, version_id: VersionId, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state({CredentialState.PENDING}, "activate")
        self.state = CredentialState.ACTIVE
        self.active_version_id = version_id
        self._mutate(now)
        self._emit(
            CredentialVersionCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                version_id=version_id,
                version_number=1,
                created_by=self.owner_principal,
                expires_at=None,
            )
        )

    def begin_rotation(
        self,
        tenant_id: TenantId,
        version_id: VersionId,
        context: RotationContext,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state == CredentialState.ROTATING:
            raise ConcurrentRotationConflict(self.credential_id)
        self._require_state({CredentialState.ACTIVE}, "begin_rotation")
        if self.active_version_id is None:
            raise InvalidStateTransition(
                current=self.state.value,
                attempted="begin_rotation",
                credential_id=self.credential_id,
            )
        previous = self.active_version_id
        self.state = CredentialState.ROTATING
        self._pending_new_version_id = version_id
        self._pending_rotation_context = context
        self._mutate(now)
        self._emit(
            CredentialRotationStarted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                new_version_id=version_id,
                previous_version_id=previous,
                rotation_context=context,
            )
        )

    def commit_rotation(
        self,
        tenant_id: TenantId,
        new_version_id: VersionId,
        old_version_id: VersionId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state({CredentialState.ROTATING}, "commit_rotation")
        self.state = CredentialState.ACTIVE
        self.active_version_id = new_version_id
        context = self._pending_rotation_context
        self._pending_new_version_id = None
        self._pending_rotation_context = None
        self._mutate(now)
        self._emit(
            CredentialRotated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                new_version_id=new_version_id,
                superseded_version_id=old_version_id,
                rotation_context=context,
            )
        )

    def abort_rotation(
        self,
        tenant_id: TenantId,
        reason: str,
        principal: PrincipalId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state({CredentialState.ROTATING}, "abort_rotation")
        if self.active_version_id is None or self._pending_new_version_id is None:
            raise InvalidStateTransition(
                current=self.state.value,
                attempted="abort_rotation",
                credential_id=self.credential_id,
            )
        aborted = self._pending_new_version_id
        reverted = self.active_version_id
        self.state = CredentialState.ACTIVE
        self._pending_new_version_id = None
        self._pending_rotation_context = None
        self._mutate(now)
        self._emit(
            RotationAborted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                aborted_version_id=aborted,
                reverted_to_version_id=reverted,
                reason=reason,
                principal_id=principal,
            )
        )

    def disable(
        self,
        tenant_id: TenantId,
        principal: PrincipalId,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state({CredentialState.ACTIVE}, "disable")
        self.state = CredentialState.DISABLED
        self._mutate(now)
        self._emit(
            CredentialDisabled(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                principal_id=principal,
                reason=reason,
            )
        )

    def enable(
        self, tenant_id: TenantId, principal: PrincipalId, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state({CredentialState.DISABLED}, "enable")
        self.state = CredentialState.ACTIVE
        self._mutate(now)
        self._emit(
            CredentialEnabled(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                principal_id=principal,
            )
        )

    def revoke(
        self,
        tenant_id: TenantId,
        principal: PrincipalId,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state(
            {
                CredentialState.ACTIVE,
                CredentialState.ROTATING,
                CredentialState.DISABLED,
            },
            "revoke",
        )
        self.state = CredentialState.REVOKED
        self._pending_new_version_id = None
        self._pending_rotation_context = None
        self._mutate(now)
        self._emit(
            CredentialRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                principal_id=principal,
                reason=reason,
                active_version_id=self.active_version_id,
            )
        )

    def emergency_revoke(
        self,
        tenant_id: TenantId,
        principal: PrincipalId,
        justification: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_deleted("emergency_revoke")
        state_before = self.state
        self.state = CredentialState.REVOKED
        self._pending_new_version_id = None
        self._pending_rotation_context = None
        self._mutate(now)
        self._emit(
            EmergencyRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                principal_id=principal,
                justification=justification,
                state_before=state_before,
            )
        )

    def expire(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._require_state(
            {CredentialState.ACTIVE, CredentialState.DISABLED}, "expire"
        )
        self.state = CredentialState.EXPIRED
        self._mutate(now)
        self._emit(
            CredentialExpired(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                active_version_id=self.active_version_id,
                expires_at=now,
            )
        )

    def recover(
        self,
        tenant_id: TenantId,
        principal: PrincipalId,
        version_id: VersionId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state({CredentialState.REVOKED}, "recover")
        self.state = CredentialState.ACTIVE
        self.active_version_id = version_id
        self._mutate(now)
        self._emit(
            CredentialRecovered(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                principal_id=principal,
                recovered_version_id=version_id,
                previous_state=CredentialState.REVOKED,
            )
        )

    def renew(
        self,
        tenant_id: TenantId,
        version_id: VersionId,
        new_expiry: datetime | None,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state({CredentialState.EXPIRED}, "renew")
        self.state = CredentialState.ACTIVE
        self.active_version_id = version_id
        self._mutate(now)
        self._emit(
            CredentialRenewed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                version_id=version_id,
                new_expires_at=new_expiry,
            )
        )

    def hard_delete(
        self, tenant_id: TenantId, principal: PrincipalId, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state(
            {
                CredentialState.REVOKED,
                CredentialState.EXPIRED,
                CredentialState.DISABLED,
            },
            "hard_delete",
        )
        self.state = CredentialState.DELETED
        self._mutate(now)
        self._emit(
            CredentialDeleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                principal_id=principal,
                deleted_at=now,
            )
        )

    def attach_rotation_policy(
        self,
        tenant_id: TenantId,
        policy_id: RotationPolicyId,
        principal: PrincipalId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state(
            {
                CredentialState.PENDING,
                CredentialState.ACTIVE,
                CredentialState.ROTATING,
                CredentialState.DISABLED,
            },
            "attach_rotation_policy",
        )
        if self.rotation_policy_id is not None:
            raise InvalidArgument(
                "rotation_policy_id",
                "policy already attached — detach first",
            )
        self.rotation_policy_id = policy_id
        self._mutate(now)
        self._emit(
            RotationPolicyAttached(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                policy_id=policy_id,
                principal_id=principal,
            )
        )

    def detach_rotation_policy(
        self, tenant_id: TenantId, principal: PrincipalId, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_deleted("detach_rotation_policy")
        if self.rotation_policy_id is None:
            raise NoPolicyAttached(self.credential_id, "rotation")
        policy_id = self.rotation_policy_id
        self.rotation_policy_id = None
        self._mutate(now)
        self._emit(
            RotationPolicyDetached(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                policy_id=policy_id,
                principal_id=principal,
            )
        )

    def attach_expiration_policy(
        self,
        tenant_id: TenantId,
        policy_id: ExpirationPolicyId,
        principal: PrincipalId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state(
            {
                CredentialState.PENDING,
                CredentialState.ACTIVE,
                CredentialState.ROTATING,
                CredentialState.DISABLED,
            },
            "attach_expiration_policy",
        )
        if self.expiration_policy_id is not None:
            raise InvalidArgument(
                "expiration_policy_id",
                "policy already attached — detach first",
            )
        self.expiration_policy_id = policy_id
        self._mutate(now)
        self._emit(
            ExpirationPolicyAttached(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                policy_id=policy_id,
                principal_id=principal,
            )
        )

    def detach_expiration_policy(
        self, tenant_id: TenantId, principal: PrincipalId, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_deleted("detach_expiration_policy")
        if self.expiration_policy_id is None:
            raise NoPolicyAttached(self.credential_id, "expiration")
        policy_id = self.expiration_policy_id
        self.expiration_policy_id = None
        self._mutate(now)
        self._emit(
            ExpirationPolicyDetached(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                policy_id=policy_id,
                principal_id=principal,
            )
        )

    def update_metadata(
        self,
        tenant_id: TenantId,
        description: str | None,
        tags: dict[str, str],
        principal: PrincipalId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_not_deleted("update_metadata")
        self._validate_metadata(description, tags)
        changed: list[str] = []
        if description != self.description:
            changed.append("description")
            self.description = description
        if tags != self.tags:
            changed.append("tags")
            self.tags = dict(tags)
        self._mutate(now)
        self._emit(
            CredentialMetadataUpdated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                principal_id=principal,
                changed_fields=changed,
            )
        )

    def rollback_version(
        self,
        tenant_id: TenantId,
        version_id: VersionId,
        principal: PrincipalId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._require_state({CredentialState.ACTIVE}, "rollback_version")
        previous = self.active_version_id
        self.active_version_id = version_id
        self._mutate(now)
        self._emit(
            VersionRolledBack(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.credential_id),
                aggregate_type="Credential",
                credential_id=self.credential_id,
                principal_id=principal,
                rolled_back_to_version_id=version_id,
                previous_active_version_id=previous,
            )
        )

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @property
    def version(self) -> int:
        return self._version

    def is_resolvable(self) -> bool:
        return self.state == CredentialState.ACTIVE
