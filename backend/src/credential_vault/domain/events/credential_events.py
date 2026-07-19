"""Credential lifecycle domain events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from credential_vault.domain.events.base import BaseDomainEvent
from credential_vault.domain.value_objects.states import CredentialState

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.value_objects.credential_name import CredentialName
    from credential_vault.domain.value_objects.credential_type import CredentialType
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        ExpirationPolicyId,
        PrincipalId,
        RotationPolicyId,
        VaultBackendId,
        VersionId,
    )
    from credential_vault.domain.value_objects.rotation_context import RotationContext


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialCreated(BaseDomainEvent):
    credential_id: CredentialId
    name: CredentialName
    credential_type: CredentialType
    owner_principal: PrincipalId
    vault_backend_id: VaultBackendId
    tags: dict[str, str]


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialVersionCreated(BaseDomainEvent):
    credential_id: CredentialId
    version_id: VersionId
    version_number: int
    created_by: PrincipalId
    expires_at: datetime | None


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialRotationStarted(BaseDomainEvent):
    credential_id: CredentialId
    new_version_id: VersionId
    previous_version_id: VersionId
    rotation_context: RotationContext


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialRotated(BaseDomainEvent):
    credential_id: CredentialId
    new_version_id: VersionId
    superseded_version_id: VersionId
    rotation_context: RotationContext | None


@dataclass(frozen=True, slots=True, kw_only=True)
class RotationAborted(BaseDomainEvent):
    credential_id: CredentialId
    aborted_version_id: VersionId
    reverted_to_version_id: VersionId
    reason: str
    principal_id: PrincipalId


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialDisabled(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialEnabled(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialRevoked(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId
    reason: str
    active_version_id: VersionId | None


@dataclass(frozen=True, slots=True, kw_only=True)
class EmergencyRevoked(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId
    justification: str
    state_before: CredentialState


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialExpired(BaseDomainEvent):
    credential_id: CredentialId
    active_version_id: VersionId | None
    expires_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialExpirationWarning(BaseDomainEvent):
    credential_id: CredentialId
    active_version_id: VersionId | None
    expires_at: datetime
    days_remaining: int


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialAccessed(BaseDomainEvent):
    credential_id: CredentialId
    version_id: VersionId
    principal_id: PrincipalId
    client_ip: str | None
    purpose: str
    break_glass: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class BreakGlassAccessed(BaseDomainEvent):
    credential_id: CredentialId
    version_id: VersionId
    principal_id: PrincipalId
    justification: str
    approvers: int


@dataclass(frozen=True, slots=True, kw_only=True)
class EmergencyOverrideAccessed(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId
    justification: str
    bypassed_checks: list[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialRecovered(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId
    recovered_version_id: VersionId
    previous_state: CredentialState = CredentialState.REVOKED


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialRenewed(BaseDomainEvent):
    credential_id: CredentialId
    version_id: VersionId
    new_expires_at: datetime | None


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialDeleted(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId
    deleted_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class CredentialMetadataUpdated(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId
    changed_fields: list[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class VersionRolledBack(BaseDomainEvent):
    credential_id: CredentialId
    principal_id: PrincipalId
    rolled_back_to_version_id: VersionId
    previous_active_version_id: VersionId | None


@dataclass(frozen=True, slots=True, kw_only=True)
class RotationPolicyAttached(BaseDomainEvent):
    credential_id: CredentialId
    policy_id: RotationPolicyId
    principal_id: PrincipalId


@dataclass(frozen=True, slots=True, kw_only=True)
class RotationPolicyDetached(BaseDomainEvent):
    credential_id: CredentialId
    policy_id: RotationPolicyId
    principal_id: PrincipalId


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpirationPolicyAttached(BaseDomainEvent):
    credential_id: CredentialId
    policy_id: ExpirationPolicyId
    principal_id: PrincipalId


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpirationPolicyDetached(BaseDomainEvent):
    credential_id: CredentialId
    policy_id: ExpirationPolicyId
    principal_id: PrincipalId


@dataclass(frozen=True, slots=True, kw_only=True)
class BulkRevocationInitiated(BaseDomainEvent):
    initiating_principal: PrincipalId
    credential_ids: list[CredentialId]
    reason: str
