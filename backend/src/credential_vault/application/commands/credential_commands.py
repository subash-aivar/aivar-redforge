"""Credential lifecycle command dataclasses (CQRS write side)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003 — runtime type for frozen dataclass fields
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields


@dataclass(frozen=True, slots=True)
class CreateCredentialCommand:
    tenant_id: UUID
    name: str
    category: str
    subtype: str
    schema_id: UUID | None
    owner_principal_id: UUID
    vault_backend_id: UUID
    plaintext_secret: bytes
    description: str | None
    tags: dict[str, str]
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ResolveCredentialCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    purpose: str
    client_ip: str | None = None
    request_id: str | None = None
    break_glass: bool = False
    justification: str | None = None


@dataclass(frozen=True, slots=True)
class RotateCredentialCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    new_plaintext_secret: bytes
    trigger: str
    policy_id: UUID | None = None
    notes: str | None = None


@dataclass(frozen=True, slots=True)
class CommitRotationCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class AbortRotationCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class DisableCredentialCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class EnableCredentialCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class RevokeCredentialCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class EmergencyRevokeCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    justification: str


@dataclass(frozen=True, slots=True)
class ExpireCredentialCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class RecoverCredentialCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    target_version_id: UUID
    justification: str


@dataclass(frozen=True, slots=True)
class HardDeleteCredentialCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class RollbackVersionCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    target_version_id: UUID


@dataclass(frozen=True, slots=True)
class UpdateCredentialMetadataCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    description: str | None
    tags: dict[str, str]


@dataclass(frozen=True, slots=True)
class AttachRotationPolicyCommand:
    tenant_id: UUID
    credential_id: UUID
    policy_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class DetachRotationPolicyCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class AttachExpirationPolicyCommand:
    tenant_id: UUID
    credential_id: UUID
    policy_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class DetachExpirationPolicyCommand:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
