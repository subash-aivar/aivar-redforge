"""Immutable CQRS command objects for Credential Integration (M45D).
Every command carries a `CloudCredentialReference` only — never secret
material. `CredentialAssociation` remains the single aggregate these
commands act against."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.cloud_credential_reference import (
        CloudCredentialReference,
    )
    from cloud_security.domain.value_objects.identifiers import AccountId, ProviderId, TenantId


@dataclass(frozen=True, slots=True)
class AttachCredentialCommand:
    tenant_id: TenantId
    account_id: AccountId
    provider_id: ProviderId
    reference: CloudCredentialReference


@dataclass(frozen=True, slots=True)
class ReplaceCredentialCommand:
    tenant_id: TenantId
    reference: CloudCredentialReference


@dataclass(frozen=True, slots=True)
class DetachCredentialCommand:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class RotateCredentialReferenceCommand:
    tenant_id: TenantId
    reference: CloudCredentialReference


@dataclass(frozen=True, slots=True)
class ValidateCredentialReferenceCommand:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class BatchCredentialCommand:
    tenant_id: TenantId
    commands: tuple[AttachCredentialCommand, ...] = field(default_factory=tuple)
