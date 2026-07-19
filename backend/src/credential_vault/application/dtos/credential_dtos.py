"""Credential, version, and resolved-secret DTOs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.credential import Credential
    from credential_vault.domain.entities.credential_version import CredentialVersion


@dataclass(frozen=True, slots=True)
class CredentialDTO:
    credential_id: str
    tenant_id: str
    name: str
    category: str
    subtype: str
    schema_id: str | None
    state: str
    owner_principal_id: str
    active_version_id: str | None
    rotation_policy_id: str | None
    expiration_policy_id: str | None
    vault_backend_id: str
    description: str | None
    tags: dict[str, str]
    created_at: str
    updated_at: str
    version: int

    @classmethod
    def from_aggregate(cls, credential: Credential) -> Self:
        schema_id = (
            str(credential.credential_type.schema_id)
            if credential.credential_type.schema_id is not None
            else None
        )
        active_version_id = (
            str(credential.active_version_id) if credential.active_version_id is not None else None
        )
        rotation_policy_id = (
            str(credential.rotation_policy_id)
            if credential.rotation_policy_id is not None
            else None
        )
        expiration_policy_id = (
            str(credential.expiration_policy_id)
            if credential.expiration_policy_id is not None
            else None
        )
        return cls(
            credential_id=str(credential.credential_id),
            tenant_id=str(credential.tenant_id),
            name=credential.name.value,
            category=credential.credential_type.category.value,
            subtype=credential.credential_type.subtype,
            schema_id=schema_id,
            state=credential.state.value,
            owner_principal_id=str(credential.owner_principal),
            active_version_id=active_version_id,
            rotation_policy_id=rotation_policy_id,
            expiration_policy_id=expiration_policy_id,
            vault_backend_id=str(credential.vault_backend_id),
            description=credential.description,
            tags=dict(credential.tags),
            created_at=credential.created_at.isoformat(),
            updated_at=credential.updated_at.isoformat(),
            version=credential.version,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "credential_id": self.credential_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "category": self.category,
            "subtype": self.subtype,
            "schema_id": self.schema_id,
            "state": self.state,
            "owner_principal_id": self.owner_principal_id,
            "active_version_id": self.active_version_id,
            "rotation_policy_id": self.rotation_policy_id,
            "expiration_policy_id": self.expiration_policy_id,
            "vault_backend_id": self.vault_backend_id,
            "description": self.description,
            "tags": dict(self.tags),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class VersionDTO:
    version_id: str
    credential_id: str
    tenant_id: str
    version_number: int
    version_state: str
    created_by: str
    created_at: str
    expires_at: str | None
    rotation_trigger: str | None
    rotation_policy_id: str | None

    @classmethod
    def from_entity(cls, version: CredentialVersion) -> Self:
        expires_at = version.expires_at.isoformat() if version.expires_at is not None else None
        if version.rotation_context is None:
            rotation_trigger: str | None = None
            rotation_policy_id: str | None = None
        else:
            rotation_trigger = version.rotation_context.trigger.value
            rotation_policy_id = (
                str(version.rotation_context.policy_id)
                if version.rotation_context.policy_id is not None
                else None
            )
        return cls(
            version_id=str(version.version_id),
            credential_id=str(version.credential_id),
            tenant_id=str(version.tenant_id),
            version_number=version.version_number,
            version_state=version.version_state.value,
            created_by=str(version.created_by),
            created_at=version.created_at.isoformat(),
            expires_at=expires_at,
            rotation_trigger=rotation_trigger,
            rotation_policy_id=rotation_policy_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "version_id": self.version_id,
            "credential_id": self.credential_id,
            "tenant_id": self.tenant_id,
            "version_number": self.version_number,
            "version_state": self.version_state,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "rotation_trigger": self.rotation_trigger,
            "rotation_policy_id": self.rotation_policy_id,
        }


@dataclass(frozen=True, slots=True)
class ResolvedSecretDTO:
    credential_id: str
    version_id: str
    plaintext_secret: bytes
    resolved_at: str
