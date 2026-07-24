"""Credential API schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CreateCredentialRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    name: str
    category: str
    subtype: str
    schema_id: UUID | None = None
    vault_backend_id: UUID
    plaintext_secret: str
    description: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    expires_at: datetime | None = None


class UpdateCredentialMetadataRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    description: str | None = None
    tags: dict[str, str] | None = None


class ResolveCredentialRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    purpose: str
    break_glass: bool = False
    justification: str | None = None


class RotateCredentialRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    new_plaintext_secret: str
    trigger: str = "MANUAL"
    policy_id: UUID | None = None
    notes: str | None = None


class DisableCredentialRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    reason: str


class RevokeCredentialRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    reason: str


class EmergencyRevokeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    justification: str


class RecoverCredentialRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    target_version_id: UUID
    justification: str


class RollbackVersionRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    target_version_id: UUID


class AttachRotationPolicyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    policy_id: UUID


class AttachExpirationPolicyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    policy_id: UUID


class DetachPolicyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    reason: str | None = None


class CredentialResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    credential_id: UUID
    tenant_id: str
    name: str
    category: str
    subtype: str
    schema_id: UUID | None
    state: str
    owner_principal_id: UUID
    active_version_id: UUID | None
    rotation_policy_id: UUID | None
    expiration_policy_id: UUID | None
    vault_backend_id: UUID
    description: str | None
    tags: dict[str, str]
    created_at: datetime
    updated_at: datetime
    version: int

    @classmethod
    def from_dto(cls, dto: object) -> CredentialResponse:
        data = dto.to_dict()  # type: ignore[attr-defined]
        for key in (
            "credential_id",
            "owner_principal_id",
            "active_version_id",
            "rotation_policy_id",
            "expiration_policy_id",
            "vault_backend_id",
            "schema_id",
        ):
            if data.get(key) is not None:
                data[key] = UUID(str(data[key]))
            else:
                data[key] = None
        data["tenant_id"] = str(data["tenant_id"])
        data["created_at"] = datetime.fromisoformat(str(data["created_at"]))
        data["updated_at"] = datetime.fromisoformat(str(data["updated_at"]))
        return cls(**data)


class VersionResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    version_id: UUID
    credential_id: UUID
    tenant_id: str
    version_number: int
    version_state: str
    created_by: UUID
    created_at: datetime
    expires_at: datetime | None
    rotation_trigger: str | None
    rotation_policy_id: UUID | None

    @classmethod
    def from_dto(cls, dto: object) -> VersionResponse:
        data = dto.to_dict()  # type: ignore[attr-defined]
        for key in (
            "version_id",
            "credential_id",
            "created_by",
            "rotation_policy_id",
        ):
            if data.get(key) is not None:
                data[key] = UUID(str(data[key]))
            else:
                data[key] = None
        data["tenant_id"] = str(data["tenant_id"])
        data["created_at"] = datetime.fromisoformat(str(data["created_at"]))
        expires = data.get("expires_at")
        data["expires_at"] = datetime.fromisoformat(str(expires)) if expires is not None else None
        return cls(**data)


class ResolveCredentialResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    credential_id: UUID
    version_id: UUID
    secret_b64: str
    resolved_at: datetime


class ListCredentialsResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    items: list[CredentialResponse]
    total: int
    limit: int
    offset: int


class ListVersionsResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    items: list[VersionResponse]
