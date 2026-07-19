"""Pydantic schemas for credential vault API."""

from credential_vault.api.schemas.audit_schemas import AuditEntryResponse, ListAuditEntriesResponse
from credential_vault.api.schemas.backend_schemas import (
    RegisterVaultBackendRequest,
    VaultBackendResponse,
)
from credential_vault.api.schemas.credential_schemas import (
    AttachExpirationPolicyRequest,
    AttachRotationPolicyRequest,
    CreateCredentialRequest,
    CredentialResponse,
    DetachPolicyRequest,
    DisableCredentialRequest,
    EmergencyRevokeRequest,
    ListCredentialsResponse,
    ListVersionsResponse,
    RecoverCredentialRequest,
    ResolveCredentialRequest,
    ResolveCredentialResponse,
    RevokeCredentialRequest,
    RollbackVersionRequest,
    RotateCredentialRequest,
    UpdateCredentialMetadataRequest,
    VersionResponse,
)
from credential_vault.api.schemas.policy_schemas import (
    CreateExpirationPolicyRequest,
    CreateRotationPolicyRequest,
    ExpirationPolicyResponse,
    RotationPolicyResponse,
    UpdateExpirationPolicyRequest,
    UpdateRotationPolicyRequest,
)

__all__ = [
    "AttachExpirationPolicyRequest",
    "AttachRotationPolicyRequest",
    "AuditEntryResponse",
    "CreateCredentialRequest",
    "CreateExpirationPolicyRequest",
    "CreateRotationPolicyRequest",
    "CredentialResponse",
    "DetachPolicyRequest",
    "DisableCredentialRequest",
    "EmergencyRevokeRequest",
    "ExpirationPolicyResponse",
    "ListAuditEntriesResponse",
    "ListCredentialsResponse",
    "ListVersionsResponse",
    "RecoverCredentialRequest",
    "RegisterVaultBackendRequest",
    "ResolveCredentialRequest",
    "ResolveCredentialResponse",
    "RevokeCredentialRequest",
    "RollbackVersionRequest",
    "RotateCredentialRequest",
    "RotationPolicyResponse",
    "UpdateCredentialMetadataRequest",
    "UpdateExpirationPolicyRequest",
    "UpdateRotationPolicyRequest",
    "VaultBackendResponse",
    "VersionResponse",
]
