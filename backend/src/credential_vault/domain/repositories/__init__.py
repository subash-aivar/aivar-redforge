"""Credential Vault repository interfaces."""

from credential_vault.domain.repositories.i_audit_log_repository import IAuditLogRepository
from credential_vault.domain.repositories.i_credential_repository import (
    ICredentialRepository,
)
from credential_vault.domain.repositories.i_credential_version_repository import (
    ICredentialVersionRepository,
)
from credential_vault.domain.repositories.i_expiration_policy_repository import (
    IExpirationPolicyRepository,
)
from credential_vault.domain.repositories.i_rotation_policy_repository import (
    IRotationPolicyRepository,
)
from credential_vault.domain.repositories.i_vault_backend_repository import (
    IVaultBackendRepository,
)

__all__ = [
    "IAuditLogRepository",
    "ICredentialRepository",
    "ICredentialVersionRepository",
    "IExpirationPolicyRepository",
    "IRotationPolicyRepository",
    "IVaultBackendRepository",
]
