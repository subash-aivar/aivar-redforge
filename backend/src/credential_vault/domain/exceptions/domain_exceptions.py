"""All 23 Credential Vault domain exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.value_objects.credential_name import CredentialName
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        PrincipalId,
        TenantId,
        VaultBackendId,
        VersionId,
    )


class DomainException(Exception):
    """Base for all domain exceptions."""


class InvalidStateTransition(DomainException):
    """Raised when an aggregate method is called in a disallowed state."""

    def __init__(
        self,
        current: str,
        attempted: str,
        credential_id: CredentialId | None = None,
    ) -> None:
        self.current = current
        self.attempted = attempted
        self.credential_id = credential_id
        detail = f"Invalid state transition from {current} via {attempted}"
        if credential_id is not None:
            detail = f"{detail} (credential_id={credential_id})"
        super().__init__(detail)


class CredentialNotFound(DomainException):
    def __init__(self, credential_id: CredentialId, tenant_id: TenantId) -> None:
        self.credential_id = credential_id
        self.tenant_id = tenant_id
        super().__init__(f"Credential not found: {credential_id} for tenant {tenant_id}")


class CredentialAlreadyExists(DomainException):
    def __init__(self, name: CredentialName, tenant_id: TenantId) -> None:
        self.name = name
        self.tenant_id = tenant_id
        super().__init__(f"Credential already exists: {name.value} for tenant {tenant_id}")


class VersionNotFound(DomainException):
    def __init__(self, version_id: VersionId, credential_id: CredentialId) -> None:
        self.version_id = version_id
        self.credential_id = credential_id
        super().__init__(f"Version not found: {version_id} for credential {credential_id}")


class ActiveVersionNotFound(DomainException):
    """Raised when resolution is attempted but no ACTIVE version exists."""

    def __init__(self, credential_id: CredentialId) -> None:
        self.credential_id = credential_id
        super().__init__(f"Active version not found for credential {credential_id}")


class ConcurrentRotationConflict(DomainException):
    """Raised when begin_rotation() is called while state == ROTATING."""

    def __init__(self, credential_id: CredentialId) -> None:
        self.credential_id = credential_id
        super().__init__(f"Concurrent rotation conflict for credential {credential_id}")


class PolicyNotFound(DomainException):
    def __init__(self, policy_id: object) -> None:
        self.policy_id = policy_id
        super().__init__(f"Policy not found: {policy_id}")


class PolicyInUse(DomainException):
    """Raised by repository when delete is attempted on a referenced policy."""

    def __init__(self, policy_id: object, referencing_credential_count: int) -> None:
        self.policy_id = policy_id
        self.referencing_credential_count = referencing_credential_count
        super().__init__(f"Policy {policy_id} in use by {referencing_credential_count} credentials")


class VaultBackendNotFound(DomainException):
    def __init__(self, backend_id: VaultBackendId) -> None:
        self.backend_id = backend_id
        super().__init__(f"Vault backend not found: {backend_id}")


class VaultBackendInUse(DomainException):
    def __init__(self, backend_id: VaultBackendId, credential_count: int) -> None:
        self.backend_id = backend_id
        self.credential_count = credential_count
        super().__init__(f"Vault backend {backend_id} in use by {credential_count} credentials")


class AccessDenied(DomainException):
    """Raised when IPermissionPort returns False for required permission."""

    def __init__(
        self,
        principal_id: PrincipalId,
        required_permission: str,
        credential_id: CredentialId,
    ) -> None:
        self.principal_id = principal_id
        self.required_permission = required_permission
        self.credential_id = credential_id
        super().__init__(
            f"Access denied: principal {principal_id} lacks "
            f"{required_permission} on {credential_id}"
        )


class TenantMismatch(DomainException):
    """Raised when aggregate.tenant_id != caller-supplied tenant_id."""

    def __init__(self, expected: TenantId, actual: TenantId) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"Tenant mismatch: expected {expected}, actual {actual}")


class CredentialIsRevoked(DomainException):
    def __init__(self, credential_id: CredentialId) -> None:
        self.credential_id = credential_id
        super().__init__(f"Credential is revoked: {credential_id}")


class CredentialIsExpired(DomainException):
    def __init__(self, credential_id: CredentialId, expired_at: datetime) -> None:
        self.credential_id = credential_id
        self.expired_at = expired_at
        super().__init__(f"Credential is expired: {credential_id} at {expired_at}")


class CredentialIsDeleted(DomainException):
    def __init__(self, credential_id: CredentialId) -> None:
        self.credential_id = credential_id
        super().__init__(f"Credential is deleted: {credential_id}")


class BreakGlassJustificationRequired(DomainException):
    def __init__(self, credential_id: CredentialId) -> None:
        self.credential_id = credential_id
        super().__init__(f"Break-glass justification required for credential {credential_id}")


class InsufficientApprovers(DomainException):
    def __init__(self, required: int, actual: int, credential_id: CredentialId) -> None:
        self.required = required
        self.actual = actual
        self.credential_id = credential_id
        super().__init__(
            f"Insufficient approvers for {credential_id}: required {required}, actual {actual}"
        )


class RecoveryVersionInvalid(DomainException):
    """Raised when the target version for recovery is PENDING or mismatched."""

    def __init__(self, version_id: VersionId, reason: str) -> None:
        self.version_id = version_id
        self.reason = reason
        super().__init__(f"Recovery version invalid: {version_id} ({reason})")


class OptimisticLockConflict(DomainException):
    """Raised by repositories (not aggregates) on version mismatch."""

    def __init__(self, aggregate_id: str, expected_version: int, actual_version: int) -> None:
        self.aggregate_id = aggregate_id
        self.expected_version = expected_version
        self.actual_version = actual_version
        super().__init__(
            f"Optimistic lock conflict on {aggregate_id}: "
            f"expected {expected_version}, actual {actual_version}"
        )


class InvalidArgument(DomainException):
    """Raised for guard failures in value objects and aggregates."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid argument {field}: {reason}")


class NoPolicyAttached(DomainException):
    """Raised when detach is called with no policy attached, or interval is unset."""

    def __init__(self, credential_id: object, policy_type: str) -> None:
        self.credential_id = credential_id
        self.policy_type = policy_type
        super().__init__(f"No {policy_type} policy attached for {credential_id}")


class DuplicatePolicyName(DomainException):
    def __init__(self, name: str, tenant_id: TenantId, policy_type: str) -> None:
        self.name = name
        self.tenant_id = tenant_id
        self.policy_type = policy_type
        super().__init__(f"Duplicate {policy_type} policy name '{name}' for tenant {tenant_id}")


class ResolvedSecretZeroized(DomainException):
    """Raised when get_plaintext() is called after zero()."""

    def __init__(self) -> None:
        super().__init__("ResolvedSecret has been zeroized")


class EncryptionAuthTagFailure(DomainException):
    """AES-GCM authentication tag verification failed. Ciphertext is corrupted or tampered."""

    def __init__(self) -> None:
        super().__init__("Encryption authentication tag verification failed")


class KmsKeyNotFound(DomainException):
    """KMS master key ID not found or inaccessible."""

    def __init__(self, master_key_id: str) -> None:
        self.master_key_id = master_key_id
        super().__init__(f"KMS master key not found: {master_key_id}")
