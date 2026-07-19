"""UUID identity value objects for the Credential Vault domain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CredentialId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("CredentialId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("TenantId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class VersionId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("VersionId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PrincipalId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("PrincipalId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RotationPolicyId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("RotationPolicyId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ExpirationPolicyId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ExpirationPolicyId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class VaultBackendId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("VaultBackendId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AuditLogId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("AuditLogId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AuditEntryId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("AuditEntryId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)
