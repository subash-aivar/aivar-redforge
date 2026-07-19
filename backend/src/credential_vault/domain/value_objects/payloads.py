"""Encrypted payload, key envelope, and resolved secret value objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.value_objects.identifiers import CredentialId, VersionId


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """Ciphertext produced by IEncryptionPort. Opaque to domain logic."""

    ciphertext: bytes
    algorithm: str
    iv: bytes
    tag: bytes
    payload_size: int

    def __post_init__(self) -> None:
        if not self.ciphertext:
            raise ValueError("ciphertext empty")
        if not self.algorithm:
            raise ValueError("algorithm empty")
        if len(self.algorithm) > 64:
            raise ValueError("algorithm max 64 chars")
        if not self.iv:
            raise ValueError("iv empty")
        if not self.tag:
            raise ValueError("tag empty")
        if self.payload_size <= 0:
            raise ValueError("payload_size must be > 0")


@dataclass(frozen=True, slots=True)
class KeyEnvelope:
    """Wrapped DEK produced by IKeyManagementPort."""

    wrapped_dek: bytes
    master_key_id: str
    wrapping_algorithm: str
    created_at: datetime

    def __post_init__(self) -> None:
        if not self.wrapped_dek:
            raise ValueError("wrapped_dek empty")
        if not self.master_key_id:
            raise ValueError("master_key_id empty")
        if len(self.master_key_id) > 256:
            raise ValueError("master_key_id max 256")
        if not self.wrapping_algorithm:
            raise ValueError("wrapping_algorithm empty")
        if len(self.wrapping_algorithm) > 64:
            raise ValueError("wrapping_algorithm max 64 chars")


class ResolvedSecret:
    """
    SECURITY-SENSITIVE value object. NOT a frozen dataclass.
    Must be manually zeroed after use. Never logged, never serialized.
    """

    __slots__ = (
        "_credential_id",
        "_plaintext",
        "_resolved_at",
        "_version_id",
        "_zeroed",
    )

    def __init__(
        self,
        plaintext: bytes,
        credential_id: CredentialId,
        version_id: VersionId,
        resolved_at: datetime,
    ) -> None:
        if not plaintext:
            raise ValueError("plaintext empty")
        self._plaintext = bytearray(plaintext)
        self._credential_id = credential_id
        self._version_id = version_id
        self._resolved_at = resolved_at
        self._zeroed = False

    @property
    def credential_id(self) -> CredentialId:
        return self._credential_id

    @property
    def version_id(self) -> VersionId:
        return self._version_id

    @property
    def resolved_at(self) -> datetime:
        return self._resolved_at

    def get_plaintext(self) -> bytes:
        if self._zeroed:
            from credential_vault.domain.exceptions.domain_exceptions import (
                ResolvedSecretZeroized,
            )

            raise ResolvedSecretZeroized()
        return bytes(self._plaintext)

    def zero(self) -> None:
        """Overwrite plaintext in memory. Must be called in finally block by caller."""
        for i in range(len(self._plaintext)):
            self._plaintext[i] = 0
        self._zeroed = True

    def __repr__(self) -> str:
        return "ResolvedSecret(***REDACTED***)"

    def __str__(self) -> str:
        return "***REDACTED***"
