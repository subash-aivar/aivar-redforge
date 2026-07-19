"""IEncryptionPort — encrypt/decrypt using a supplied DEK."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.payloads import EncryptedPayload


class IEncryptionPort(ABC):
    """
    Encrypts/decrypts secret payloads using a provided DEK (bytes).
    The DEK is supplied by IKeyManagementPort — this port never manages keys.
    """

    @abstractmethod
    async def encrypt(self, plaintext: bytes, dek: bytes) -> EncryptedPayload:
        """Encrypt plaintext using dek. Implementation MUST zero dek bytes after use."""

    @abstractmethod
    async def decrypt(self, payload: EncryptedPayload, dek: bytes) -> bytes:
        """
        Decrypt payload using dek.
        Raises DomainException on authentication tag failure.
        Implementation MUST zero dek bytes after use.
        """
