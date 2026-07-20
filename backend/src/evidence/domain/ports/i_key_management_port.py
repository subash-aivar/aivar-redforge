
"""IKeyManagementPort — encryption key lifecycle for evidence blobs.

Key rotation model (Hardening §6)
---------------------------------
* ``EvidenceEncryptionKeyRef`` stores ``key_id`` + ``key_version``.
* ``generate_key_ref`` always returns the current (latest) version for a tenant.
* Historical ciphertext encrypted under older versions remains decryptable via
  ``unwrap`` / ``decrypt`` using the version embedded in the key ref.
* Rotation does **not** invalidate old versions; ``rewrap`` optionally migrates
  ciphertext from an old version to the current version without changing
  ``key_id``.
* Plaintext DEKs never leave the KMS boundary except ephemerally for encrypt/decrypt.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidence.domain.value_objects.evidence_vos import EvidenceEncryptionKeyRef
    from evidence.domain.value_objects.identifiers import TenantId


class IKeyManagementPort(ABC):
    @abstractmethod
    async def generate_key_ref(self, tenant_id: TenantId) -> EvidenceEncryptionKeyRef:
        """Return current key_id + key_version for the tenant."""
        ...

    @abstractmethod
    async def encrypt(
        self,
        tenant_id: TenantId,
        key_ref: EvidenceEncryptionKeyRef,
        plaintext: bytes,
    ) -> bytes:
        """Encrypt plaintext under the specified key version; return ciphertext."""
        ...

    @abstractmethod
    async def decrypt(
        self,
        tenant_id: TenantId,
        key_ref: EvidenceEncryptionKeyRef,
        ciphertext: bytes,
    ) -> bytes:
        """Decrypt ciphertext under the key version in key_ref."""
        ...

    @abstractmethod
    async def rewrap(
        self,
        tenant_id: TenantId,
        old_key_ref: EvidenceEncryptionKeyRef,
        ciphertext: bytes,
    ) -> tuple[bytes, EvidenceEncryptionKeyRef]:
        """Decrypt with old version and re-encrypt under current version."""
        ...
