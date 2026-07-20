
"""IEvidenceBlobStore — encrypted immutable storage for evidence payloads."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidence.domain.value_objects.evidence_vos import (
        EvidenceEncryptionKeyRef,
        EvidencePayloadHash,
        EvidenceStorageRef,
    )
    from evidence.domain.value_objects.identifiers import TenantId


class IEvidenceBlobStore(ABC):
    """Tenant-isolated encrypted blob store. Domain API never stores plaintext."""

    @abstractmethod
    async def put(
        self,
        tenant_id: TenantId,
        ciphertext: bytes,
        key_ref: EvidenceEncryptionKeyRef,
    ) -> EvidenceStorageRef:
        """Store ciphertext only; returns opaque storage reference."""
        ...

    @abstractmethod
    async def get(self, tenant_id: TenantId, storage_ref: EvidenceStorageRef) -> bytes:
        """Return ciphertext bytes for the given ref (caller decrypts via KMS)."""
        ...

    @abstractmethod
    async def exists(self, tenant_id: TenantId, storage_ref: EvidenceStorageRef) -> bool: ...

    @abstractmethod
    async def hash_payload(self, payload: bytes) -> EvidencePayloadHash:
        """Compute SHA-256 of raw (plaintext) payload bytes."""
        ...
