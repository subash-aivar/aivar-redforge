
"""In-memory evidence blob store — stores ciphertext only."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from evidence.domain.ports.i_evidence_blob_store import IEvidenceBlobStore
from evidence.domain.value_objects.evidence_vos import (
    EvidencePayloadHash,
    EvidenceStorageRef,
)

if TYPE_CHECKING:
    from evidence.domain.value_objects.evidence_vos import EvidenceEncryptionKeyRef
    from evidence.domain.value_objects.identifiers import TenantId


class InMemoryEvidenceBlobStore(IEvidenceBlobStore):
    def __init__(self) -> None:
        # (tenant_id, storage_ref) -> ciphertext
        self._blobs: dict[tuple[str, str], bytes] = {}
        self._key_meta: dict[tuple[str, str], EvidenceEncryptionKeyRef] = {}

    async def put(
        self,
        tenant_id: TenantId,
        ciphertext: bytes,
        key_ref: EvidenceEncryptionKeyRef,
    ) -> EvidenceStorageRef:
        ref = EvidenceStorageRef(f"evidence://{tenant_id}/{uuid7()}")
        key = (str(tenant_id), ref.value)
        self._blobs[key] = ciphertext
        self._key_meta[key] = key_ref
        return ref

    async def get(self, tenant_id: TenantId, storage_ref: EvidenceStorageRef) -> bytes:
        key = (str(tenant_id), storage_ref.value)
        if key not in self._blobs:
            raise KeyError(f"Blob not found: {storage_ref.value}")
        return self._blobs[key]

    async def exists(self, tenant_id: TenantId, storage_ref: EvidenceStorageRef) -> bool:
        return (str(tenant_id), storage_ref.value) in self._blobs

    async def hash_payload(self, payload: bytes) -> EvidencePayloadHash:
        return EvidencePayloadHash.from_payload(payload)

    def tamper(self, tenant_id: TenantId, storage_ref: EvidenceStorageRef) -> None:
        """Test helper: corrupt stored ciphertext without going through domain API."""
        key = (str(tenant_id), storage_ref.value)
        original = self._blobs[key]
        self._blobs[key] = original[:-1] + bytes([(original[-1] ^ 0xFF) if original else 0xFF])
