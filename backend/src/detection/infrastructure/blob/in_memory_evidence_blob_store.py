"""In-memory evidence blob store for tests and local composition."""

from __future__ import annotations

from detection.domain.ports.i_evidence_blob_store import IEvidenceBlobStore
from detection.domain.value_objects.evidence import (
    EvidencePayloadHash,
    EvidenceStorageRef,
)


class InMemoryEvidenceBlobStore(IEvidenceBlobStore):
    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}

    async def put(self, storage_ref: EvidenceStorageRef, payload: bytes) -> None:
        self._store[str(storage_ref)] = payload

    async def get(self, storage_ref: EvidenceStorageRef) -> bytes:
        key = str(storage_ref)
        if key not in self._store:
            raise KeyError(key)
        return self._store[key]

    async def exists(self, storage_ref: EvidenceStorageRef) -> bool:
        return str(storage_ref) in self._store

    def hash_payload(self, payload: bytes) -> EvidencePayloadHash:
        return EvidencePayloadHash.from_payload(payload)
