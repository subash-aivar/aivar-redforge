"""IEvidenceBlobStore — durable storage for detection evidence payloads."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection.domain.value_objects.evidence import (
        EvidencePayloadHash,
        EvidenceStorageRef,
    )


class IEvidenceBlobStore(ABC):
    """Stores raw evidence bytes; PostgreSQL holds only metadata + hash."""

    @abstractmethod
    async def put(self, storage_ref: EvidenceStorageRef, payload: bytes) -> None: ...

    @abstractmethod
    async def get(self, storage_ref: EvidenceStorageRef) -> bytes: ...

    @abstractmethod
    async def exists(self, storage_ref: EvidenceStorageRef) -> bool: ...

    @abstractmethod
    def hash_payload(self, payload: bytes) -> EvidencePayloadHash: ...
