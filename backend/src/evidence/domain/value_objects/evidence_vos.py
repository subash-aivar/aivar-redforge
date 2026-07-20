
"""Domain value objects for the evidence context."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from evidence.domain.value_objects.enums import CustodyAction

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class EvidencePayloadHash:
    value: str

    def __post_init__(self) -> None:
        if not _SHA256_RE.match(self.value):
            raise ValueError("EvidencePayloadHash must be a 64-char lowercase hex SHA-256")

    @classmethod
    def from_payload(cls, payload: bytes) -> EvidencePayloadHash:
        return cls(hashlib.sha256(payload).hexdigest())

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class EvidenceStorageRef:
    value: str

    def __post_init__(self) -> None:
        if not self.value or len(self.value) > 512:
            raise ValueError("EvidenceStorageRef must be 1-512 characters")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class EvidenceEncryptionKeyRef:
    """Reference to a KMS key including version for rotation (Hardening §6).

    Key rotation creates a new ``key_version``; historical evidence encrypted
    under older versions remains decryptable. Rewrap updates ciphertext to
    the current version without changing the logical ``key_id``.
    """

    key_id: str
    key_version: int

    def __post_init__(self) -> None:
        if not self.key_id or len(self.key_id) > 256:
            raise ValueError("key_id must be 1-256 characters")
        if self.key_version < 1:
            raise ValueError("key_version must be >= 1")


@dataclass(frozen=True, slots=True)
class CollectedAt:
    value: datetime

    def __str__(self) -> str:
        return self.value.isoformat()


@dataclass(frozen=True, slots=True)
class CollectedBy:
    """Operator or worker identity that collected the evidence."""

    identity: str

    def __post_init__(self) -> None:
        if not self.identity or len(self.identity) > 256:
            raise ValueError("CollectedBy.identity must be 1-256 characters")


@dataclass(frozen=True, slots=True)
class CorrectionsRef:
    evidence_id: UUID

    def __post_init__(self) -> None:
        if self.evidence_id.int == 0:
            raise ValueError("CorrectionsRef must not be nil UUID")


@dataclass(frozen=True, slots=True)
class CustodyRecord:
    custodian_identity: str
    timestamp: datetime
    action: CustodyAction

    def __post_init__(self) -> None:
        if not self.custodian_identity or len(self.custodian_identity) > 256:
            raise ValueError("custodian_identity must be 1-256 characters")


@dataclass(frozen=True, slots=True)
class ChainEntry:
    evidence_id: UUID
    sequence: int
    entry_hash: str

    def __post_init__(self) -> None:
        if self.evidence_id.int == 0:
            raise ValueError("ChainEntry.evidence_id must not be nil UUID")
        if self.sequence < 1:
            raise ValueError("ChainEntry.sequence must be >= 1")
        if not _SHA256_RE.match(self.entry_hash):
            raise ValueError("ChainEntry.entry_hash must be SHA-256 hex")


@dataclass(frozen=True, slots=True)
class ChainHash:
    value: str

    def __post_init__(self) -> None:
        if not _SHA256_RE.match(self.value):
            raise ValueError("ChainHash must be a 64-char lowercase hex SHA-256")

    @classmethod
    def from_entry_hashes(cls, entry_hashes: list[str]) -> ChainHash:
        concatenated = "".join(entry_hashes).encode("utf-8")
        return cls(hashlib.sha256(concatenated).hexdigest())

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class SealedBy:
    operator_id: UUID
    sealed_at: datetime
    role: str
    signature: str

    def __post_init__(self) -> None:
        if self.operator_id.int == 0:
            raise ValueError("SealedBy.operator_id must not be nil UUID")
        if not self.role:
            raise ValueError("SealedBy.role must not be empty")
        if not self.signature:
            raise ValueError("SealedBy.signature must not be empty")


@dataclass(frozen=True, slots=True)
class ChainIntegrityReport:
    chain_id: str
    status: str
    expected_hash: str
    computed_hash: str
    entry_count: int
