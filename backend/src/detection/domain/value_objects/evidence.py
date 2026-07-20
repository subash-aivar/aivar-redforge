"""Value objects for DetectionEvidence aggregate."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from detection.domain.exceptions.domain_exceptions import InvalidArgument

if TYPE_CHECKING:
    from datetime import datetime

_HEX64 = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True, slots=True)
class EvidencePayloadHash:
    """SHA-256 of evidence content."""

    value: str

    def __post_init__(self) -> None:
        cleaned = self.value.strip().lower()
        if not _HEX64.match(cleaned):
            raise InvalidArgument(
                "EvidencePayloadHash", "must be 64-character hex SHA-256 digest"
            )
        object.__setattr__(self, "value", cleaned)

    @classmethod
    def from_payload(cls, payload: bytes) -> EvidencePayloadHash:
        return cls(hashlib.sha256(payload).hexdigest())

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class EvidenceStorageRef:
    """Pointer to blob in durable store — content never stored in domain model."""

    uri: str

    def __post_init__(self) -> None:
        cleaned = self.uri.strip()
        if not cleaned:
            raise InvalidArgument("EvidenceStorageRef.uri", "required")
        if len(cleaned) > 2048:
            raise InvalidArgument("EvidenceStorageRef.uri", "max 2048 characters")
        object.__setattr__(self, "uri", cleaned)

    def __str__(self) -> str:
        return self.uri


@dataclass(frozen=True, slots=True)
class EvidenceCollectedAt:
    value: datetime


@dataclass(frozen=True, slots=True)
class EvidenceCollectedBy:
    identity: str

    def __post_init__(self) -> None:
        if not self.identity.strip():
            raise InvalidArgument("EvidenceCollectedBy.identity", "required")
        object.__setattr__(self, "identity", self.identity.strip()[:256])


@dataclass(frozen=True, slots=True)
class FindingRef:
    finding_id: str

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise InvalidArgument("FindingRef.finding_id", "required")
        object.__setattr__(self, "finding_id", self.finding_id.strip())


@dataclass(frozen=True, slots=True)
class ExceptionRef:
    exception_id: str

    def __post_init__(self) -> None:
        if not self.exception_id.strip():
            raise InvalidArgument("ExceptionRef.exception_id", "required")
        object.__setattr__(self, "exception_id", self.exception_id.strip())


@dataclass(frozen=True, slots=True)
class SimulationRef:
    simulation_id: str

    def __post_init__(self) -> None:
        if not self.simulation_id.strip():
            raise InvalidArgument("SimulationRef.simulation_id", "required")
        object.__setattr__(self, "simulation_id", self.simulation_id.strip())
