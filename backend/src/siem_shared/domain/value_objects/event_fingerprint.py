"""EventFingerprint — stable hash for idempotent re-ingestion (M37 §2.1),
the same design principle as Integration Hub's `AssetIdentity.fingerprint`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from siem_shared.domain.exceptions.domain_exceptions import InvalidFingerprintError


@dataclass(frozen=True, slots=True)
class EventFingerprint:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise InvalidFingerprintError()

    def __str__(self) -> str:
        return self.value

    @classmethod
    def compute(cls, *parts: str) -> EventFingerprint:
        """Deterministically derive a fingerprint from the ordered parts
        that make a source event unique (e.g. vendor + source-native id
        + tenant). Re-ingestion of the same source event always resolves
        to the same fingerprint."""
        raw = ":".join(parts)
        return cls(hashlib.sha256(raw.encode("utf-8")).hexdigest())
