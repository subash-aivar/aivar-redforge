"""Domain events for DetectionEvidence aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionEvidenceSubmitted(BaseDomainEvent):
    evidence_type: str
    payload_hash: str
    storage_ref: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionEvidenceIntegrityVerified(BaseDomainEvent):
    payload_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionEvidenceIntegrityFailed(BaseDomainEvent):
    expected_hash: str
    actual_hash: str
