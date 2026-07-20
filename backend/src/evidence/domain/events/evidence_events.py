
"""Domain events for ExecutionEvidence."""

from __future__ import annotations

from dataclasses import dataclass

from evidence.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionEvidenceCollected(BaseDomainEvent):
    evidence_type: str
    action_id: str
    operation_id: str
    payload_hash: str
    storage_ref: str
    collected_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceIntegrityVerified(BaseDomainEvent):
    payload_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceIntegrityFailed(BaseDomainEvent):
    expected_hash: str
    computed_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceCustodyTransferred(BaseDomainEvent):
    from_custodian: str
    to_custodian: str
    custody_action: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceRetentionExpired(BaseDomainEvent):
    retention_class: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceQuarantined(BaseDomainEvent):
    reason: str
