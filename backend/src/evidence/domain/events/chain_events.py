
"""Domain events for EvidenceChain."""

from __future__ import annotations

from dataclasses import dataclass

from evidence.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceChainOpened(BaseDomainEvent):
    operation_id: str
    engagement_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceChainEntryAdded(BaseDomainEvent):
    evidence_id: str
    sequence: int
    chain_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceChainSealed(BaseDomainEvent):
    sealed_by: str
    chain_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceChainSubmitted(BaseDomainEvent):
    destination_ref: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceChainArchived(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceChainIntegrityVerified(BaseDomainEvent):
    chain_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceChainIntegrityFailed(BaseDomainEvent):
    expected_hash: str
    computed_hash: str
