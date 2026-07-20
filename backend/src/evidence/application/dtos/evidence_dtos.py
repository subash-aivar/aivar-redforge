
"""Evidence application DTOs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class CustodyRecordDTO:
    custodian_identity: str
    timestamp: datetime
    action: str


@dataclass(frozen=True, slots=True)
class ExecutionEvidenceDTO:
    evidence_id: str
    tenant_id: str
    evidence_type: str
    payload_hash: str
    storage_ref: str
    key_id: str
    key_version: int
    action_id: str
    engagement_id: str
    operation_id: str
    collected_at: datetime
    collected_by: str
    integrity_status: str
    retention_class: str
    quarantined: bool
    retention_expired: bool
    custody_chain: tuple[CustodyRecordDTO, ...]
    corrects_evidence_id: str | None
    version: int


@dataclass(frozen=True, slots=True)
class ChainEntryDTO:
    evidence_id: str
    sequence: int
    entry_hash: str


@dataclass(frozen=True, slots=True)
class EvidenceChainDTO:
    chain_id: str
    tenant_id: str
    operation_id: str
    engagement_id: str
    state: str
    chain_hash: str
    integrity_status: str
    entries: tuple[ChainEntryDTO, ...]
    sealed_by_operator_id: str | None
    sealed_at: datetime | None
    sealer_role: str | None
    submission_destination_ref: str | None
    version: int


@dataclass(frozen=True, slots=True)
class ChainIntegrityReportDTO:
    chain_id: str
    status: str
    expected_hash: str
    computed_hash: str
    entry_count: int


@dataclass(frozen=True, slots=True)
class IntegrityVerificationResultDTO:
    evidence_id: str
    status: str
    payload_hash: str
