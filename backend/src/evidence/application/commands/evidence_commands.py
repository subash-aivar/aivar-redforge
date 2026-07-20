
"""Evidence application commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CollectEvidence:
    tenant_id: UUID
    action_id: UUID
    engagement_id: UUID
    operation_id: UUID
    evidence_type: str
    payload: bytes
    collected_by: str
    retention_class: str = "Standard"
    corrects_evidence_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class VerifyEvidenceIntegrity:
    tenant_id: UUID
    evidence_id: UUID


@dataclass(frozen=True, slots=True)
class TransferCustody:
    tenant_id: UUID
    evidence_id: UUID
    new_custodian: str
    custody_action: str = "Transferred"


@dataclass(frozen=True, slots=True)
class RequestEvidenceDeletion:
    tenant_id: UUID
    evidence_id: UUID


@dataclass(frozen=True, slots=True)
class OpenEvidenceChain:
    tenant_id: UUID
    operation_id: UUID
    engagement_id: UUID


@dataclass(frozen=True, slots=True)
class AddEvidenceToChain:
    tenant_id: UUID
    chain_id: UUID
    evidence_id: UUID


@dataclass(frozen=True, slots=True)
class SealEvidenceChain:
    tenant_id: UUID
    chain_id: UUID
    sealer_operator_id: UUID
    sealer_role: str
    signature: str


@dataclass(frozen=True, slots=True)
class SubmitEvidenceChain:
    tenant_id: UUID
    chain_id: UUID
    destination_ref: str


@dataclass(frozen=True, slots=True)
class QueryEvidenceChainIntegrity:
    tenant_id: UUID
    chain_id: UUID
