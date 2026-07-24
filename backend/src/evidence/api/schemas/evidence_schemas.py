"""API request/response schemas for evidence."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from evidence.application.dtos.evidence_dtos import (
    ChainIntegrityReportDTO,
    EvidenceChainDTO,
    ExecutionEvidenceDTO,
    IntegrityVerificationResultDTO,
)


class CollectEvidenceRequest(BaseModel):
    action_id: UUID
    engagement_id: UUID
    operation_id: UUID
    evidence_type: str
    payload_b64: str = Field(min_length=1, description="Base64-encoded evidence payload")
    collected_by: str = Field(min_length=1, max_length=256)
    retention_class: str = "Standard"
    corrects_evidence_id: UUID | None = None


class TransferCustodyRequest(BaseModel):
    new_custodian: str = Field(min_length=1, max_length=256)
    custody_action: str = "Transferred"


class OpenEvidenceChainRequest(BaseModel):
    operation_id: UUID
    engagement_id: UUID


class AddEvidenceToChainRequest(BaseModel):
    evidence_id: UUID


class SealEvidenceChainRequest(BaseModel):
    sealer_operator_id: UUID
    sealer_role: str = Field(min_length=1, max_length=128)
    signature: str = Field(min_length=1)


class SubmitEvidenceChainRequest(BaseModel):
    destination_ref: str = Field(min_length=1, max_length=512)


class CustodyRecordResponse(BaseModel):
    custodian_identity: str
    timestamp: datetime
    action: str


class ExecutionEvidenceResponse(BaseModel):
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
    custody_chain: list[CustodyRecordResponse]
    corrects_evidence_id: str | None
    version: int

    @classmethod
    def from_dto(cls, dto: ExecutionEvidenceDTO) -> ExecutionEvidenceResponse:
        return cls(
            evidence_id=dto.evidence_id,
            tenant_id=str(dto.tenant_id),
            evidence_type=dto.evidence_type,
            payload_hash=dto.payload_hash,
            storage_ref=dto.storage_ref,
            key_id=dto.key_id,
            key_version=dto.key_version,
            action_id=dto.action_id,
            engagement_id=dto.engagement_id,
            operation_id=dto.operation_id,
            collected_at=dto.collected_at,
            collected_by=dto.collected_by,
            integrity_status=dto.integrity_status,
            retention_class=dto.retention_class,
            quarantined=dto.quarantined,
            retention_expired=dto.retention_expired,
            custody_chain=[
                CustodyRecordResponse(
                    custodian_identity=c.custodian_identity,
                    timestamp=c.timestamp,
                    action=c.action,
                )
                for c in dto.custody_chain
            ],
            corrects_evidence_id=dto.corrects_evidence_id,
            version=dto.version,
        )


class ListEvidenceResponse(BaseModel):
    items: list[ExecutionEvidenceResponse]


class ChainEntryResponse(BaseModel):
    evidence_id: str
    sequence: int
    entry_hash: str


class EvidenceChainResponse(BaseModel):
    chain_id: str
    tenant_id: str
    operation_id: str
    engagement_id: str
    state: str
    chain_hash: str
    integrity_status: str
    entries: list[ChainEntryResponse]
    sealed_by_operator_id: str | None
    sealed_at: datetime | None
    sealer_role: str | None
    submission_destination_ref: str | None
    version: int

    @classmethod
    def from_dto(cls, dto: EvidenceChainDTO) -> EvidenceChainResponse:
        return cls(
            chain_id=dto.chain_id,
            tenant_id=str(dto.tenant_id),
            operation_id=dto.operation_id,
            engagement_id=dto.engagement_id,
            state=dto.state,
            chain_hash=dto.chain_hash,
            integrity_status=dto.integrity_status,
            entries=[
                ChainEntryResponse(
                    evidence_id=e.evidence_id,
                    sequence=e.sequence,
                    entry_hash=e.entry_hash,
                )
                for e in dto.entries
            ],
            sealed_by_operator_id=dto.sealed_by_operator_id,
            sealed_at=dto.sealed_at,
            sealer_role=dto.sealer_role,
            submission_destination_ref=dto.submission_destination_ref,
            version=dto.version,
        )


class ListEvidenceChainsResponse(BaseModel):
    items: list[EvidenceChainResponse]


class IntegrityVerificationResponse(BaseModel):
    evidence_id: str
    status: str
    payload_hash: str

    @classmethod
    def from_dto(cls, dto: IntegrityVerificationResultDTO) -> IntegrityVerificationResponse:
        return cls(
            evidence_id=dto.evidence_id,
            status=dto.status,
            payload_hash=dto.payload_hash,
        )


class ChainIntegrityReportResponse(BaseModel):
    chain_id: str
    status: str
    expected_hash: str
    computed_hash: str
    entry_count: int

    @classmethod
    def from_dto(cls, dto: ChainIntegrityReportDTO) -> ChainIntegrityReportResponse:
        return cls(
            chain_id=dto.chain_id,
            status=dto.status,
            expected_hash=dto.expected_hash,
            computed_hash=dto.computed_hash,
            entry_count=dto.entry_count,
        )
