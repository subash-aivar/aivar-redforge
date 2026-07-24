"""PgDetectionEvidenceRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from detection.domain.aggregates.detection_evidence import DetectionEvidence
from detection.domain.exceptions.domain_exceptions import OptimisticLockConflict
from detection.domain.repositories.i_detection_evidence_repository import (
    IDetectionEvidenceRepository,
)
from detection.domain.value_objects.enums import EvidenceIntegrityStatus, EvidenceType
from detection.domain.value_objects.evidence import (
    EvidenceCollectedBy,
    EvidencePayloadHash,
    EvidenceStorageRef,
    ExceptionRef,
    FindingRef,
    SimulationRef,
)
from detection.domain.value_objects.identifiers import (
    DetectionEvidenceId,
    DetectionExceptionId,
    DetectionFindingId,
    TenantId,
)
from detection.infrastructure.persistence.models.pack_exception_evidence_model import (
    DetectionEvidenceModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgDetectionEvidenceRepository(IDetectionEvidenceRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_model(self, evidence: DetectionEvidence) -> DetectionEvidenceModel:
        return DetectionEvidenceModel(
            id=evidence.evidence_id.value,
            tenant_id=evidence.tenant_id.value,
            evidence_type=evidence.evidence_type.value,
            payload_hash=str(evidence.payload_hash),
            storage_ref=str(evidence.storage_ref),
            collected_by=evidence.collected_by.identity,
            collected_at=evidence.collected_at,
            integrity_status=evidence.integrity_status.value,
            finding_id=evidence.finding_ref.finding_id if evidence.finding_ref else None,
            exception_id=(
                evidence.exception_ref.exception_id if evidence.exception_ref else None
            ),
            simulation_id=(
                evidence.simulation_ref.simulation_id if evidence.simulation_ref else None
            ),
            created_at=evidence.created_at,
            updated_at=evidence.updated_at,
            row_version=evidence.version,
        )

    def _to_domain(self, model: DetectionEvidenceModel) -> DetectionEvidence:
        return DetectionEvidence(
            evidence_id=DetectionEvidenceId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            evidence_type=EvidenceType(model.evidence_type),
            payload_hash=EvidencePayloadHash(model.payload_hash),
            storage_ref=EvidenceStorageRef(model.storage_ref),
            collected_by=EvidenceCollectedBy(model.collected_by),
            collected_at=model.collected_at,
            integrity_status=EvidenceIntegrityStatus(model.integrity_status),
            created_at=model.created_at,
            updated_at=model.updated_at,
            finding_ref=FindingRef(model.finding_id) if model.finding_id else None,
            exception_ref=(
                ExceptionRef(model.exception_id) if model.exception_id else None
            ),
            simulation_ref=(
                SimulationRef(model.simulation_id) if model.simulation_id else None
            ),
            version=model.row_version,
        )

    async def save(self, evidence: DetectionEvidence) -> None:
        existing = await self._session.execute(
            select(DetectionEvidenceModel).where(
                DetectionEvidenceModel.id == evidence.evidence_id.value
            )
        )
        row = existing.scalar_one_or_none()
        model = self._to_model(evidence)
        if row is None:
            self._session.add(model)
        else:
            if row.row_version > evidence.version:
                raise OptimisticLockConflict(str(evidence.evidence_id))
            # Append-only: only integrity_status / updated_at / row_version may change
            row.integrity_status = model.integrity_status
            row.updated_at = model.updated_at
            row.row_version = model.row_version
        await self._session.flush()

    async def find_by_id(
        self, evidence_id: DetectionEvidenceId, tenant_id: TenantId
    ) -> DetectionEvidence | None:
        result = await self._session.execute(
            select(DetectionEvidenceModel).where(
                DetectionEvidenceModel.id == evidence_id.value,
                DetectionEvidenceModel.tenant_id == tenant_id.value,
            )
        )
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None

    async def find_by_finding(
        self,
        finding_id: DetectionFindingId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionEvidence]:
        result = await self._session.execute(
            select(DetectionEvidenceModel)
            .where(
                DetectionEvidenceModel.tenant_id == tenant_id.value,
                DetectionEvidenceModel.finding_id == str(finding_id),
            )
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_by_exception(
        self,
        exception_id: DetectionExceptionId,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionEvidence]:
        result = await self._session.execute(
            select(DetectionEvidenceModel)
            .where(
                DetectionEvidenceModel.tenant_id == tenant_id.value,
                DetectionEvidenceModel.exception_id == str(exception_id),
            )
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionEvidence]:
        result = await self._session.execute(
            select(DetectionEvidenceModel)
            .where(DetectionEvidenceModel.tenant_id == tenant_id.value)
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]
