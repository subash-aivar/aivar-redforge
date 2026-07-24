
"""PgExecutionEvidenceRepository."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select, update

from evidence.domain.aggregates.execution_evidence import ExecutionEvidence
from evidence.domain.exceptions.domain_exceptions import OptimisticLockConflict
from evidence.domain.repositories.i_repositories import IExecutionEvidenceRepository
from evidence.domain.value_objects.enums import (
    CustodyAction,
    EvidenceIntegrityStatus,
    EvidenceType,
    RetentionClass,
)
from evidence.domain.value_objects.evidence_vos import (
    CollectedAt,
    CollectedBy,
    CorrectionsRef,
    CustodyRecord,
    EvidenceEncryptionKeyRef,
    EvidencePayloadHash,
    EvidenceStorageRef,
)
from evidence.domain.value_objects.identifiers import (
    AttackActionRef,
    EngagementRef,
    ExecutionEvidenceId,
    OperationRef,
    TenantId,
)
from evidence.infrastructure.persistence.models.evidence_models import (
    ExecutionEvidenceModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgExecutionEvidenceRepository(IExecutionEvidenceRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_model(self, ev: ExecutionEvidence) -> ExecutionEvidenceModel:
        return ExecutionEvidenceModel(
            id=ev.evidence_id.value,
            tenant_id=ev.tenant_id.value,
            evidence_type=ev.evidence_type.value,
            payload_hash=ev.payload_hash.value,
            storage_ref=ev.storage_ref.value,
            key_id=ev.encryption_key_ref.key_id,
            key_version=ev.encryption_key_ref.key_version,
            action_id=ev.action_ref.value,
            engagement_id=ev.engagement_ref.value,
            operation_id=ev.operation_ref.value,
            collected_at=ev.collected_at.value,
            collected_by=ev.collected_by.identity,
            integrity_status=ev.integrity_status.value,
            retention_class=ev.retention_class.value,
            corrections_ref=(
                ev.corrections_ref.evidence_id if ev.corrections_ref else None
            ),
            custody_chain_json={
                "records": [
                    {
                        "custodian_identity": c.custodian_identity,
                        "timestamp": c.timestamp.isoformat(),
                        "action": c.action.value,
                    }
                    for c in ev.custody_chain
                ]
            },
            quarantined=ev.quarantined,
            retention_expired=ev.retention_expired,
            created_at=ev.created_at,
            updated_at=ev.updated_at,
            row_version=ev.version,
        )

    def _to_domain(self, model: ExecutionEvidenceModel) -> ExecutionEvidence:
        records_raw = model.custody_chain_json.get("records", [])
        custody = [
            CustodyRecord(
                custodian_identity=r["custodian_identity"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
                action=CustodyAction(r["action"]),
            )
            for r in records_raw
        ]
        return ExecutionEvidence(
            evidence_id=ExecutionEvidenceId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            evidence_type=EvidenceType(model.evidence_type),
            payload_hash=EvidencePayloadHash(model.payload_hash),
            storage_ref=EvidenceStorageRef(model.storage_ref),
            encryption_key_ref=EvidenceEncryptionKeyRef(
                key_id=model.key_id, key_version=model.key_version
            ),
            action_ref=AttackActionRef(model.action_id),
            engagement_ref=EngagementRef(model.engagement_id),
            operation_ref=OperationRef(model.operation_id),
            collected_at=CollectedAt(model.collected_at),
            collected_by=CollectedBy(model.collected_by),
            integrity_status=EvidenceIntegrityStatus(model.integrity_status),
            retention_class=RetentionClass(model.retention_class),
            custody_chain=custody,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
            corrections_ref=(
                CorrectionsRef(model.corrections_ref)
                if model.corrections_ref is not None
                else None
            ),
            quarantined=model.quarantined,
            retention_expired=model.retention_expired,
        )

    async def save(self, evidence: ExecutionEvidence) -> None:
        existing = await self._session.get(ExecutionEvidenceModel, evidence.evidence_id.value)
        if existing is None:
            self._session.add(self._to_model(evidence))
            await self._session.flush()
            return

        expected = existing.row_version
        if evidence.version != expected + 1 and evidence.version != expected:
            # Domain already bumped version on mutate; accept expected+1 after load version
            pass
        result = await self._session.execute(
            update(ExecutionEvidenceModel)
            .where(
                ExecutionEvidenceModel.id == evidence.evidence_id.value,
                ExecutionEvidenceModel.row_version == expected,
            )
            .values(
                integrity_status=evidence.integrity_status.value,
                custody_chain_json={
                    "records": [
                        {
                            "custodian_identity": c.custodian_identity,
                            "timestamp": c.timestamp.isoformat(),
                            "action": c.action.value,
                        }
                        for c in evidence.custody_chain
                    ]
                },
                quarantined=evidence.quarantined,
                retention_expired=evidence.retention_expired,
                updated_at=evidence.updated_at,
                row_version=evidence.version,
            )
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise OptimisticLockConflict("ExecutionEvidence", str(evidence.evidence_id))

    async def find_by_id(
        self, evidence_id: ExecutionEvidenceId, tenant_id: TenantId
    ) -> ExecutionEvidence | None:
        model = await self._session.get(ExecutionEvidenceModel, evidence_id.value)
        if model is None or model.tenant_id != tenant_id.value:
            return None
        return self._to_domain(model)

    async def find_by_action(
        self, action_ref: AttackActionRef, tenant_id: TenantId
    ) -> list[ExecutionEvidence]:
        result = await self._session.execute(
            select(ExecutionEvidenceModel).where(
                ExecutionEvidenceModel.tenant_id == tenant_id.value,
                ExecutionEvidenceModel.action_id == action_ref.value,
            )
        )
        return [self._to_domain(m) for m in result.scalars().all()]

    async def find_by_operation(
        self,
        operation_ref: OperationRef,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExecutionEvidence]:
        result = await self._session.execute(
            select(ExecutionEvidenceModel)
            .where(
                ExecutionEvidenceModel.tenant_id == tenant_id.value,
                ExecutionEvidenceModel.operation_id == operation_ref.value,
            )
            .order_by(ExecutionEvidenceModel.collected_at)
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(m) for m in result.scalars().all()]
