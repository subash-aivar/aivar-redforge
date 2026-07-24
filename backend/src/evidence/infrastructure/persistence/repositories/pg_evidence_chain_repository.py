
"""PgEvidenceChainRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select, update

from evidence.domain.aggregates.evidence_chain import EvidenceChain
from evidence.domain.exceptions.domain_exceptions import OptimisticLockConflict
from evidence.domain.repositories.i_repositories import IEvidenceChainRepository
from evidence.domain.value_objects.enums import ChainIntegrityStatus, ChainState
from evidence.domain.value_objects.evidence_vos import ChainEntry, ChainHash, SealedBy
from evidence.domain.value_objects.identifiers import (
    EngagementRef,
    EvidenceChainId,
    OperationRef,
    TenantId,
)
from evidence.infrastructure.persistence.models.evidence_models import EvidenceChainModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgEvidenceChainRepository(IEvidenceChainRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_model(self, chain: EvidenceChain) -> EvidenceChainModel:
        sealed = chain.sealed_by
        return EvidenceChainModel(
            id=chain.chain_id.value,
            tenant_id=chain.tenant_id.value,
            operation_id=chain.operation_ref.value,
            engagement_id=chain.engagement_ref.value,
            state=chain.state.value,
            chain_hash=chain.chain_hash.value,
            integrity_status=chain.integrity_status.value,
            entries_json={
                "entries": [
                    {
                        "evidence_id": str(e.evidence_id),
                        "sequence": e.sequence,
                        "entry_hash": e.entry_hash,
                    }
                    for e in chain.entries
                ]
            },
            sealed_by_operator_id=sealed.operator_id if sealed else None,
            sealed_at=sealed.sealed_at if sealed else None,
            sealer_role=sealed.role if sealed else None,
            seal_signature=sealed.signature if sealed else None,
            submission_destination_ref=chain.submission_destination_ref,
            created_at=chain.created_at,
            updated_at=chain.updated_at,
            row_version=chain.version,
        )

    def _to_domain(self, model: EvidenceChainModel) -> EvidenceChain:
        entries = [
            ChainEntry(
                evidence_id=UUID(e["evidence_id"]),
                sequence=e["sequence"],
                entry_hash=e["entry_hash"],
            )
            for e in model.entries_json.get("entries", [])
        ]
        sealed = None
        if model.sealed_by_operator_id is not None and model.sealed_at is not None:
            sealed = SealedBy(
                operator_id=model.sealed_by_operator_id,
                sealed_at=model.sealed_at,
                role=model.sealer_role or "",
                signature=model.seal_signature or "",
            )
        return EvidenceChain(
            chain_id=EvidenceChainId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            operation_ref=OperationRef(model.operation_id),
            engagement_ref=EngagementRef(model.engagement_id),
            entries=entries,
            chain_hash=ChainHash(model.chain_hash),
            state=ChainState(model.state),
            integrity_status=ChainIntegrityStatus(model.integrity_status),
            sealed_by=sealed,
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
            submission_destination_ref=model.submission_destination_ref,
        )

    async def save(self, chain: EvidenceChain) -> None:
        existing = await self._session.get(EvidenceChainModel, chain.chain_id.value)
        if existing is None:
            self._session.add(self._to_model(chain))
            await self._session.flush()
            return

        expected = existing.row_version
        result = await self._session.execute(
            update(EvidenceChainModel)
            .where(
                EvidenceChainModel.id == chain.chain_id.value,
                EvidenceChainModel.row_version == expected,
            )
            .values(
                state=chain.state.value,
                chain_hash=chain.chain_hash.value,
                integrity_status=chain.integrity_status.value,
                entries_json={
                    "entries": [
                        {
                            "evidence_id": str(e.evidence_id),
                            "sequence": e.sequence,
                            "entry_hash": e.entry_hash,
                        }
                        for e in chain.entries
                    ]
                },
                sealed_by_operator_id=(
                    chain.sealed_by.operator_id if chain.sealed_by else None
                ),
                sealed_at=chain.sealed_by.sealed_at if chain.sealed_by else None,
                sealer_role=chain.sealed_by.role if chain.sealed_by else None,
                seal_signature=chain.sealed_by.signature if chain.sealed_by else None,
                submission_destination_ref=chain.submission_destination_ref,
                updated_at=chain.updated_at,
                row_version=chain.version,
            )
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            raise OptimisticLockConflict("EvidenceChain", str(chain.chain_id))

    async def find_by_id(
        self, chain_id: EvidenceChainId, tenant_id: TenantId
    ) -> EvidenceChain | None:
        model = await self._session.get(EvidenceChainModel, chain_id.value)
        if model is None or model.tenant_id != tenant_id.value:
            return None
        return self._to_domain(model)

    async def find_by_operation(
        self, operation_ref: OperationRef, tenant_id: TenantId
    ) -> EvidenceChain | None:
        result = await self._session.execute(
            select(EvidenceChainModel).where(
                EvidenceChainModel.tenant_id == tenant_id.value,
                EvidenceChainModel.operation_id == operation_ref.value,
            )
        )
        model = result.scalar_one_or_none()
        return self._to_domain(model) if model else None
