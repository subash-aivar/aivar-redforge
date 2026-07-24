"""PostgreSQL ModelProvenance repository with append-only chain persistence."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from ai_supply_chain.domain.aggregates.model_provenance import ModelProvenance
from ai_supply_chain.domain.entities.provenance_chain_entry import ProvenanceChainEntry
from ai_supply_chain.domain.repositories.i_model_provenance_repository import (
    IModelProvenanceRepository,
)
from ai_supply_chain.domain.value_objects.enums import (
    ChainEntryKind,
    ChecksumAlgorithm,
    ModelOrigin,
    ProvenanceIntegrityStatus,
    VerificationMethod,
    VerificationOperationalStatus,
)
from ai_supply_chain.domain.value_objects.identifiers import (
    AISystemAssetId,
    ModelProvenanceId,
    ProvenanceChainEntryId,
    TenantId,
)
from ai_supply_chain.domain.value_objects.supply_chain_vos import (
    CurrentChecksum,
    LastVerifiedChecksum,
    SignatureChainRef,
    SourceRegistryRef,
    TrainingDataLineageRef,
)
from ai_supply_chain.infrastructure.persistence.models.supply_chain_models import (
    ModelProvenanceModel,
    ProvenanceChainEntryModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgModelProvenanceRepository(IModelProvenanceRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, provenance: ModelProvenance) -> None:
        row = await self._session.get(ModelProvenanceModel, provenance.provenance_id.value)
        payload = self._to_row_dict(provenance)
        if row is None:
            self._session.add(ModelProvenanceModel(**payload))
        else:
            for key, value in payload.items():
                if key != "id":
                    setattr(row, key, value)
        # Append-only chain: insert missing entries only (never update)
        existing_ids = set(
            (
                await self._session.execute(
                    select(ProvenanceChainEntryModel.id).where(
                        ProvenanceChainEntryModel.provenance_id == provenance.provenance_id.value
                    )
                )
            ).scalars()
        )
        for entry in provenance.chain_entries:
            if entry.entry_id.value in existing_ids:
                continue
            self._session.add(
                ProvenanceChainEntryModel(
                    id=entry.entry_id.value,
                    tenant_id=provenance.tenant_id.value,
                    provenance_id=provenance.provenance_id.value,
                    entry_kind=entry.entry_kind.value,
                    recorded_at=entry.recorded_at,
                    verification_method=(
                        entry.verification_method.value if entry.verification_method else None
                    ),
                    trust_delegation_note=entry.trust_delegation_note,
                    notes=entry.notes,
                )
            )

    async def find_by_id(
        self, provenance_id: ModelProvenanceId, tenant_id: TenantId
    ) -> ModelProvenance | None:
        row = await self._session.get(ModelProvenanceModel, provenance_id.value)
        if row is None or row.tenant_id != tenant_id.value:
            return None
        return await self._hydrate(row)

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> ModelProvenance | None:
        result = await self._session.execute(
            select(ModelProvenanceModel).where(
                ModelProvenanceModel.tenant_id == tenant_id.value,
                ModelProvenanceModel.ai_system_asset_id == asset_id.value,
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return await self._hydrate(row)

    async def find_mismatched(self, tenant_id: TenantId) -> list[ModelProvenance]:
        result = await self._session.execute(
            select(ModelProvenanceModel).where(
                ModelProvenanceModel.tenant_id == tenant_id.value,
                ModelProvenanceModel.integrity_status == ProvenanceIntegrityStatus.MISMATCHED.value,
            )
        )
        return [await self._hydrate(r) for r in result.scalars()]

    async def _hydrate(self, row: ModelProvenanceModel) -> ModelProvenance:
        entries_result = await self._session.execute(
            select(ProvenanceChainEntryModel)
            .where(ProvenanceChainEntryModel.provenance_id == row.id)
            .order_by(ProvenanceChainEntryModel.recorded_at)
        )
        entries = [
            ProvenanceChainEntry(
                entry_id=ProvenanceChainEntryId(e.id),
                entry_kind=ChainEntryKind(e.entry_kind),
                recorded_at=e.recorded_at,
                verification_method=(
                    VerificationMethod(e.verification_method) if e.verification_method else None
                ),
                trust_delegation_note=e.trust_delegation_note,
                notes=e.notes,
            )
            for e in entries_result.scalars()
        ]
        return ModelProvenance(
            provenance_id=ModelProvenanceId(row.id),
            tenant_id=TenantId.from_uuid(row.tenant_id),
            ai_system_asset_id=AISystemAssetId(row.ai_system_asset_id),
            model_origin=ModelOrigin(row.model_origin),
            source_registry_ref=self._registry(row.source_registry_json),
            training_data_lineage=self._lineage(row.training_lineage_json),
            current_checksum=self._checksum(row.current_checksum_json),
            last_verified_checksum=self._last_checksum(row.last_verified_checksum_json),
            integrity_status=ProvenanceIntegrityStatus(row.integrity_status),
            signature_chain_ref=self._sig(row.signature_chain_json),
            last_verified_at=row.last_verified_at,
            artifact_size_bytes=row.artifact_size_bytes,
            operational_status=VerificationOperationalStatus(row.operational_status),
            consecutive_failures=row.consecutive_failures,
            chain_entries=entries,
            version=row.row_version,
        )

    def _to_row_dict(self, p: ModelProvenance) -> dict[str, Any]:
        return {
            "id": p.provenance_id.value,
            "tenant_id": p.tenant_id.value,
            "ai_system_asset_id": p.ai_system_asset_id.value,
            "model_origin": p.model_origin.value,
            "integrity_status": p.integrity_status.value,
            "operational_status": p.operational_status.value,
            "artifact_size_bytes": p.artifact_size_bytes,
            "current_checksum_json": (
                {"algorithm": p.current_checksum.algorithm.value, "value": p.current_checksum.value}
                if p.current_checksum
                else None
            ),
            "last_verified_checksum_json": (
                {
                    "algorithm": p.last_verified_checksum.algorithm.value,
                    "value": p.last_verified_checksum.value,
                    "verified_at": p.last_verified_checksum.verified_at.isoformat(),
                }
                if p.last_verified_checksum
                else None
            ),
            "signature_chain_json": (
                {
                    "provider": p.signature_chain_ref.provider,
                    "signature_location": p.signature_chain_ref.signature_location,
                    "signing_key_fingerprint": p.signature_chain_ref.signing_key_fingerprint,
                }
                if p.signature_chain_ref
                else None
            ),
            "source_registry_json": (
                {
                    "provider": p.source_registry_ref.provider,
                    "registry_id": p.source_registry_ref.registry_id,
                }
                if p.source_registry_ref
                else None
            ),
            "training_lineage_json": (
                {
                    "description": p.training_data_lineage.description,
                    "source_refs": list(p.training_data_lineage.source_refs),
                }
                if p.training_data_lineage
                else None
            ),
            "last_verified_at": p.last_verified_at,
            "consecutive_failures": p.consecutive_failures,
            "row_version": p.version,
        }

    @staticmethod
    def _checksum(data: dict[str, Any] | None) -> CurrentChecksum | None:
        if not data:
            return None
        return CurrentChecksum(ChecksumAlgorithm(data["algorithm"]), data["value"])

    @staticmethod
    def _last_checksum(data: dict[str, Any] | None) -> LastVerifiedChecksum | None:
        if not data:
            return None
        from datetime import datetime

        return LastVerifiedChecksum(
            ChecksumAlgorithm(data["algorithm"]),
            data["value"],
            datetime.fromisoformat(data["verified_at"]),
        )

    @staticmethod
    def _sig(data: dict[str, Any] | None) -> SignatureChainRef | None:
        if not data:
            return None
        return SignatureChainRef(
            data["provider"], data["signature_location"], data["signing_key_fingerprint"]
        )

    @staticmethod
    def _registry(data: dict[str, Any] | None) -> SourceRegistryRef | None:
        if not data:
            return None
        return SourceRegistryRef(data["provider"], data["registry_id"])

    @staticmethod
    def _lineage(data: dict[str, Any] | None) -> TrainingDataLineageRef | None:
        if not data:
            return None
        return TrainingDataLineageRef(data["description"], tuple(data.get("source_refs") or ()))
