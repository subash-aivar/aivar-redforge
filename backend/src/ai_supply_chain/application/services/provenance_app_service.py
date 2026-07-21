from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from ai_supply_chain.application._auth import require_at_least
from ai_supply_chain.application.dtos.supply_chain_dtos import ModelProvenanceDTO
from ai_supply_chain.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_supply_chain.domain.aggregates.model_provenance import ModelProvenance
from ai_supply_chain.domain.exceptions.domain_exceptions import SupplyChainDomainError
from ai_supply_chain.domain.services.provenance_verification_service import (
    ProvenanceVerificationService,
)
from ai_supply_chain.domain.value_objects.enums import AIPostureRole, ModelOrigin
from ai_supply_chain.domain.value_objects.identifiers import (
    AISystemAssetId,
    ModelProvenanceId,
    TenantId,
)
from ai_supply_chain.domain.value_objects.supply_chain_vos import (
    ArtifactDescriptor,
    SignatureChainRef,
    SourceRegistryRef,
    TrainingDataLineageRef,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_supply_chain.application.commands.supply_chain_commands import (
        ManualResetVerificationCommand,
        RecordModelProvenanceCommand,
        SetVerificationThresholdCommand,
        VerifyModelProvenanceCommand,
    )
    from ai_supply_chain.application.ports.i_event_publisher import IEventPublisher
    from ai_supply_chain.application.ports.i_unit_of_work import IUnitOfWork
    from ai_supply_chain.domain.ports.i_artifact_hash_port import IArtifactHashPort
    from ai_supply_chain.domain.ports.i_provider_signature_port import (
        IProviderSignaturePort,
    )


def _to_dto(p: ModelProvenance) -> ModelProvenanceDTO:
    latest_method = None
    latest_note = ""
    for entry in reversed(p.chain_entries):
        if entry.verification_method is not None:
            latest_method = entry.verification_method.value
            latest_note = entry.trust_delegation_note
            break
    return ModelProvenanceDTO(
        provenance_id=str(p.provenance_id),
        tenant_id=str(p.tenant_id),
        ai_system_asset_id=str(p.ai_system_asset_id),
        model_origin=p.model_origin.value,
        integrity_status=p.integrity_status.value,
        operational_status=p.operational_status.value,
        artifact_size_bytes=p.artifact_size_bytes,
        verification_method_latest=latest_method,
        trust_delegation_note_latest=latest_note,
        chain_entry_count=len(p.chain_entries),
        consecutive_failures=p.consecutive_failures,
    )


class ProvenanceApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        hash_port: IArtifactHashPort,
        signature_port: IProviderSignaturePort,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._verifier = ProvenanceVerificationService(hash_port, signature_port)

    async def record(self, cmd: RecordModelProvenanceCommand) -> ModelProvenanceDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        try:
            origin = ModelOrigin(cmd.model_origin)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        async with self._uow_factory() as uow:
            existing = await uow.provenances.find_by_asset(AISystemAssetId(cmd.asset_id), tenant)
            if existing is not None:
                return _to_dto(existing)
            registry = None
            if cmd.registry_provider and cmd.registry_id:
                registry = SourceRegistryRef(cmd.registry_provider, cmd.registry_id)
            lineage = None
            if cmd.training_data_description:
                lineage = TrainingDataLineageRef(cmd.training_data_description)
            prov = ModelProvenance.record(
                ModelProvenanceId.generate(),
                tenant,
                AISystemAssetId(cmd.asset_id),
                origin,
                registry,
                lineage,
                cmd.artifact_size_bytes,
                now,
            )
            await uow.provenances.save(prov)
            await uow.commit()
            await self._publisher.publish_batch(prov.pop_events())
        return _to_dto(prov)

    async def verify(self, cmd: VerifyModelProvenanceCommand) -> ModelProvenanceDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        sig = None
        if cmd.signature_provider and cmd.signature_location and cmd.signing_key_fingerprint:
            sig = SignatureChainRef(
                cmd.signature_provider,
                cmd.signature_location,
                cmd.signing_key_fingerprint,
            )
        artifact = ArtifactDescriptor(
            size_bytes=0,  # filled from aggregate
            retrieval_uri=cmd.retrieval_uri,
            provider_reported_checksum=cmd.provider_reported_checksum,
            signature_chain=sig,
        )
        async with self._uow_factory() as uow:
            prov = await uow.provenances.find_by_id(ModelProvenanceId(cmd.provenance_id), tenant)
            if prov is None:
                raise ApplicationNotFoundError("ModelProvenance", str(cmd.provenance_id))
            artifact = ArtifactDescriptor(
                size_bytes=prov.artifact_size_bytes,
                retrieval_uri=cmd.retrieval_uri,
                provider_reported_checksum=cmd.provider_reported_checksum,
                signature_chain=sig,
            )
            settings = await uow.settings.get(tenant)
            try:
                prov = await self._verifier.verify(prov, tenant, artifact, settings, now)
            except SupplyChainDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.settings.save(tenant, settings)
            await uow.provenances.save(prov)
            await uow.commit()
            await self._publisher.publish_batch(prov.pop_events())
        return _to_dto(prov)

    async def manual_reset(self, cmd: ManualResetVerificationCommand) -> ModelProvenanceDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            prov = await uow.provenances.find_by_id(ModelProvenanceId(cmd.provenance_id), tenant)
            if prov is None:
                raise ApplicationNotFoundError("ModelProvenance", str(cmd.provenance_id))
            prov.reset_for_manual_retry(tenant, now)
            await uow.provenances.save(prov)
            await uow.commit()
        return _to_dto(prov)

    async def set_threshold(self, cmd: SetVerificationThresholdCommand) -> dict[str, int]:
        require_at_least(cmd.actor_roles, AIPostureRole.ADMIN)
        tenant = TenantId(cmd.tenant_id)
        async with self._uow_factory() as uow:
            settings = await uow.settings.get(tenant)
            from ai_supply_chain.domain.policies.verification_tier_policy import (
                VerificationTierPolicy,
            )

            VerificationTierPolicy().validate_threshold(cmd.size_threshold_bytes)
            settings.size_threshold_bytes = cmd.size_threshold_bytes
            await uow.settings.save(tenant, settings)
            await uow.commit()
        return {"size_threshold_bytes": cmd.size_threshold_bytes}

    async def get(self, tenant_id: UUID, provenance_id: UUID) -> ModelProvenanceDTO:
        tenant = TenantId(tenant_id)
        async with self._uow_factory() as uow:
            prov = await uow.provenances.find_by_id(ModelProvenanceId(provenance_id), tenant)
            if prov is None:
                raise ApplicationNotFoundError("ModelProvenance", str(provenance_id))
        return _to_dto(prov)

    async def get_integrity_for_asset(self, tenant_id: UUID, asset_id: UUID) -> str | None:
        """Query used by ai_posture ACL for risk scoring."""
        tenant = TenantId(tenant_id)
        async with self._uow_factory() as uow:
            prov = await uow.provenances.find_by_asset(AISystemAssetId(asset_id), tenant)
        return None if prov is None else prov.integrity_status.value
