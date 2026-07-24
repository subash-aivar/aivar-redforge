"""Compliance mapping application service — Phase 5."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ai_posture.application._auth import require_at_least
from ai_posture.application.dtos.posture_dtos import AIComplianceMappingDTO
from ai_posture.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_posture.domain.exceptions.domain_exceptions import (
    AIPostureDomainError,
    AttestationRequiredCannotAutoSatisfy,
)
from ai_posture.domain.services.ai_compliance_mapping_service import (
    AIComplianceMappingService,
)
from ai_posture.domain.value_objects.compliance_vos import (
    ControlEvidenceSnapshot,
    HumanAttestation,
)
from ai_posture.domain.value_objects.enums import (
    AIPostureRole,
    ComplianceFrameworkId,
)
from ai_posture.domain.value_objects.identifiers import (
    AIComplianceMappingId,
    AISystemAssetId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from ai_posture.application.commands.posture_commands import (
        EvaluateComplianceMappingCommand,
        RecordComplianceAttestationCommand,
    )
    from ai_posture.application.ports.i_event_publisher import IEventPublisher
    from ai_posture.application.ports.i_unit_of_work import IUnitOfWork
    from ai_posture.domain.aggregates.ai_compliance_mapping import AIComplianceMapping
    from ai_posture.domain.ports.i_agent_deviation_stats_port import (
        IAgentDeviationStatsPort,
    )
    from ai_posture.domain.ports.i_compliance_query_port import IComplianceQueryPort
    from ai_posture.domain.ports.i_provenance_integrity_query_port import (
        IProvenanceIntegrityQueryPort,
    )


def _to_dto(m: AIComplianceMapping) -> AIComplianceMappingDTO:
    return AIComplianceMappingDTO(
        mapping_id=str(m.mapping_id),
        tenant_id=str(m.tenant_id),
        ai_system_asset_id=str(m.ai_system_asset_id),
        framework_id=m.framework_ref.framework_id.value,
        control_id=m.framework_ref.control_id,
        control_title=m.framework_ref.control_title,
        control_status=m.control_status.value,
        requires_human_attestation=m.requires_human_attestation,
        evaluation_mode=m.evaluation_mode.value,
        attestor_id=m.attestation.attestor_id if m.attestation else None,
        attested_at=m.attestation.attested_at if m.attestation else None,
        recorded_at=m.recorded_at,
    )


class ComplianceMappingApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        compliance_port: IComplianceQueryPort,
        provenance_port: IProvenanceIntegrityQueryPort,
        agent_port: IAgentDeviationStatsPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._compliance = compliance_port
        self._provenance = provenance_port
        self._agent = agent_port
        self._domain = AIComplianceMappingService()

    async def evaluate(self, cmd: EvaluateComplianceMappingCommand) -> list[AIComplianceMappingDTO]:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        results: list[AIComplianceMappingDTO] = []
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(cmd.asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(cmd.asset_id))
            if asset.ai_system_kind is None:
                raise ApplicationValidationError(
                    "Asset must be classified before compliance mapping"
                )
            profile = await uow.profiles.find_by_asset(asset.asset_id, tenant)
            integrity = await self._provenance.get_integrity_status(tenant, cmd.asset_id)
            has_envelope = await self._agent.has_active_envelope(tenant, cmd.asset_id)
            evidence = ControlEvidenceSnapshot(
                has_threat_profile=profile is not None and not profile.archived,
                threat_max_exposure=(
                    profile.max_exposure_level().value if profile is not None else None
                ),
                provenance_integrity_status=integrity,
                has_active_envelope=has_envelope,
            )
            framework = ComplianceFrameworkId(cmd.framework_id)
            controls = await self._compliance.resolve_applicable_controls(
                framework,
                asset.ai_system_kind,
                asset.data_sensitivity,
                tenant,
            )
            events = []
            for control in controls:
                try:
                    mapping = self._domain.evaluate_control(
                        tenant, asset.asset_id, control, evidence, now=now
                    )
                except AttestationRequiredCannotAutoSatisfy as exc:
                    raise ApplicationValidationError(str(exc)) from exc
                await uow.compliance_mappings.save(mapping)
                events.extend(mapping.pop_events())
                results.append(_to_dto(mapping))
            await uow.commit()
            await self._publisher.publish_batch(events)
        return results

    async def record_attestation(
        self, cmd: RecordComplianceAttestationCommand
    ) -> AIComplianceMappingDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ANALYST)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            mapping = await uow.compliance_mappings.find_by_id(
                AIComplianceMappingId(cmd.mapping_id), tenant
            )
            if mapping is None:
                raise ApplicationNotFoundError("AIComplianceMapping", str(cmd.mapping_id))
            try:
                mapping.apply_human_attestation(
                    tenant,
                    HumanAttestation(cmd.attestor_id, now, cmd.notes),
                    satisfied=cmd.satisfied,
                    now=now,
                )
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.compliance_mappings.save(mapping)
            await uow.commit()
            await self._publisher.publish_batch(mapping.pop_events())
        return _to_dto(mapping)

    async def list_for_asset(self, tenant_id: TenantId, asset_id: UUID) -> list[AIComplianceMappingDTO]:
        tenant = tenant_id
        async with self._uow_factory() as uow:
            items = await uow.compliance_mappings.find_by_asset(AISystemAssetId(asset_id), tenant)
        return [_to_dto(m) for m in items]

    async def gap_count_for_asset(self, tenant_id: TenantId, asset_id: UUID) -> int:
        tenant = tenant_id
        async with self._uow_factory() as uow:
            return await uow.compliance_mappings.count_gaps_for_asset(
                AISystemAssetId(asset_id), tenant
            )
