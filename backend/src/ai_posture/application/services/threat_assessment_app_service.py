"""Threat assessment application service — Phase 2."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ai_posture.application._auth import require_at_least
from ai_posture.application.dtos.posture_dtos import AIThreatProfileDTO
from ai_posture.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_posture.domain.aggregates.ai_threat_profile import AIThreatProfile
from ai_posture.domain.exceptions.domain_exceptions import AIPostureDomainError
from ai_posture.domain.ports.i_cloud_discovery_query_port import CloudSystemConfigSignals
from ai_posture.domain.services.ai_threat_assessment_service import AIThreatAssessmentService
from ai_posture.domain.value_objects.enums import (
    AIPostureRole,
    AIThreatCategory,
    DownstreamActionCapability,
    InputSurface,
    OutputVerbosity,
    SanitizationPosture,
)
from ai_posture.domain.value_objects.identifiers import (
    AISystemAssetId,
    AIThreatProfileId,
    TenantId,
)
from ai_posture.domain.value_objects.posture_vos import AIThreatProfileRef

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_posture.application.commands.posture_commands import (
        AssessThreatProfileCommand,
        CreateThreatProfileCommand,
    )
    from ai_posture.application.ports.i_event_publisher import IEventPublisher
    from ai_posture.application.ports.i_unit_of_work import IUnitOfWork
    from ai_posture.domain.ports.i_cloud_discovery_query_port import ICloudDiscoveryQueryPort
    from ai_posture.domain.ports.i_detection_rule_query_port import IDetectionRuleQueryPort


def _to_dto(profile: AIThreatProfile) -> AIThreatProfileDTO:
    return AIThreatProfileDTO(
        profile_id=str(profile.profile_id),
        tenant_id=str(profile.tenant_id),
        ai_system_asset_id=str(profile.ai_system_asset_id),
        ai_system_kind=profile.ai_system_kind.value,
        requires_reassessment=profile.requires_reassessment,
        archived=profile.archived,
        max_exposure_level=profile.max_exposure_level().value,
        applicable_categories=[c.value for c in profile.applicable_categories],
    )


class ThreatAssessmentApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        cloud_port: ICloudDiscoveryQueryPort,
        detection_port: IDetectionRuleQueryPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._cloud = cloud_port
        self._detection = detection_port
        self._engine = AIThreatAssessmentService()

    async def create_profile(self, cmd: CreateThreatProfileCommand) -> AIThreatProfileDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(cmd.asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(cmd.asset_id))
            if asset.ai_system_kind is None:
                raise ApplicationValidationError("AISystemAsset must be classified first")
            existing = await uow.profiles.find_by_asset(asset.asset_id, tenant)
            if existing is not None:
                return _to_dto(existing)
            # Independence: create profile without further asset mutations until attach ref
            profile = AIThreatProfile.create(
                profile_id=AIThreatProfileId.generate(),
                tenant_id=tenant,
                ai_system_asset_id=asset.asset_id,
                ai_system_kind=asset.ai_system_kind,
                now=now,
            )
            asset.attach_threat_profile_ref(tenant, AIThreatProfileRef(profile.profile_id), now)
            await uow.profiles.save(profile)
            await uow.assets.save(asset)
            await uow.commit()
            events = profile.pop_events() + asset.pop_events()
            await self._publisher.publish_batch(events)
        return _to_dto(profile)

    async def assess(self, cmd: AssessThreatProfileCommand) -> AIThreatProfileDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            profile = await uow.profiles.find_by_asset(AISystemAssetId(cmd.asset_id), tenant)
            if profile is None:
                raise ApplicationNotFoundError("AIThreatProfile", str(cmd.asset_id))
            signals = await self._cloud.get_system_config_signals(
                profile.ai_system_asset_id, tenant
            )
            try:
                await self._apply_assessments(profile, tenant, signals, cmd.evidence_refs, now)
            except AIPostureDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            # Completeness signal from M28 (informational — does not block)
            for cat in profile.applicable_categories:
                await self._detection.has_rules_for_category(cat, tenant)
            await uow.profiles.save(profile)
            await uow.commit()
            await self._publisher.publish_batch(profile.pop_events())
        return _to_dto(profile)

    async def _apply_assessments(
        self,
        profile: AIThreatProfile,
        tenant: TenantId,
        signals: CloudSystemConfigSignals,
        evidence_refs: list[str],
        now: datetime,
    ) -> None:
        applicable = set(profile.applicable_categories)
        if AIThreatCategory.PROMPT_INJECTION in applicable:
            assessment = self._engine.assess_prompt_injection(
                input_surface=InputSurface(signals.input_surface),
                sanitization_posture=SanitizationPosture(signals.sanitization_posture),
                downstream_action_capability=DownstreamActionCapability(
                    signals.downstream_action_capability
                ),
            )
            profile.record_prompt_injection(tenant, assessment, evidence_refs, now)
        if AIThreatCategory.MODEL_EXTRACTION in applicable:
            assessment_me = self._engine.assess_model_extraction(
                query_rate_limiting_present=signals.query_rate_limiting_present,
                output_verbosity=OutputVerbosity(signals.output_verbosity),
                watermarking_present=signals.watermarking_present,
            )
            profile.record_model_extraction(tenant, assessment_me, evidence_refs, now)
        if AIThreatCategory.TRAINING_DATA_LEAKAGE in applicable:
            from ai_posture.domain.value_objects.enums import DataSensitivityClassification

            assessment_td = self._engine.assess_training_data_leakage(
                training_data_sensitivity=DataSensitivityClassification.INTERNAL,
                memorization_testing_performed=False,
                output_filtering_present=False,
            )
            profile.record_training_data_leakage(tenant, assessment_td, evidence_refs, now)
