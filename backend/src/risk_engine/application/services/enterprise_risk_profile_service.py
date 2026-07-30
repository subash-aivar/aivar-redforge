"""EnterpriseRiskProfileApplicationService — the M48C application
service orchestrating the six `EnterpriseRiskProfile` commands. Never
performs domain computation itself: normalization is delegated to
`RiskNormalizationService`, composition to `RiskCompositionService`,
construction to `RiskProfileFactory`, and every state transition to
the aggregate's own methods. Returns DTOs only — no domain object ever
crosses this boundary. Constructor-injected, Protocol-typed
collaborators only (`EnterpriseRiskProfileRepository` + `IUnitOfWork`)
— no concrete infrastructure."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from risk_engine.application.dtos.risk_profile_dto import (
    EnterpriseRiskProfileDTO,
    RiskContributionDTO,
)
from risk_engine.application.exceptions import (
    EnterpriseRiskProfileNotFoundError,
    RiskTenantIsolationViolationError,
)
from risk_engine.application.services.command_validation import (
    validate_signals_non_empty,
    validate_subject_reference,
)
from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.factories.risk_profile_factory import RiskProfileFactory
from risk_engine.domain.services.risk_composition_service import RiskCompositionService
from risk_engine.domain.services.risk_normalization_service import RiskNormalizationService

if TYPE_CHECKING:
    from risk_engine.application.commands.risk_profile_commands import (
        AcceptEnterpriseRiskCommand,
        AcknowledgeEnterpriseRiskCommand,
        CloseEnterpriseRiskCommand,
        CreateEnterpriseRiskProfileCommand,
        MitigateEnterpriseRiskCommand,
        RecomputeEnterpriseRiskCommand,
    )
    from risk_engine.application.ports.i_risk_profile_repository import (
        EnterpriseRiskProfileRepository,
    )
    from risk_engine.application.ports.i_unit_of_work import IUnitOfWork
    from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
    from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId


def _contribution_to_dto(contribution: RiskContribution) -> RiskContributionDTO:
    return RiskContributionDTO(
        dimension=str(contribution.dimension.value),
        normalized_score=contribution.normalized_score.value,
        source_context=contribution.source_signal.source_context,
        source_id=contribution.source_signal.source_id,
        computed_at=contribution.computed_at,
        subject_reference=contribution.source_signal.subject_reference,
    )


def _to_dto(profile: EnterpriseRiskProfile) -> EnterpriseRiskProfileDTO:
    return EnterpriseRiskProfileDTO(
        profile_id=str(profile.profile_id),
        tenant_id=str(profile.tenant_id),
        subject_reference=profile.subject_reference,
        status=profile.status.value,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
        composite_score=(
            profile.composite_score.value.value if profile.composite_score is not None else None
        ),
        weight_profile_id=(
            profile.composite_score.weight_profile_id
            if profile.composite_score is not None
            else None
        ),
        composite_computed_at=(
            profile.composite_score.computed_at if profile.composite_score is not None else None
        ),
        accepted_expires_at=profile.accepted_expires_at,
        contributions=tuple(_contribution_to_dto(c) for c in profile.contributions),
    )


class EnterpriseRiskProfileApplicationService:
    def __init__(
        self,
        repository: EnterpriseRiskProfileRepository,
        unit_of_work: IUnitOfWork,
    ) -> None:
        self._repository = repository
        self._uow = unit_of_work

    # -- commands --------------------------------------------------------

    async def create_profile(
        self, cmd: CreateEnterpriseRiskProfileCommand
    ) -> EnterpriseRiskProfileDTO:
        validate_subject_reference(cmd.subject_reference)
        now = datetime.now(UTC)
        normalized = RiskNormalizationService.normalize(
            cmd.signal_reference.raw_value, cmd.signal_reference.raw_scale
        )
        contribution = RiskContribution(
            dimension=cmd.dimension,
            normalized_score=normalized,
            source_signal=cmd.signal_reference,
            computed_at=now,
        )
        profile = RiskProfileFactory.create(
            tenant_id=cmd.tenant_id,
            subject_reference=cmd.subject_reference,
            initial_contribution=contribution,
            now=now,
            profile_id=cmd.profile_id,
        )
        async with self._uow:
            await self._repository.save(profile)
            await self._uow.commit()
        return _to_dto(profile)

    async def recompute_score(
        self, cmd: RecomputeEnterpriseRiskCommand
    ) -> EnterpriseRiskProfileDTO:
        validate_signals_non_empty(cmd.signals)
        profile = await self._require_profile(cmd.tenant_id, cmd.profile_id)
        now = datetime.now(UTC)
        contributions = tuple(
            RiskContribution(
                dimension=signal.dimension,
                normalized_score=RiskNormalizationService.normalize(
                    signal.signal_reference.raw_value, signal.signal_reference.raw_scale
                ),
                source_signal=signal.signal_reference,
                computed_at=now,
            )
            for signal in cmd.signals
        )
        composite_score = RiskCompositionService.compose(contributions, cmd.weight_profile)
        profile.recompute_score(cmd.tenant_id, composite_score, contributions, now)
        async with self._uow:
            await self._repository.save(profile)
            await self._uow.commit()
        return _to_dto(profile)

    async def acknowledge(self, cmd: AcknowledgeEnterpriseRiskCommand) -> EnterpriseRiskProfileDTO:
        profile = await self._require_profile(cmd.tenant_id, cmd.profile_id)
        profile.acknowledge(cmd.tenant_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(profile)
            await self._uow.commit()
        return _to_dto(profile)

    async def mitigate(self, cmd: MitigateEnterpriseRiskCommand) -> EnterpriseRiskProfileDTO:
        profile = await self._require_profile(cmd.tenant_id, cmd.profile_id)
        profile.mitigate(cmd.tenant_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(profile)
            await self._uow.commit()
        return _to_dto(profile)

    async def accept(self, cmd: AcceptEnterpriseRiskCommand) -> EnterpriseRiskProfileDTO:
        profile = await self._require_profile(cmd.tenant_id, cmd.profile_id)
        profile.accept(cmd.tenant_id, cmd.expires_at, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(profile)
            await self._uow.commit()
        return _to_dto(profile)

    async def close(self, cmd: CloseEnterpriseRiskCommand) -> EnterpriseRiskProfileDTO:
        profile = await self._require_profile(cmd.tenant_id, cmd.profile_id)
        profile.close(cmd.tenant_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(profile)
            await self._uow.commit()
        return _to_dto(profile)

    # -- helpers -----------------------------------------------------------

    async def _require_profile(
        self, tenant_id: TenantId, profile_id: RiskProfileId
    ) -> EnterpriseRiskProfile:
        profile = await self._repository.get(tenant_id, profile_id)
        if profile is None:
            raise EnterpriseRiskProfileNotFoundError(profile_id)
        if profile.tenant_id != tenant_id:
            raise RiskTenantIsolationViolationError(tenant_id, profile.tenant_id)
        return profile
