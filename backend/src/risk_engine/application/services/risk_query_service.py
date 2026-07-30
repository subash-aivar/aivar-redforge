"""RiskQueryService — the M48C read-only application service
orchestrating `GetEnterpriseRiskProfileQuery`,
`ListEnterpriseRiskProfilesQuery`, and `GetRiskCorrelationSetQuery`.
Never mutates state; returns DTOs only. `GetRiskTimelineQuery` is
handled by `RiskTimelineApplicationService` instead, since it needs
`RiskTrendAnalysisService` — kept separate to keep this service a pure
single-repository-pair reader."""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.application.dtos.risk_profile_dto import (
    EnterpriseRiskProfileDTO,
    RiskContributionDTO,
    RiskCorrelationDTO,
)
from risk_engine.application.exceptions import RiskTenantIsolationViolationError

if TYPE_CHECKING:
    from risk_engine.application.ports.i_risk_correlation_repository import (
        RiskCorrelationRepository,
    )
    from risk_engine.application.ports.i_risk_profile_repository import (
        EnterpriseRiskProfileRepository,
    )
    from risk_engine.application.queries.risk_profile_queries import (
        GetEnterpriseRiskProfileQuery,
        GetRiskCorrelationSetQuery,
        ListEnterpriseRiskProfilesQuery,
    )
    from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
    from risk_engine.domain.aggregates.risk_correlation_set import RiskCorrelationSet
    from risk_engine.domain.entities.risk_contribution import RiskContribution


def _contribution_to_dto(contribution: RiskContribution) -> RiskContributionDTO:
    return RiskContributionDTO(
        dimension=str(contribution.dimension.value),
        normalized_score=contribution.normalized_score.value,
        source_context=contribution.source_signal.source_context,
        source_id=contribution.source_signal.source_id,
        computed_at=contribution.computed_at,
        subject_reference=contribution.source_signal.subject_reference,
    )


def _profile_to_dto(profile: EnterpriseRiskProfile) -> EnterpriseRiskProfileDTO:
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


def _correlation_to_dto(correlation_set: RiskCorrelationSet) -> RiskCorrelationDTO:
    return RiskCorrelationDTO(
        correlation_set_id=str(correlation_set.correlation_set_id),
        tenant_id=str(correlation_set.tenant_id),
        formed_at=correlation_set.formed_at,
        signal_references=tuple(ref.source_id for ref in correlation_set.signal_references),
    )


class RiskQueryService:
    def __init__(
        self,
        profile_repository: EnterpriseRiskProfileRepository,
        correlation_repository: RiskCorrelationRepository,
    ) -> None:
        self._profiles = profile_repository
        self._correlations = correlation_repository

    async def get_profile(
        self, query: GetEnterpriseRiskProfileQuery
    ) -> EnterpriseRiskProfileDTO | None:
        profile = await self._profiles.get(query.tenant_id, query.profile_id)
        if profile is None:
            return None
        if profile.tenant_id != query.tenant_id:
            raise RiskTenantIsolationViolationError(query.tenant_id, profile.tenant_id)
        return _profile_to_dto(profile)

    async def list_profiles(
        self, query: ListEnterpriseRiskProfilesQuery
    ) -> tuple[EnterpriseRiskProfileDTO, ...]:
        filters: dict[str, object] = {}
        if query.status is not None:
            filters["status"] = query.status
        if query.subject_reference is not None:
            filters["subject_reference"] = query.subject_reference
        profiles = await self._profiles.list(query.tenant_id, **filters)
        return tuple(_profile_to_dto(p) for p in profiles if p.tenant_id == query.tenant_id)

    async def get_correlation_set(
        self, query: GetRiskCorrelationSetQuery
    ) -> RiskCorrelationDTO | None:
        correlation_set = await self._correlations.get(query.tenant_id, query.correlation_set_id)
        if correlation_set is None:
            return None
        if correlation_set.tenant_id != query.tenant_id:
            raise RiskTenantIsolationViolationError(query.tenant_id, correlation_set.tenant_id)
        return _correlation_to_dto(correlation_set)
