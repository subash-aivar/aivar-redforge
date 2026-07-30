"""RiskTimelineApplicationService — the M48C application service
orchestrating `GetRiskTimelineQuery`. Read-only: fetches a profile's
chronological `CompositeRiskScore` history via
`EnterpriseRiskProfileRepository.score_history`, optionally windowed
by `since`/`until`, and derives a `RiskTrendDirection` via
`RiskTrendAnalysisService.analyze_trend` — never recomputing the trend
heuristic itself."""

from __future__ import annotations

from typing import TYPE_CHECKING

from risk_engine.application.dtos.risk_profile_dto import RiskScoreSnapshotDTO, RiskTimelineDTO
from risk_engine.application.exceptions import (
    EnterpriseRiskProfileNotFoundError,
    RiskTenantIsolationViolationError,
)
from risk_engine.domain.services.risk_trend_analysis_service import RiskTrendAnalysisService

if TYPE_CHECKING:
    from risk_engine.application.ports.i_risk_profile_repository import (
        EnterpriseRiskProfileRepository,
    )
    from risk_engine.application.queries.risk_profile_queries import GetRiskTimelineQuery


class RiskTimelineApplicationService:
    def __init__(self, repository: EnterpriseRiskProfileRepository) -> None:
        self._repository = repository

    async def get_timeline(self, query: GetRiskTimelineQuery) -> RiskTimelineDTO:
        profile = await self._repository.get(query.tenant_id, query.profile_id)
        if profile is None:
            raise EnterpriseRiskProfileNotFoundError(query.profile_id)
        if profile.tenant_id != query.tenant_id:
            raise RiskTenantIsolationViolationError(query.tenant_id, profile.tenant_id)

        history = list(await self._repository.score_history(query.tenant_id, query.profile_id))
        if query.since is not None:
            history = [s for s in history if s.computed_at >= query.since]
        if query.until is not None:
            history = [s for s in history if s.computed_at <= query.until]

        trend = RiskTrendAnalysisService.analyze_trend(history)
        snapshots = tuple(
            RiskScoreSnapshotDTO(
                value=snapshot.value.value,
                weight_profile_id=snapshot.weight_profile_id,
                computed_at=snapshot.computed_at,
            )
            for snapshot in history
        )
        return RiskTimelineDTO(
            profile_id=str(query.profile_id),
            tenant_id=str(query.tenant_id),
            snapshots=snapshots,
            trend_direction=trend.value,
        )
