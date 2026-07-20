"""RiskCalculationService facade — calculate + query APIs."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from redforge.application.cloud_security.risk.aggregation_service import (
    RiskAggregationService,
)
from redforge.application.cloud_security.risk.dtos import (
    CalculateRiskCommand,
    RiskAssessmentResultDTO,
    RiskFactorDTO,
    RiskScoreDTO,
    RiskSummaryDTO,
)
from redforge.domain.cloud_security.risk.exceptions import CloudRiskNotFoundError
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId

if TYPE_CHECKING:
    from redforge.application.cloud_security.risk.calculation_pipeline import (
        RiskCalculationPipeline,
    )
    from redforge.domain.cloud_security.risk.repositories import (
        CloudRiskFactorRepository,
        CloudRiskHistoryRepository,
        CloudRiskRepository,
    )

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
RepoFactory = Callable[[AsyncSession], Any]


def _to_dto(score: CloudRiskScore) -> RiskScoreDTO:
    return RiskScoreDTO(
        risk_id=str(score.id),
        organization_id=str(score.organization_id),
        cloud_asset_id=str(score.cloud_asset_id),
        overall_score=score.overall_score,
        threat_intel_score=score.threat_intel_score,
        compliance_score=score.compliance_score,
        identity_score=score.identity_score,
        exposure_score=score.exposure_score,
        business_criticality_score=score.business_criticality_score,
        attack_path_score=score.attack_path_score,
        cspm_score=score.cspm_score,
        kubernetes_score=score.kubernetes_score,
        runtime_score=score.runtime_score,
        confidence=score.confidence.value,
        trend=score.trend.value,
        state=score.state.value,
        calculation_version=str(score.calculation_version),
        computed_at=score.computed_at,
        valid_until=score.valid_until,
        score_components=[c.to_dict() for c in score.score_components],
        evidence=[e.to_dict() for e in score.evidence],
    )


class RiskCalculationService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        pipeline: RiskCalculationPipeline,
        risk_repo_factory: RepoFactory,
        factor_repo_factory: RepoFactory,
        history_repo_factory: RepoFactory,
        aggregation: RiskAggregationService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._pipeline = pipeline
        self._risk_repo_factory = risk_repo_factory
        self._factor_repo_factory = factor_repo_factory
        self._history_repo_factory = history_repo_factory
        self._aggregation = aggregation or RiskAggregationService()

    async def calculate(self, command: CalculateRiskCommand) -> RiskAssessmentResultDTO:
        if command.asset_id is not None:
            result = await self._pipeline.calculate_asset(
                organization_id=command.organization_id,
                asset_id=command.asset_id,
            )
        elif command.account_id is not None:
            result = await self._pipeline.calculate_account(
                organization_id=command.organization_id,
                account_id=command.account_id,
            )
        elif command.asset_ids:
            if command.incremental:
                result = await self._pipeline.calculate_incremental(
                    organization_id=command.organization_id,
                    changed_asset_ids=list(command.asset_ids),
                )
            else:
                result = await self._pipeline.calculate_batch(
                    organization_id=command.organization_id,
                    asset_ids=list(command.asset_ids),
                )
        else:
            result = await self._pipeline.calculate_organization(
                organization_id=command.organization_id,
            )
        a = result.assessment
        return RiskAssessmentResultDTO(
            assessment_id=str(a.id),
            organization_id=str(a.organization_id),
            scope=a.scope,
            target_id=a.target_id,
            status=a.status,
            assets_evaluated=a.assets_evaluated,
            risks_created=a.risks_created,
            risks_updated=a.risks_updated,
            calculation_version=a.calculation_version,
            diagnostics=dict(a.diagnostics),
        )

    async def recalculate_organization(
        self, organization_id: str
    ) -> RiskAssessmentResultDTO:
        return await self.calculate(
            CalculateRiskCommand(
                organization_id=organization_id, organization_wide=True
            )
        )

    async def list_scores(
        self,
        organization_id: str,
        *,
        min_score: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RiskScoreDTO]:
        async with self._session_factory() as session:
            repo: CloudRiskRepository = self._risk_repo_factory(session)
            scores = await repo.list_by_organization(
                OrganizationId(organization_id),
                min_score=min_score,
                limit=limit,
                offset=offset,
            )
            return [_to_dto(s) for s in scores]

    async def get_score(
        self,
        organization_id: str,
        *,
        risk_id: UUID | None = None,
        asset_id: UUID | None = None,
    ) -> RiskScoreDTO:
        async with self._session_factory() as session:
            repo: CloudRiskRepository = self._risk_repo_factory(session)
            org = OrganizationId(organization_id)
            score: CloudRiskScore | None = None
            if risk_id is not None:
                score = await repo.get_by_id(risk_id, organization_id=org)
            elif asset_id is not None:
                score = await repo.get_current_by_asset(
                    CloudAssetId(asset_id), organization_id=org
                )
            if score is None:
                raise CloudRiskNotFoundError(str(risk_id or asset_id))
            return _to_dto(score)

    async def summary(self, organization_id: str) -> RiskSummaryDTO:
        async with self._session_factory() as session:
            repo: CloudRiskRepository = self._risk_repo_factory(session)
            scores = await repo.list_by_organization(
                OrganizationId(organization_id), limit=1000, offset=0
            )
            return self._aggregation.summarize(
                organization_id=organization_id, scores=scores
            )

    async def top(
        self, organization_id: str, *, limit: int = 10, threshold: float = 0.0
    ) -> list[RiskScoreDTO]:
        async with self._session_factory() as session:
            repo: CloudRiskRepository = self._risk_repo_factory(session)
            scores = await repo.list_by_organization(
                OrganizationId(organization_id),
                min_score=threshold if threshold > 0 else None,
                limit=max(1, min(limit, 100)),
                offset=0,
            )
            return [_to_dto(s) for s in self._aggregation.top_n(scores, n=limit)]

    async def history(
        self,
        organization_id: str,
        asset_id: UUID,
        *,
        limit: int = 50,
    ) -> list[dict[str, object]]:
        async with self._session_factory() as session:
            repo: CloudRiskHistoryRepository = self._history_repo_factory(session)
            return await repo.list_for_asset(
                asset_id,
                organization_id=OrganizationId(organization_id),
                limit=limit,
            )

    async def list_factors(
        self, organization_id: str, asset_id: UUID
    ) -> list[RiskFactorDTO]:
        async with self._session_factory() as session:
            repo: CloudRiskFactorRepository = self._factor_repo_factory(session)
            factors = await repo.list_by_asset(
                asset_id, organization_id=OrganizationId(organization_id)
            )
            return [
                RiskFactorDTO(
                    factor_id=str(f.id),
                    organization_id=str(f.organization_id),
                    cloud_asset_id=str(f.cloud_asset_id),
                    category=f.category.value,
                    source=f.source.value,
                    title=f.title,
                    description=f.description,
                    score=f.score,
                    severity=f.severity.value,
                    confidence=f.confidence.value,
                )
                for f in factors
            ]
