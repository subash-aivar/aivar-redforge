"""PostgreSQL repository implementations for cloud risk aggregates."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select

from redforge.domain.cloud_security.risk.factor import (
    CloudRiskAssessment,
    CloudRiskExposure,
    CloudRiskExposureId,
    CloudRiskFactor,
)
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.risk.value_objects import CloudRiskScoreId
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId
from redforge.infrastructure.cloud_security.risk.mappings import (
    assessment_from_model,
    assessment_to_model,
    exposure_to_model,
    factor_from_model,
    factor_to_model,
    history_row_from_score,
    score_from_model,
    score_to_model,
)
from redforge.infrastructure.database.models.cloud_security import (
    CloudRiskAssessmentModel,
    CloudRiskExposureModel,
    CloudRiskFactorModel,
    CloudRiskHistoryModel,
    CloudRiskScoreModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgCloudRiskRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, score: CloudRiskScore) -> None:
        result = await self._session.execute(
            select(CloudRiskScoreModel).where(
                CloudRiskScoreModel.organization_id == str(score.organization_id),
                CloudRiskScoreModel.cloud_asset_id == score.cloud_asset_id.value,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            self._session.add(score_to_model(score))
        else:
            score.id = CloudRiskScoreId(existing.id)
            score_to_model(score, existing)
        await self._session.flush()

    async def get_by_id(
        self, risk_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRiskScore | None:
        result = await self._session.execute(
            select(CloudRiskScoreModel).where(
                CloudRiskScoreModel.id == risk_id,
                CloudRiskScoreModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return score_from_model(row) if row is not None else None

    async def get_current_by_asset(
        self, asset_id: CloudAssetId, *, organization_id: OrganizationId
    ) -> CloudRiskScore | None:
        result = await self._session.execute(
            select(CloudRiskScoreModel).where(
                CloudRiskScoreModel.cloud_asset_id == asset_id.value,
                CloudRiskScoreModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return score_from_model(row) if row is not None else None

    async def list_by_organization(
        self,
        organization_id: OrganizationId,
        *,
        min_score: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CloudRiskScore]:
        stmt = select(CloudRiskScoreModel).where(
            CloudRiskScoreModel.organization_id == str(organization_id)
        )
        if min_score is not None:
            stmt = stmt.where(CloudRiskScoreModel.overall_score >= min_score)
        result = await self._session.execute(
            stmt.order_by(CloudRiskScoreModel.overall_score.desc())
            .offset(max(0, offset))
            .limit(max(1, min(limit, 1000)))
        )
        return [score_from_model(row) for row in result.scalars().all()]

    async def list_critical_by_organization(
        self, organization_id: OrganizationId, *, threshold: float = 7.0, limit: int = 50
    ) -> list[CloudRiskScore]:
        return await self.list_by_organization(
            organization_id, min_score=threshold, limit=limit, offset=0
        )


class PgCloudRiskHistoryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append_from_score(self, score: CloudRiskScore) -> None:
        row = history_row_from_score(score)
        existing = await self._session.get(CloudRiskHistoryModel, row.id)
        if existing is None:
            self._session.add(row)
            await self._session.flush()

    async def list_for_asset(
        self,
        asset_id: UUID,
        *,
        organization_id: OrganizationId,
        limit: int = 50,
    ) -> list[dict[str, object]]:
        result = await self._session.execute(
            select(CloudRiskHistoryModel)
            .where(
                CloudRiskHistoryModel.cloud_asset_id == asset_id,
                CloudRiskHistoryModel.organization_id == str(organization_id),
            )
            .order_by(CloudRiskHistoryModel.recorded_at.desc())
            .limit(max(1, min(limit, 500)))
        )
        return [
            {
                "id": str(row.id),
                "organization_id": row.organization_id,
                "cloud_asset_id": str(row.cloud_asset_id),
                "risk_score_id": str(row.risk_score_id),
                "overall_score": float(row.overall_score),
                "dimensions": dict(row.dimensions or {}),
                "calculation_version": row.calculation_version,
                "recorded_at": row.recorded_at.isoformat(),
                "reason": row.reason,
            }
            for row in result.scalars().all()
        ]


class PgCloudRiskFactorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_batch(self, factors: list[CloudRiskFactor]) -> None:
        for factor in factors:
            existing = await self._session.get(CloudRiskFactorModel, factor.id.value)
            if existing is None:
                self._session.add(factor_to_model(factor))
            else:
                factor_to_model(factor, existing)
        await self._session.flush()

    async def list_by_asset(
        self, asset_id: UUID, *, organization_id: OrganizationId
    ) -> list[CloudRiskFactor]:
        result = await self._session.execute(
            select(CloudRiskFactorModel)
            .where(
                CloudRiskFactorModel.cloud_asset_id == asset_id,
                CloudRiskFactorModel.organization_id == str(organization_id),
            )
            .order_by(CloudRiskFactorModel.score.desc())
        )
        return [factor_from_model(row) for row in result.scalars().all()]


class PgCloudRiskExposureRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, exposure: CloudRiskExposure) -> None:
        result = await self._session.execute(
            select(CloudRiskExposureModel).where(
                CloudRiskExposureModel.organization_id == str(exposure.organization_id),
                CloudRiskExposureModel.cloud_asset_id == exposure.cloud_asset_id.value,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            self._session.add(exposure_to_model(exposure))
        else:
            exposure.id = CloudRiskExposureId(existing.id)
            exposure_to_model(exposure, existing)
        await self._session.flush()


class PgCloudRiskAssessmentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, assessment: CloudRiskAssessment) -> None:
        existing = await self._session.get(CloudRiskAssessmentModel, assessment.id.value)
        if existing is None:
            self._session.add(assessment_to_model(assessment))
        else:
            assessment_to_model(assessment, existing)
        await self._session.flush()

    async def get_by_id(
        self, assessment_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRiskAssessment | None:
        result = await self._session.execute(
            select(CloudRiskAssessmentModel).where(
                CloudRiskAssessmentModel.id == assessment_id,
                CloudRiskAssessmentModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return assessment_from_model(row) if row is not None else None
