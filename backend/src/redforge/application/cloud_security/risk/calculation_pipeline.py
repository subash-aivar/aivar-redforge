"""Risk calculation pipeline — batch/single asset/account/org, idempotent."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.cloud_security.risk.engine import CloudRiskEngine
from redforge.domain.cloud_security.risk.factor import (
    CloudRiskAssessment,
    CloudRiskExposure,
)
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.risk.value_objects import (
    RiskCalculationVersion,
    RiskDimensionScores,
    RiskWeightProfile,
)
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    OrganizationId,
)
from redforge.infrastructure.cloud_security.acl.exposure_acl import ExposureSignalACL

if TYPE_CHECKING:
    from redforge.application.cloud_security.risk.correlation_service import (
        RiskCorrelationService,
    )
    from redforge.application.cloud_security.risk.projection_service import (
        RiskProjectionService,
    )
    from redforge.application.cloud_security.risk.snapshot_builder import RiskSnapshotBuilder
    from redforge.domain.cloud_security.cloud_asset import CloudAsset
    from redforge.domain.cloud_security.repositories import CloudAssetRepository
    from redforge.domain.cloud_security.risk.repositories import (
        CloudRiskAssessmentRepository,
        CloudRiskExposureRepository,
        CloudRiskFactorRepository,
        CloudRiskHistoryRepository,
        CloudRiskRepository,
    )

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
RepoFactory = Callable[[AsyncSession], Any]


@dataclass
class PipelineResult:
    assessment: CloudRiskAssessment
    scores: list[CloudRiskScore]


class RiskCalculationPipeline:
    """Deterministic calculation unit — no workers / schedules."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        asset_repo_factory: RepoFactory,
        risk_repo_factory: RepoFactory,
        history_repo_factory: RepoFactory,
        factor_repo_factory: RepoFactory,
        exposure_repo_factory: RepoFactory,
        assessment_repo_factory: RepoFactory,
        snapshot_builder: RiskSnapshotBuilder,
        correlation: RiskCorrelationService,
        projection: RiskProjectionService | None = None,
        engine: CloudRiskEngine | None = None,
        weights: RiskWeightProfile | None = None,
        calculation_version: RiskCalculationVersion | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._asset_repo_factory = asset_repo_factory
        self._risk_repo_factory = risk_repo_factory
        self._history_repo_factory = history_repo_factory
        self._factor_repo_factory = factor_repo_factory
        self._exposure_repo_factory = exposure_repo_factory
        self._assessment_repo_factory = assessment_repo_factory
        self._snapshot_builder = snapshot_builder
        self._correlation = correlation
        self._projection = projection
        self._engine = engine or CloudRiskEngine()
        self._weights = weights or RiskWeightProfile.default()
        self._version = calculation_version or RiskCalculationVersion.default()

    async def calculate_asset(
        self,
        *,
        organization_id: str,
        asset_id: UUID,
        now: datetime | None = None,
    ) -> PipelineResult:
        return await self._run(
            organization_id=organization_id,
            scope="ASSET",
            target_id=str(asset_id),
            asset_ids=(asset_id,),
            now=now,
        )

    async def calculate_account(
        self,
        *,
        organization_id: str,
        account_id: UUID,
        now: datetime | None = None,
    ) -> PipelineResult:
        async with self._session_factory() as session:
            assets = await self._load_account_assets(
                session, organization_id=organization_id, account_id=account_id
            )
        return await self._run(
            organization_id=organization_id,
            scope="ACCOUNT",
            target_id=str(account_id),
            assets=assets,
            now=now,
        )

    async def calculate_organization(
        self,
        *,
        organization_id: str,
        now: datetime | None = None,
    ) -> PipelineResult:
        async with self._session_factory() as session:
            assets = await self._load_org_assets(session, organization_id=organization_id)
        return await self._run(
            organization_id=organization_id,
            scope="ORGANIZATION",
            target_id=organization_id,
            assets=assets,
            now=now,
        )

    async def calculate_batch(
        self,
        *,
        organization_id: str,
        asset_ids: list[UUID],
        now: datetime | None = None,
    ) -> PipelineResult:
        return await self._run(
            organization_id=organization_id,
            scope="BATCH",
            target_id=f"batch:{len(asset_ids)}",
            asset_ids=tuple(asset_ids),
            now=now,
        )

    async def calculate_incremental(
        self,
        *,
        organization_id: str,
        changed_asset_ids: list[UUID],
        now: datetime | None = None,
    ) -> PipelineResult:
        """Delta/incremental — only recalculate listed assets."""
        return await self.calculate_batch(
            organization_id=organization_id,
            asset_ids=changed_asset_ids,
            now=now,
        )

    async def _run(
        self,
        *,
        organization_id: str,
        scope: str,
        target_id: str,
        asset_ids: tuple[UUID, ...] | None = None,
        assets: list[CloudAsset] | None = None,
        now: datetime | None = None,
    ) -> PipelineResult:
        ts = now or datetime.now(UTC)
        org = OrganizationId(organization_id)
        assessment = CloudRiskAssessment.start(
            organization_id=org,
            scope=scope,
            target_id=target_id,
            calculation_version=str(self._version),
            now=ts,
        )
        created = 0
        updated = 0
        scores: list[CloudRiskScore] = []
        evaluated = 0
        fingerprint_keys: set[str] = set()

        async with self._session_factory() as session:
            asset_repo: CloudAssetRepository = self._asset_repo_factory(session)
            risk_repo: CloudRiskRepository = self._risk_repo_factory(session)
            history_repo: CloudRiskHistoryRepository = self._history_repo_factory(session)
            factor_repo: CloudRiskFactorRepository = self._factor_repo_factory(session)
            exposure_repo: CloudRiskExposureRepository = self._exposure_repo_factory(session)
            assessment_repo: CloudRiskAssessmentRepository = self._assessment_repo_factory(
                session
            )

            if assets is None:
                assets = []
                for aid in asset_ids or ():
                    asset = await asset_repo.get_by_id(CloudAssetId(aid), org)
                    if asset is not None and not asset.is_deleted:
                        assets.append(asset)

            await assessment_repo.save(assessment)

            for asset in assets:
                key = str(asset.id.value)
                if key in fingerprint_keys:
                    continue
                fingerprint_keys.add(key)

                snapshot = await self._snapshot_builder.build(asset)
                dimensions, components, evidence, factors = self._correlation.correlate(
                    organization_id=org,
                    cloud_asset_id=asset.id,
                    snapshot=snapshot,
                    weights=self._weights,
                )
                assert isinstance(dimensions, RiskDimensionScores)
                previous = await risk_repo.get_current_by_asset(asset.id, organization_id=org)
                score = CloudRiskScore.calculate(
                    organization_id=org,
                    cloud_asset_id=asset.id,
                    dimensions=dimensions,
                    components=components,
                    evidence=evidence,
                    weights=self._weights,
                    calculation_version=self._version,
                    previous=previous,
                    now=ts,
                )
                if previous is None:
                    created += 1
                else:
                    updated += 1
                await risk_repo.save(score)
                await history_repo.append_from_score(score)
                if factors:
                    await factor_repo.save_batch(factors)

                exp_signals = ExposureSignalACL().from_asset(asset)
                exposure = CloudRiskExposure.derive(
                    organization_id=org,
                    cloud_asset_id=asset.id,
                    public_accessibility=bool(exp_signals["public_accessibility"]),
                    internet_exposure=bool(exp_signals["internet_exposure"]),
                    encryption_at_rest=bool(exp_signals["encryption_at_rest"]),
                    privilege_level=snapshot.privilege_level,
                    lateral_movement_potential=snapshot.lateral_movement_potential,
                    details={"network_exposure": snapshot.network_exposure},
                    now=ts,
                )
                await exposure_repo.save(exposure)
                scores.append(score)
                evaluated += 1

                if self._projection is not None:
                    await self._projection.project(
                        score=score, factors=factors, exposure=exposure
                    )

            assessment.complete(
                assets_evaluated=evaluated,
                risks_created=created,
                risks_updated=updated,
                diagnostics={
                    "scope": scope,
                    "target_id": target_id,
                    "unique_assets": len(fingerprint_keys),
                    "attack_path_stub": True,
                },
                now=ts,
            )
            await assessment_repo.save(assessment)
            await session.commit()

        return PipelineResult(assessment=assessment, scores=scores)

    async def _load_org_assets(
        self, session: AsyncSession, *, organization_id: str
    ) -> list[CloudAsset]:
        repo: CloudAssetRepository = self._asset_repo_factory(session)
        org = OrganizationId(organization_id)
        assets: list[CloudAsset] = []
        page = 1
        while True:
            result = await repo.list_by_organization(org, page=page, size=200)
            assets.extend(a for a in result.items if not a.is_deleted)
            if page * 200 >= result.total or not result.items:
                break
            page += 1
        return assets

    async def _load_account_assets(
        self, session: AsyncSession, *, organization_id: str, account_id: UUID
    ) -> list[CloudAsset]:
        repo: CloudAssetRepository = self._asset_repo_factory(session)
        org = OrganizationId(organization_id)
        account = CloudAccountId(account_id)
        assets: list[CloudAsset] = []
        page = 1
        while True:
            result = await repo.list_by_account(
                account, org, None, page=page, size=200
            )
            assets.extend(a for a in result.items if not a.is_deleted)
            if page * 200 >= result.total or not result.items:
                break
            page += 1
        return assets
