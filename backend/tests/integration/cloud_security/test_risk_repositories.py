"""PostgreSQL integration tests for cloud risk repositories."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from ulid import ULID

from redforge.domain.cloud_security.risk.engine import CloudRiskEngine, RiskSignalSnapshot
from redforge.domain.cloud_security.risk.factor import (
    CloudRiskAssessment,
    CloudRiskExposure,
    CloudRiskFactor,
)
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.risk.value_objects import RiskCategory, RiskSource
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId
from redforge.infrastructure.cloud_security.risk.repositories import (
    PgCloudRiskAssessmentRepository,
    PgCloudRiskExposureRepository,
    PgCloudRiskFactorRepository,
    PgCloudRiskHistoryRepository,
    PgCloudRiskRepository,
)

pytestmark = pytest.mark.integration

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)
NOW = datetime(2026, 7, 19, 18, 0, tzinfo=UTC)


@pytest.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _score(org: OrganizationId, asset: CloudAssetId) -> CloudRiskScore:
    dims, components, evidence = CloudRiskEngine().score_dimensions(
        RiskSignalSnapshot(open_finding_severities=("HIGH",), privilege_level="MEDIUM")
    )
    return CloudRiskScore.calculate(
        organization_id=org,
        cloud_asset_id=asset,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )


@pytest.mark.asyncio
async def test_risk_repositories_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    asset = CloudAssetId(uuid4())

    async with session_factory() as session, session.begin():
        risks = PgCloudRiskRepository(session)
        history = PgCloudRiskHistoryRepository(session)
        factors = PgCloudRiskFactorRepository(session)
        exposures = PgCloudRiskExposureRepository(session)
        assessments = PgCloudRiskAssessmentRepository(session)

        score = _score(org, asset)
        await risks.save(score)
        await history.append_from_score(score)

        factor = CloudRiskFactor.create(
            organization_id=org,
            cloud_asset_id=asset,
            category=RiskCategory.CONFIGURATION,
            source=RiskSource.CSPM,
            title="cspm:7.50",
            score=7.5,
            now=NOW,
        )
        await factors.save_batch([factor])

        exposure = CloudRiskExposure.derive(
            organization_id=org,
            cloud_asset_id=asset,
            public_accessibility=True,
            now=NOW,
        )
        await exposures.save(exposure)

        assessment = CloudRiskAssessment.start(
            organization_id=org,
            scope="ASSET",
            target_id=str(asset),
            calculation_version=str(score.calculation_version),
            now=NOW,
        )
        assessment.complete(
            assets_evaluated=1, risks_created=1, risks_updated=0, now=NOW
        )
        await assessments.save(assessment)

        loaded = await risks.get_current_by_asset(asset, organization_id=org)
        assert loaded is not None
        assert loaded.overall_score == score.overall_score
        assert loaded.attack_path_score == 0.0

        by_id = await risks.get_by_id(score.id.value, organization_id=org)
        assert by_id is not None

        listed = await risks.list_by_organization(org, min_score=0.0, limit=10)
        assert len(listed) >= 1

        hist = await history.list_for_asset(asset.value, organization_id=org, limit=10)
        assert len(hist) >= 1

        factor_rows = await factors.list_by_asset(asset.value, organization_id=org)
        assert len(factor_rows) == 1

        loaded_assessment = await assessments.get_by_id(
            assessment.id.value, organization_id=org
        )
        assert loaded_assessment is not None
        assert loaded_assessment.status == "COMPLETED"

        # Idempotent overwrite of current score for same org+asset
        score2 = _score(org, asset)
        score2 = CloudRiskScore.calculate(
            organization_id=org,
            cloud_asset_id=asset,
            dimensions=CloudRiskEngine().score_dimensions(
                RiskSignalSnapshot(open_finding_severities=("CRITICAL",))
            )[0],
            components=[],
            evidence=[],
            previous=loaded,
            now=NOW,
        )
        await risks.save(score2)
        again = await risks.get_current_by_asset(asset, organization_id=org)
        assert again is not None
        assert again.id.value == loaded.id.value
