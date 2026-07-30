from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from risk_engine.application.exceptions import EnterpriseRiskProfileNotFoundError
from risk_engine.application.queries.risk_profile_queries import GetRiskTimelineQuery
from risk_engine.application.services.risk_timeline_service import RiskTimelineApplicationService
from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.factories.risk_profile_factory import RiskProfileFactory
from risk_engine.domain.services.risk_normalization_service import RiskNormalizationService
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
from risk_engine.domain.value_objects.enums import RiskDimension, RiskTrendDirection
from risk_engine.domain.value_objects.identifiers import RiskProfileId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from tests.risk_engine.application.conftest import make_signal_reference


@pytest.fixture
def service(profile_repository) -> RiskTimelineApplicationService:
    return RiskTimelineApplicationService(profile_repository)


async def _build_and_save_profile(profile_repository, tenant_id):
    now = datetime.now(UTC)
    signal = make_signal_reference(tenant_id)
    contribution = RiskContribution(
        dimension=RiskDimension.VULNERABILITY,
        normalized_score=RiskNormalizationService.normalize(signal.raw_value, signal.raw_scale),
        source_signal=signal,
        computed_at=now,
    )
    profile = RiskProfileFactory.create(tenant_id, "asset-1", contribution, now)
    await profile_repository.save(profile)
    return profile


class TestGetRiskTimelineQuery:
    @pytest.mark.asyncio
    async def test_raises_not_found_for_unknown_profile(self, service, tenant_id):
        with pytest.raises(EnterpriseRiskProfileNotFoundError):
            await service.get_timeline(GetRiskTimelineQuery(tenant_id, RiskProfileId.generate()))

    @pytest.mark.asyncio
    async def test_stable_trend_with_insufficient_history(
        self, service, profile_repository, tenant_id
    ):
        profile = await _build_and_save_profile(profile_repository, tenant_id)
        dto = await service.get_timeline(GetRiskTimelineQuery(tenant_id, profile.profile_id))
        assert dto.trend_direction == RiskTrendDirection.STABLE.value
        assert dto.snapshots == ()

    @pytest.mark.asyncio
    async def test_increasing_trend_across_recomputes(self, service, profile_repository, tenant_id):
        profile = await _build_and_save_profile(profile_repository, tenant_id)
        base = datetime.now(UTC)
        signal = make_signal_reference(tenant_id)
        contribution = RiskContribution(
            dimension=RiskDimension.VULNERABILITY,
            normalized_score=NormalizedRiskScore(2.0),
            source_signal=signal,
            computed_at=base,
        )
        for i, score_value in enumerate((2.0, 3.0, 4.0), start=1):
            score = CompositeRiskScore(
                value=NormalizedRiskScore(score_value),
                weight_profile_id="default:v1",
                computed_at=base + timedelta(hours=i),
            )
            profile.recompute_score(tenant_id, score, (contribution,), base + timedelta(hours=i))
            await profile_repository.save(profile)

        dto = await service.get_timeline(GetRiskTimelineQuery(tenant_id, profile.profile_id))
        assert dto.trend_direction == RiskTrendDirection.INCREASING.value
        assert len(dto.snapshots) == 3

    @pytest.mark.asyncio
    async def test_since_until_window_filters_snapshots(
        self, service, profile_repository, tenant_id
    ):
        profile = await _build_and_save_profile(profile_repository, tenant_id)
        base = datetime.now(UTC)
        signal = make_signal_reference(tenant_id)
        contribution = RiskContribution(
            dimension=RiskDimension.VULNERABILITY,
            normalized_score=NormalizedRiskScore(2.0),
            source_signal=signal,
            computed_at=base,
        )
        for i, score_value in enumerate((2.0, 5.0), start=1):
            score = CompositeRiskScore(
                value=NormalizedRiskScore(score_value),
                weight_profile_id="default:v1",
                computed_at=base + timedelta(hours=i),
            )
            profile.recompute_score(tenant_id, score, (contribution,), base + timedelta(hours=i))
            await profile_repository.save(profile)

        dto = await service.get_timeline(
            GetRiskTimelineQuery(
                tenant_id,
                profile.profile_id,
                since=base + timedelta(hours=2),
            )
        )
        assert len(dto.snapshots) == 1
        assert dto.snapshots[0].value == pytest.approx(5.0)
