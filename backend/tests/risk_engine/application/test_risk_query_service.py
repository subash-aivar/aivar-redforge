from __future__ import annotations

from datetime import UTC, datetime

import pytest

from risk_engine.application.queries.risk_profile_queries import (
    GetEnterpriseRiskProfileQuery,
    GetRiskCorrelationSetQuery,
    ListEnterpriseRiskProfilesQuery,
)
from risk_engine.application.services.risk_query_service import RiskQueryService
from risk_engine.domain.aggregates.risk_correlation_set import RiskCorrelationSet
from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.factories.risk_profile_factory import RiskProfileFactory
from risk_engine.domain.services.risk_normalization_service import RiskNormalizationService
from risk_engine.domain.value_objects.enums import RiskDimension, RiskProfileStatus
from risk_engine.domain.value_objects.identifiers import CorrelationSetId, RiskProfileId
from tests.risk_engine.application.conftest import make_signal_reference


@pytest.fixture
def service(profile_repository, correlation_repository) -> RiskQueryService:
    return RiskQueryService(profile_repository, correlation_repository)


def _build_profile(tenant_id, subject_reference="asset-1"):
    now = datetime.now(UTC)
    signal = make_signal_reference(tenant_id, subject_reference=subject_reference)
    contribution = RiskContribution(
        dimension=RiskDimension.VULNERABILITY,
        normalized_score=RiskNormalizationService.normalize(signal.raw_value, signal.raw_scale),
        source_signal=signal,
        computed_at=now,
    )
    return RiskProfileFactory.create(tenant_id, subject_reference, contribution, now)


class TestGetEnterpriseRiskProfileQuery:
    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, service, tenant_id):
        result = await service.get_profile(
            GetEnterpriseRiskProfileQuery(tenant_id, RiskProfileId.generate())
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_dto_when_present(self, service, profile_repository, tenant_id):
        profile = _build_profile(tenant_id)
        await profile_repository.save(profile)
        result = await service.get_profile(
            GetEnterpriseRiskProfileQuery(tenant_id, profile.profile_id)
        )
        assert result is not None
        assert result.profile_id == str(profile.profile_id)

    @pytest.mark.asyncio
    async def test_wrong_tenant_returns_none(
        self, service, profile_repository, tenant_id, other_tenant_id
    ):
        profile = _build_profile(tenant_id)
        await profile_repository.save(profile)
        result = await service.get_profile(
            GetEnterpriseRiskProfileQuery(other_tenant_id, profile.profile_id)
        )
        assert result is None


class TestListEnterpriseRiskProfilesQuery:
    @pytest.mark.asyncio
    async def test_lists_only_tenant_profiles(
        self, service, profile_repository, tenant_id, other_tenant_id
    ):
        mine = _build_profile(tenant_id)
        theirs = _build_profile(other_tenant_id)
        await profile_repository.save(mine)
        await profile_repository.save(theirs)

        results = await service.list_profiles(ListEnterpriseRiskProfilesQuery(tenant_id))
        assert {r.profile_id for r in results} == {str(mine.profile_id)}

    @pytest.mark.asyncio
    async def test_filters_by_status(self, service, profile_repository, tenant_id):
        profile = _build_profile(tenant_id)
        await profile_repository.save(profile)
        results = await service.list_profiles(
            ListEnterpriseRiskProfilesQuery(tenant_id, status=RiskProfileStatus.ACKNOWLEDGED)
        )
        assert results == ()

    @pytest.mark.asyncio
    async def test_filters_by_subject_reference(self, service, profile_repository, tenant_id):
        a = _build_profile(tenant_id, subject_reference="asset-a")
        b = _build_profile(tenant_id, subject_reference="asset-b")
        await profile_repository.save(a)
        await profile_repository.save(b)
        results = await service.list_profiles(
            ListEnterpriseRiskProfilesQuery(tenant_id, subject_reference="asset-a")
        )
        assert {r.profile_id for r in results} == {str(a.profile_id)}


class TestGetRiskCorrelationSetQuery:
    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, service, tenant_id):
        result = await service.get_correlation_set(
            GetRiskCorrelationSetQuery(tenant_id, CorrelationSetId.generate())
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_dto_when_present(self, service, correlation_repository, tenant_id):
        now = datetime.now(UTC)
        refs = (
            make_signal_reference(tenant_id, source_id="s1", subject_reference="subj"),
            make_signal_reference(tenant_id, source_id="s2", subject_reference="subj"),
        )
        correlation_set = RiskCorrelationSet.create(
            CorrelationSetId.generate(), tenant_id, refs, now
        )
        await correlation_repository.save(correlation_set)
        result = await service.get_correlation_set(
            GetRiskCorrelationSetQuery(tenant_id, correlation_set.correlation_set_id)
        )
        assert result is not None
        assert result.correlation_set_id == str(correlation_set.correlation_set_id)
        assert len(result.signal_references) == 2

    @pytest.mark.asyncio
    async def test_wrong_tenant_returns_none(
        self, service, correlation_repository, tenant_id, other_tenant_id
    ):
        now = datetime.now(UTC)
        refs = (
            make_signal_reference(tenant_id, source_id="s1", subject_reference="subj"),
            make_signal_reference(tenant_id, source_id="s2", subject_reference="subj"),
        )
        correlation_set = RiskCorrelationSet.create(
            CorrelationSetId.generate(), tenant_id, refs, now
        )
        await correlation_repository.save(correlation_set)
        result = await service.get_correlation_set(
            GetRiskCorrelationSetQuery(other_tenant_id, correlation_set.correlation_set_id)
        )
        assert result is None
