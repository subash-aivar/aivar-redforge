"""Shared fixtures for risk_engine's application-layer tests (M48C).

Fake, in-memory-dict implementations of the `EnterpriseRiskProfileRepository`,
`RiskCorrelationRepository` (now async `ABC` ports, converted from
sync `Protocol`s in the M48C contract correction — see
`docs/architecture/m48/M48E_ADR.md`) and the `IUnitOfWork` ABC live
here — never in `src/`, per M48C's explicit scope boundary (no
infrastructure, not even in-memory, may exist in `src/risk_engine`)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from risk_engine.domain.value_objects.enums import RiskScale, RiskSignalType
from risk_engine.domain.value_objects.identifiers import TenantId
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference
from risk_engine.domain.value_objects.weight_profile import RiskWeightProfile

if TYPE_CHECKING:
    from collections.abc import Sequence

    from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
    from risk_engine.domain.aggregates.risk_correlation_set import RiskCorrelationSet
    from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
    from risk_engine.domain.value_objects.identifiers import (
        CorrelationSetId,
        RiskProfileId,
    )


class FakeEnterpriseRiskProfileRepository:
    """An in-memory-dict fake satisfying `EnterpriseRiskProfileRepository`
    structurally (duck-typed against the async ABC) — local to tests
    only."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], EnterpriseRiskProfile] = {}
        self._history: dict[tuple[str, str], list[CompositeRiskScore]] = {}

    async def save(self, profile: EnterpriseRiskProfile) -> None:
        key = (str(profile.tenant_id), str(profile.profile_id))
        self._by_key[key] = profile
        if profile.composite_score is not None:
            self._history.setdefault(key, []).append(profile.composite_score)

    async def get(
        self, tenant_id: TenantId, profile_id: RiskProfileId
    ) -> EnterpriseRiskProfile | None:
        profile = self._by_key.get((str(tenant_id), str(profile_id)))
        if profile is None or profile.tenant_id != tenant_id:
            return None
        return profile

    async def list(self, tenant_id: TenantId, **filters: object) -> Sequence[EnterpriseRiskProfile]:
        results = [p for (tid, _), p in self._by_key.items() if tid == str(tenant_id)]
        status = filters.get("status")
        if status is not None:
            results = [p for p in results if p.status == status]
        subject_reference = filters.get("subject_reference")
        if subject_reference is not None:
            results = [p for p in results if p.subject_reference == subject_reference]
        return tuple(results)

    async def score_history(
        self, tenant_id: TenantId, profile_id: RiskProfileId
    ) -> Sequence[CompositeRiskScore]:
        return tuple(self._history.get((str(tenant_id), str(profile_id)), ()))


class FakeRiskCorrelationRepository:
    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], RiskCorrelationSet] = {}

    async def save(self, correlation_set: RiskCorrelationSet) -> None:
        key = (str(correlation_set.tenant_id), str(correlation_set.correlation_set_id))
        self._by_key[key] = correlation_set

    async def get(
        self, tenant_id: TenantId, correlation_set_id: CorrelationSetId
    ) -> RiskCorrelationSet | None:
        correlation_set = self._by_key.get((str(tenant_id), str(correlation_set_id)))
        if correlation_set is None or correlation_set.tenant_id != tenant_id:
            return None
        return correlation_set

    async def list(self, tenant_id: TenantId) -> Sequence[RiskCorrelationSet]:
        return tuple(cs for (tid, _), cs in self._by_key.items() if tid == str(tenant_id))


class FakeUnitOfWork:
    """An in-memory fake structurally satisfying `IUnitOfWork` (async
    commit/rollback, bundled repository attributes) — local to tests
    only, matching the platform-wide `IUnitOfWork` shape."""

    def __init__(
        self,
        risk_profiles: FakeEnterpriseRiskProfileRepository,
        correlation_sets: FakeRiskCorrelationRepository,
    ) -> None:
        self.risk_profiles = risk_profiles
        self.correlation_sets = correlation_sets
        self._committed = False
        self.committed = 0
        self.rolled_back = 0

    async def commit(self) -> None:
        self._committed = True
        self.committed += 1

    async def rollback(self) -> None:
        self.rolled_back += 1

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        if not self._committed:
            await self.rollback()


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def other_tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def profile_repository() -> FakeEnterpriseRiskProfileRepository:
    return FakeEnterpriseRiskProfileRepository()


@pytest.fixture
def correlation_repository() -> FakeRiskCorrelationRepository:
    return FakeRiskCorrelationRepository()


@pytest.fixture
def unit_of_work(
    profile_repository: FakeEnterpriseRiskProfileRepository,
    correlation_repository: FakeRiskCorrelationRepository,
) -> FakeUnitOfWork:
    return FakeUnitOfWork(profile_repository, correlation_repository)


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


def make_signal_reference(
    tenant_id: TenantId,
    *,
    subject_reference: str = "asset-123",
    raw_value: float = 7.5,
    raw_scale: RiskScale = RiskScale.CVSS_0_10,
    source_id: str = "sig-1",
    observed_at: datetime | None = None,
) -> RiskSignalReference:
    return RiskSignalReference(
        tenant_id=tenant_id,
        source_context="vulnerability_engine",
        source_aggregate_type="ScanFinding",
        source_id=source_id,
        signal_type=RiskSignalType.SEVERITY_RATING,
        raw_value=raw_value,
        raw_scale=raw_scale,
        observed_at=observed_at or datetime.now(UTC),
        subject_reference=subject_reference,
    )


def make_weight_profile() -> RiskWeightProfile:
    from risk_engine.domain.value_objects.enums import RiskDimension

    return RiskWeightProfile(
        profile_name="default",
        version=1,
        weights={RiskDimension.VULNERABILITY: 1.0, RiskDimension.CLOUD: 1.0},
    )


@pytest.fixture
def weight_profile() -> RiskWeightProfile:
    return make_weight_profile()


@pytest.fixture
def week() -> timedelta:
    return timedelta(days=7)
