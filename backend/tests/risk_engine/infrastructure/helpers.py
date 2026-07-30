"""Shared aggregate builders for risk_engine infrastructure tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ulid import ULID

from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
from risk_engine.domain.aggregates.risk_correlation_set import RiskCorrelationSet
from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
from risk_engine.domain.value_objects.enums import RiskDimension, RiskScale, RiskSignalType
from risk_engine.domain.value_objects.identifiers import (
    CorrelationSetId,
    RiskProfileId,
    TenantId,
)
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference


def make_tenant_id() -> TenantId:
    return TenantId(ULID())


def make_signal(
    tenant_id: TenantId,
    *,
    subject_reference: str | None = "asset-42",
    source_context: str = "vulnerability_engine",
    source_id: str | None = None,
    raw_value: float = 7.5,
    observed_at: datetime | None = None,
) -> RiskSignalReference:
    return RiskSignalReference(
        tenant_id=tenant_id,
        source_context=source_context,
        source_aggregate_type="Vulnerability",
        source_id=source_id or str(uuid4()),
        signal_type=RiskSignalType.SEVERITY_RATING,
        raw_value=raw_value,
        raw_scale=RiskScale.CVSS_0_10,
        observed_at=observed_at or datetime.now(UTC),
        subject_reference=subject_reference,
    )


def make_contribution(
    tenant_id: TenantId,
    *,
    dimension: RiskDimension = RiskDimension.VULNERABILITY,
    normalized_value: float = 7.5,
    computed_at: datetime | None = None,
) -> RiskContribution:
    now = computed_at or datetime.now(UTC)
    return RiskContribution(
        dimension=dimension,
        normalized_score=NormalizedRiskScore(normalized_value),
        source_signal=make_signal(tenant_id, raw_value=normalized_value, observed_at=now),
        computed_at=now,
    )


def make_profile(
    tenant_id: TenantId,
    *,
    profile_id: RiskProfileId | None = None,
    subject_reference: str = "asset-42",
    contributions: tuple[RiskContribution, ...] | None = None,
    composite_score: CompositeRiskScore | None = None,
    now: datetime | None = None,
) -> EnterpriseRiskProfile:
    now = now or datetime.now(UTC)
    return EnterpriseRiskProfile(
        profile_id=profile_id or RiskProfileId.generate(),
        tenant_id=tenant_id,
        subject_reference=subject_reference,
        created_at=now,
        contributions=contributions or (make_contribution(tenant_id, computed_at=now),),
        composite_score=composite_score,
    )


def make_composite_score(
    *,
    value: float = 6.0,
    weight_profile_id: str = "default-v1",
    computed_at: datetime | None = None,
) -> CompositeRiskScore:
    return CompositeRiskScore(
        value=NormalizedRiskScore(value),
        weight_profile_id=weight_profile_id,
        computed_at=computed_at or datetime.now(UTC),
    )


def make_correlation_set(
    tenant_id: TenantId,
    *,
    correlation_set_id: CorrelationSetId | None = None,
    signal_count: int = 2,
    subject_reference: str = "asset-99",
    now: datetime | None = None,
) -> RiskCorrelationSet:
    now = now or datetime.now(UTC)
    signals = tuple(
        make_signal(
            tenant_id,
            subject_reference=subject_reference,
            observed_at=now + timedelta(minutes=i),
        )
        for i in range(signal_count)
    )
    return RiskCorrelationSet.create(
        correlation_set_id=correlation_set_id or CorrelationSetId.generate(),
        tenant_id=tenant_id,
        signal_references=signals,
        now=now,
    )
