"""Unit tests for risk application services."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.application.cloud_security.risk.aggregation_service import (
    RiskAggregationService,
)
from redforge.application.cloud_security.risk.correlation_service import (
    RiskCorrelationService,
)
from redforge.application.cloud_security.risk.projection_service import (
    RiskProjectionService,
)
from redforge.domain.cloud_security.risk.engine import CloudRiskEngine, RiskSignalSnapshot
from redforge.domain.cloud_security.risk.factor import CloudRiskExposure, CloudRiskFactor
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.risk.value_objects import RiskSource
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")
ASSET = CloudAssetId(uuid4())
NOW = datetime(2026, 7, 19, 16, 0, 0, tzinfo=UTC)


def _score(overall_hint: RiskSignalSnapshot | None = None) -> CloudRiskScore:
    engine = CloudRiskEngine()
    snap = overall_hint or RiskSignalSnapshot(open_finding_severities=("HIGH",))
    dims, components, evidence = engine.score_dimensions(snap)
    return CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )


def test_aggregation_empty() -> None:
    summary = RiskAggregationService().summarize(organization_id=str(ORG), scores=[])
    assert summary.total_scores == 0
    assert summary.average_score == 0.0


def test_aggregation_counts() -> None:
    scores = [
        _score(RiskSignalSnapshot(open_finding_severities=("CRITICAL",), privilege_level="ADMIN")),
        _score(RiskSignalSnapshot(open_finding_severities=("LOW",))),
    ]
    dims, components, evidence = CloudRiskEngine().score_dimensions(RiskSignalSnapshot())
    scores[1] = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=CloudAssetId(uuid4()),
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )
    summary = RiskAggregationService().summarize(organization_id=str(ORG), scores=scores)
    assert summary.total_scores == 2
    assert summary.average_score >= 0.0
    assert "ACTIVE" in summary.by_state


def test_top_n_ordering() -> None:
    low = _score(RiskSignalSnapshot(open_finding_severities=("LOW",)))
    d_high, c_high, e_high = CloudRiskEngine().score_dimensions(
        RiskSignalSnapshot(open_finding_severities=("CRITICAL",), privilege_level="ADMIN")
    )
    high = CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=CloudAssetId(uuid4()),
        dimensions=d_high,
        components=c_high,
        evidence=e_high,
        now=NOW,
    )
    top = RiskAggregationService().top_n([low, high], n=1)
    assert top[0].overall_score >= low.overall_score


def test_correlation_produces_factors() -> None:
    snap = RiskSignalSnapshot(
        open_finding_severities=("HIGH",),
        privilege_level="HIGH",
        network_exposure="PUBLIC",
    )
    dims, components, evidence, factors = RiskCorrelationService().correlate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        snapshot=snap,
    )
    assert dims.cspm > 0
    assert components
    assert evidence
    assert any(f.source == RiskSource.CSPM for f in factors)


def test_correlation_source_mapping() -> None:
    assert RiskCorrelationService._source_for("runtime") == RiskSource.RUNTIME
    assert RiskCorrelationService._source_for("unknown") == RiskSource.COMPOSITE


@pytest.mark.asyncio
async def test_projection_service_noop_without_acl() -> None:
    score = _score()
    await RiskProjectionService(None).project(score=score, factors=[], exposure=None)


@pytest.mark.asyncio
async def test_projection_service_calls_acl() -> None:
    calls: list[str] = []

    class _ACL:
        async def project_risk(self, *, score: CloudRiskScore) -> None:
            calls.append("risk")

        async def project_factor(self, *, factor: CloudRiskFactor, risk_id: str) -> None:
            calls.append("factor")

        async def project_exposure(
            self, *, exposure: CloudRiskExposure, risk_id: str
        ) -> None:
            calls.append("exposure")

    score = _score()
    _dims, _, _, factors = RiskCorrelationService().correlate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        snapshot=RiskSignalSnapshot(open_finding_severities=("HIGH",)),
    )
    exposure = CloudRiskExposure.derive(
        organization_id=ORG, cloud_asset_id=ASSET, now=NOW
    )
    await RiskProjectionService(_ACL()).project(
        score=score, factors=factors[:1], exposure=exposure
    )
    assert "risk" in calls
    assert "factor" in calls
    assert "exposure" in calls


@pytest.mark.parametrize(
    "dimension",
    [
        "threat_intel",
        "compliance",
        "identity",
        "exposure",
        "attack_path",
        "cspm",
        "criticality",
        "kubernetes",
        "runtime",
    ],
)
def test_category_for_each_dimension(dimension: str) -> None:
    cat = RiskCorrelationService.category_for_dimension(dimension)
    assert cat.value
