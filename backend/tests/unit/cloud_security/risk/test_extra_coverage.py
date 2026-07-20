"""Additional Phase 7 coverage — engine edges, VO, DTOs, ACL stubs."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.application.cloud_security.risk.dtos import (
    CalculateRiskCommand,
    RiskAssessmentResultDTO,
    RiskFactorDTO,
    RiskScoreDTO,
    RiskSummaryDTO,
)
from redforge.domain.cloud_security.risk.engine import CloudRiskEngine, RiskSignalSnapshot
from redforge.domain.cloud_security.risk.entities import RiskException
from redforge.domain.cloud_security.risk.exceptions import CloudRiskNotFoundError
from redforge.domain.cloud_security.risk.value_objects import (
    CloudRiskScoreId,
    RiskCalculationVersion,
    RiskConfidence,
    RiskDimensionScores,
    RiskScore,
    RiskTrend,
    RiskWeightProfile,
)
from redforge.infrastructure.cloud_security.acl.exposure_acl import ExposureSignalACL
from redforge.infrastructure.cloud_security.acl.threat_intel_acl import ThreatIntelRiskACL


@pytest.mark.parametrize(
    ("exposure", "public", "enc", "min_score"),
    [
        ("PUBLIC", True, False, 8.0),
        ("INTERNET", False, True, 6.0),
        ("INTERNAL", False, True, 1.0),
        ("PRIVATE", False, True, 1.0),
        ("UNKNOWN", False, True, 0.0),
    ],
)
def test_exposure_score_variants(
    exposure: str, public: bool, enc: bool, min_score: float
) -> None:
    snap = RiskSignalSnapshot(
        network_exposure=exposure,
        public_accessibility=public,
        encryption_at_rest=enc,
    )
    dims, _, _ = CloudRiskEngine().score_dimensions(snap)
    assert dims.exposure >= min_score


@pytest.mark.parametrize(
    ("label", "tags", "expected"),
    [
        ("CRITICAL", (), 10.0),
        ("HIGH", (), 7.5),
        ("LOW", (), 2.5),
        ("MEDIUM", (), 5.0),
        ("MEDIUM", (("criticality", "tier0"),), 10.0),
        ("MEDIUM", (("criticality", "high"),), 7.5),
    ],
)
def test_criticality_variants(
    label: str, tags: tuple[tuple[str, str], ...], expected: float
) -> None:
    snap = RiskSignalSnapshot(business_criticality=label, tags=tags)
    dims, _, _ = CloudRiskEngine().score_dimensions(snap)
    assert dims.criticality == expected


@pytest.mark.parametrize("ratio", [0.0, 0.25, 0.5, 0.75, 1.0])
def test_compliance_gap_ratio(ratio: float) -> None:
    snap = RiskSignalSnapshot(compliance_gap_ratio=ratio)
    dims, _, _ = CloudRiskEngine().score_dimensions(snap)
    assert dims.compliance == pytest.approx(ratio * 10.0)


def test_threat_intel_clamped() -> None:
    snap = RiskSignalSnapshot(threat_intel_score=99.0)
    dims, _, _ = CloudRiskEngine().score_dimensions(snap)
    assert dims.threat_intel == 10.0


def test_engine_rationale_strings() -> None:
    engine = CloudRiskEngine()
    snap = RiskSignalSnapshot(
        open_finding_severities=("LOW",),
        privilege_level="LOW",
        network_exposure="INTERNAL",
        k8s_security_score=90.0,
        runtime_event_severities=("INFO",),
        compliance_gap_ratio=0.1,
        business_criticality="LOW",
        threat_intel_score=1.0,
    )
    for dim in RiskWeightProfile.default().to_dict():
        text = engine._rationale(dim, snap)
        assert isinstance(text, str)
        assert text


def test_risk_score_clamp() -> None:
    assert RiskScore.clamp(50).value == 10.0
    assert RiskScore.clamp(-5).value == 0.0


def test_calculation_version_default() -> None:
    v = RiskCalculationVersion.default()
    assert v.profile == "default"
    assert RiskCalculationVersion.from_dict(None).major == 1


def test_calculation_version_invalid() -> None:
    with pytest.raises(ValueError):
        RiskCalculationVersion(major=-1, minor=0, patch=0)
    with pytest.raises(ValueError):
        RiskCalculationVersion(major=1, minor=0, patch=0, profile="")


def test_cloud_risk_score_id() -> None:
    rid = CloudRiskScoreId.new()
    assert CloudRiskScoreId.from_str(str(rid)).value == rid.value


def test_dimension_from_dict_empty() -> None:
    dims = RiskDimensionScores.from_dict(None)
    assert dims.cspm == 0.0


def test_weight_profile_from_dict_empty() -> None:
    assert RiskWeightProfile.from_dict(None).cspm == RiskWeightProfile.default().cspm


def test_risk_exception_to_dict() -> None:
    ex = RiskException(
        exception_id="x1",
        reason="ok",
        approved_by="admin",
        expires_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    assert ex.to_dict()["exception_id"] == "x1"


def test_dto_constructors() -> None:
    cmd = CalculateRiskCommand(organization_id="org", organization_wide=True)
    assert cmd.organization_wide is True
    summary = RiskSummaryDTO(
        organization_id="org",
        total_scores=0,
        average_score=0.0,
        critical_count=0,
        high_count=0,
    )
    assert summary.total_scores == 0
    result = RiskAssessmentResultDTO(
        assessment_id=str(uuid4()),
        organization_id="org",
        scope="ASSET",
        target_id="t",
        status="COMPLETED",
        assets_evaluated=1,
        risks_created=1,
        risks_updated=0,
        calculation_version="1.0.0+default",
    )
    assert result.status == "COMPLETED"
    factor = RiskFactorDTO(
        factor_id=str(uuid4()),
        organization_id="org",
        cloud_asset_id=str(uuid4()),
        category="CONFIGURATION",
        source="CSPM",
        title="t",
        description="",
        score=1.0,
        severity="LOW",
        confidence="MEDIUM",
    )
    assert factor.score == 1.0
    score_dto = RiskScoreDTO(
        risk_id=str(uuid4()),
        organization_id="org",
        cloud_asset_id=str(uuid4()),
        overall_score=1.0,
        threat_intel_score=0.0,
        compliance_score=0.0,
        identity_score=0.0,
        exposure_score=0.0,
        business_criticality_score=0.0,
        attack_path_score=0.0,
        cspm_score=0.0,
        kubernetes_score=0.0,
        runtime_score=0.0,
        confidence=RiskConfidence.MEDIUM.value,
        trend=RiskTrend.STABLE.value,
        state="ACTIVE",
        calculation_version="1.0.0+default",
        computed_at=datetime.now(UTC),
        valid_until=datetime.now(UTC),
    )
    assert score_dto.attack_path_score == 0.0


def test_not_found_error() -> None:
    err = CloudRiskNotFoundError("abc")
    assert err.risk_id == "abc"


@pytest.mark.asyncio
async def test_threat_intel_acl_stub() -> None:
    class _A:
        pass

    assert await ThreatIntelRiskACL().threat_intel_score_for_asset(_A()) == 0.0  # type: ignore[arg-type]


def test_exposure_acl_encryption_none_defaults_true() -> None:
    from redforge.domain.cloud_security.value_objects import (
        NetworkExposure,
        NormalizedConfig,
    )

    cfg = NormalizedConfig(
        schema_version="1",
        resource_class="compute",
        network_exposure=NetworkExposure.UNKNOWN,
        encryption_at_rest=None,
    )
    signals = ExposureSignalACL.from_config(cfg)
    assert signals["encryption_at_rest"] is True


@pytest.mark.parametrize("n_findings", [0, 1, 3, 5, 10])
def test_cspm_score_scales_with_findings(n_findings: int) -> None:
    sevs = tuple(["HIGH"] * n_findings)
    dims, _, _ = CloudRiskEngine().score_dimensions(
        RiskSignalSnapshot(open_finding_severities=sevs)
    )
    if n_findings == 0:
        assert dims.cspm == 0.0
    else:
        assert dims.cspm > 0.0


def test_components_include_attack_path_stub() -> None:
    _, components, _ = CloudRiskEngine().score_dimensions(RiskSignalSnapshot())
    names = {c.dimension for c in components}
    assert "attack_path" in names
