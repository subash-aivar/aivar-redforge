"""Mapping + entity serialization coverage for cloud risk."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.domain.cloud_security.risk.engine import CloudRiskEngine, RiskSignalSnapshot
from redforge.domain.cloud_security.risk.entities import (
    RiskContribution,
    RiskEvidence,
    RiskHistoryEntry,
    RiskWeight,
)
from redforge.domain.cloud_security.risk.factor import (
    CloudRiskAssessment,
    CloudRiskExposure,
    CloudRiskFactor,
)
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.risk.value_objects import (
    RiskCategory,
    RiskConfidence,
    RiskSource,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId
from redforge.infrastructure.cloud_security.risk.mappings import (
    assessment_from_model,
    assessment_to_model,
    exposure_from_model,
    exposure_to_model,
    factor_from_model,
    factor_to_model,
    history_row_from_score,
    score_from_model,
    score_to_model,
)

ORG = OrganizationId("01HXORG0000000000000000001")
ASSET = CloudAssetId(uuid4())
NOW = datetime(2026, 7, 19, 17, 0, 0, tzinfo=UTC)


def _make_score() -> CloudRiskScore:
    dims, components, evidence = CloudRiskEngine().score_dimensions(
        RiskSignalSnapshot(open_finding_severities=("MEDIUM",))
    )
    return CloudRiskScore.calculate(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        dimensions=dims,
        components=components,
        evidence=evidence,
        now=NOW,
    )


def test_score_mapping_round_trip() -> None:
    score = _make_score()
    model = score_to_model(score)
    restored = score_from_model(model)
    assert restored.overall_score == score.overall_score
    assert restored.cloud_asset_id == score.cloud_asset_id
    assert restored.state == score.state
    assert len(restored.score_components) == len(score.score_components)


def test_history_row_from_score() -> None:
    score = _make_score()
    row = history_row_from_score(score)
    assert row.organization_id == str(ORG)
    assert row.overall_score == score.overall_score
    assert row.risk_score_id == score.id.value


def test_factor_mapping_round_trip() -> None:
    factor = CloudRiskFactor.create(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        category=RiskCategory.CONFIGURATION,
        source=RiskSource.CSPM,
        title="finding",
        score=6.0,
        confidence=RiskConfidence.MEDIUM,
        now=NOW,
    )
    model = factor_to_model(factor)
    restored = factor_from_model(model)
    assert restored.title == factor.title
    assert restored.score == factor.score


def test_exposure_mapping_round_trip() -> None:
    exposure = CloudRiskExposure.derive(
        organization_id=ORG,
        cloud_asset_id=ASSET,
        public_accessibility=True,
        now=NOW,
    )
    model = exposure_to_model(exposure)
    restored = exposure_from_model(model)
    assert restored.public_accessibility is True
    assert restored.exposure_score == exposure.exposure_score


def test_assessment_mapping_round_trip() -> None:
    assessment = CloudRiskAssessment.start(
        organization_id=ORG,
        scope="BATCH",
        target_id="batch:1",
        calculation_version="1.0.0+default",
        now=NOW,
    )
    assessment.complete(
        assets_evaluated=1, risks_created=1, risks_updated=0, now=NOW
    )
    model = assessment_to_model(assessment)
    restored = assessment_from_model(model)
    assert restored.status == "COMPLETED"
    assert restored.assets_evaluated == 1


def test_evidence_dict_round_trip() -> None:
    ev = RiskEvidence(
        evidence_id="e1",
        source=RiskSource.CSPM,
        summary="open findings",
        details={"n": 2},
        observed_at=NOW,
    )
    restored = RiskEvidence.from_dict(ev.to_dict())
    assert restored.evidence_id == "e1"
    assert restored.source == RiskSource.CSPM


def test_contribution_dict_round_trip() -> None:
    c = RiskContribution(
        dimension="cspm",
        raw_score=5.0,
        weight=0.15,
        weighted_score=0.75,
        rationale="test",
        category=RiskCategory.CONFIGURATION,
    )
    restored = RiskContribution.from_dict(c.to_dict())
    assert restored.dimension == "cspm"
    assert restored.weighted_score == 0.75


def test_history_entry_dict_round_trip() -> None:
    entry = RiskHistoryEntry(
        history_id=str(uuid4()),
        overall_score=3.5,
        state="ACTIVE",
        calculation_version="1.0.0+default",
        recorded_at=NOW,
        reason="calculated",
        dimensions={"cspm": 5.0},
    )
    restored = RiskHistoryEntry.from_dict(entry.to_dict())
    assert restored.overall_score == 3.5
    assert restored.dimensions == {"cspm": 5.0}


def test_risk_weight_to_dict() -> None:
    w = RiskWeight(profile_name="default", weights={"cspm": 0.15})
    assert w.to_dict()["profile_name"] == "default"


@pytest.mark.parametrize(
    "exposure_kwargs",
    [
        {"public_accessibility": True},
        {"internet_exposure": True},
        {"encryption_at_rest": False},
        {"privilege_level": "HIGH"},
        {"privilege_level": "ADMIN"},
    ],
)
def test_exposure_score_components(exposure_kwargs: dict[str, object]) -> None:
    base = {
        "organization_id": ORG,
        "cloud_asset_id": ASSET,
        "now": NOW,
    }
    exp = CloudRiskExposure.derive(**base, **exposure_kwargs)  # type: ignore[arg-type]
    assert exp.exposure_score > 0.0
