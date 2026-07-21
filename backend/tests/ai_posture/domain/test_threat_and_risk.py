"""Domain tests for threat assessment and risk scoring."""

from __future__ import annotations

from datetime import datetime

import pytest

from ai_posture.domain.aggregates.ai_risk_score_snapshot import AIRiskScoreSnapshot
from ai_posture.domain.aggregates.ai_threat_profile import AIThreatProfile
from ai_posture.domain.exceptions.domain_exceptions import ThreatProfileArchived
from ai_posture.domain.services.ai_risk_scoring_service import AIRiskScoringService
from ai_posture.domain.services.ai_threat_assessment_service import AIThreatAssessmentService
from ai_posture.domain.value_objects.enums import (
    AISystemKind,
    DownstreamActionCapability,
    ExposureLevel,
    InputSurface,
    OutputVerbosity,
    SanitizationPosture,
)
from ai_posture.domain.value_objects.identifiers import (
    AIRiskScoreSnapshotId,
    AISystemAssetId,
    AIThreatProfileId,
    TenantId,
)
from ai_posture.domain.value_objects.posture_vos import SCORE_INPUT_VERSION, compute_composite_score


def test_prompt_injection_critical_when_unsanitized_write() -> None:
    svc = AIThreatAssessmentService()
    result = svc.assess_prompt_injection(
        input_surface=InputSurface.USER_FACING_TEXT,
        sanitization_posture=SanitizationPosture.NONE,
        downstream_action_capability=DownstreamActionCapability.WRITE_UNRESTRICTED,
    )
    assert result.exposure_level == ExposureLevel.CRITICAL


def test_model_extraction_low_when_controls_present() -> None:
    svc = AIThreatAssessmentService()
    result = svc.assess_model_extraction(
        query_rate_limiting_present=True,
        output_verbosity=OutputVerbosity.MINIMAL,
        watermarking_present=True,
    )
    assert result.exposure_level == ExposureLevel.LOW


def test_threat_profile_independent_create(now: datetime, tenant_id: TenantId) -> None:
    profile = AIThreatProfile.create(
        profile_id=AIThreatProfileId.generate(),
        tenant_id=tenant_id,
        ai_system_asset_id=AISystemAssetId.generate(),
        ai_system_kind=AISystemKind.FOUNDATION_MODEL_API,
        now=now,
    )
    assert profile.requires_reassessment is True
    assert any(e.__class__.__name__ == "AIThreatProfileCreated" for e in profile.pop_events())


def test_archived_profile_rejects_assessment(now: datetime, tenant_id: TenantId) -> None:
    profile = AIThreatProfile.create(
        profile_id=AIThreatProfileId.generate(),
        tenant_id=tenant_id,
        ai_system_asset_id=AISystemAssetId.generate(),
        ai_system_kind=AISystemKind.RAG_PIPELINE,
        now=now,
    )
    profile.archive(tenant_id)
    svc = AIThreatAssessmentService()
    assessment = svc.assess_prompt_injection(
        input_surface=InputSurface.RAG_RETRIEVED_CONTENT,
        sanitization_posture=SanitizationPosture.HEURISTIC,
        downstream_action_capability=DownstreamActionCapability.READ_ONLY,
    )
    with pytest.raises(ThreatProfileArchived):
        profile.record_prompt_injection(tenant_id, assessment, ["ev-1"], now)


def test_composite_score_deterministic_weights() -> None:
    scorer = AIRiskScoringService()
    components = scorer.build_components(max_exposure_score=100.0)
    score = scorer.compute_composite(components)
    # 100 * 0.40 + 0 + 0 + 0
    assert score == 40.0
    assert scorer.score_input_version == SCORE_INPUT_VERSION
    assert compute_composite_score(components) == score


def test_snapshot_staleness(now: datetime, tenant_id: TenantId) -> None:
    from datetime import timedelta

    scorer = AIRiskScoringService()
    components = scorer.build_components(max_exposure_score=50.0)
    snap = AIRiskScoreSnapshot.create(
        snapshot_id=AIRiskScoreSnapshotId.generate(),
        tenant_id=tenant_id,
        ai_system_asset_id=AISystemAssetId.generate(),
        components=components,
        now=now,
    )
    assert snap.is_stale(now) is False
    assert snap.is_stale(now + timedelta(hours=25)) is True
