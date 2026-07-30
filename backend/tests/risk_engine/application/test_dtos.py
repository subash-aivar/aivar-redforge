from __future__ import annotations

from datetime import UTC, datetime

import pytest

from risk_engine.application.dtos.risk_profile_dto import (
    EnterpriseRiskProfileDTO,
    RiskContributionDTO,
    RiskCorrelationDTO,
    RiskScoreSnapshotDTO,
    RiskTimelineDTO,
)
from risk_engine.application.dtos.risk_profile_outcomes import RiskProfileOperationResult


def test_dtos_are_frozen() -> None:
    now = datetime.now(UTC)
    contribution = RiskContributionDTO(
        dimension="vulnerability",
        normalized_score=5.0,
        source_context="vulnerability_engine",
        source_id="sig-1",
        computed_at=now,
    )
    with pytest.raises(AttributeError):
        contribution.normalized_score = 9.0  # type: ignore[misc]

    profile_dto = EnterpriseRiskProfileDTO(
        profile_id="p1",
        tenant_id="t1",
        subject_reference="asset-1",
        status="open",
        created_at=now,
        updated_at=now,
        contributions=(contribution,),
    )
    with pytest.raises(AttributeError):
        profile_dto.status = "closed"  # type: ignore[misc]

    correlation_dto = RiskCorrelationDTO(
        correlation_set_id="c1", tenant_id="t1", formed_at=now, signal_references=("s1", "s2")
    )
    with pytest.raises(AttributeError):
        correlation_dto.tenant_id = "t2"  # type: ignore[misc]

    snapshot = RiskScoreSnapshotDTO(value=5.0, weight_profile_id="default:v1", computed_at=now)
    timeline = RiskTimelineDTO(
        profile_id="p1", tenant_id="t1", snapshots=(snapshot,), trend_direction="stable"
    )
    with pytest.raises(AttributeError):
        timeline.trend_direction = "increasing"  # type: ignore[misc]

    outcome = RiskProfileOperationResult(success=True, profile=profile_dto)
    with pytest.raises(AttributeError):
        outcome.success = False  # type: ignore[misc]


def test_profile_dto_never_holds_domain_objects() -> None:
    now = datetime.now(UTC)
    dto = EnterpriseRiskProfileDTO(
        profile_id="p1",
        tenant_id="t1",
        subject_reference="asset-1",
        status="open",
        created_at=now,
        updated_at=now,
    )
    for value in (dto.profile_id, dto.tenant_id, dto.subject_reference, dto.status):
        assert isinstance(value, str)
