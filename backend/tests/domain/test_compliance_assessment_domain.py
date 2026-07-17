"""Domain tests for M24 Phase 2 Organization Assessment."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redforge.domain.compliance.assessment import (
    AssessmentPeriod,
    ComplianceProfile,
    ControlAssessment,
)
from redforge.domain.compliance.events import (
    ComplianceProfileActivated,
    ControlEvidenceLinkConfirmed,
    ControlStatusChanged,
)
from redforge.domain.compliance.exceptions import (
    AssessmentPeriodNotOpenError,
    ControlAssessmentInvariantError,
    DuplicateEvidenceLinkError,
    InvalidControlStatusTransitionError,
    ProfileNotActiveError,
)
from redforge.domain.compliance.services import ControlStatusEvaluator
from redforge.domain.compliance.value_objects import (
    AssessmentPeriodStatus,
    ConfirmedEvidenceLink,
    ControlStatus,
    ControlStatusCode,
    FrameworkKey,
    ProfileStatus,
)
from redforge.shared.identifiers import EntityId

_ORG = "01ORG00000000000000000001"
_ACTOR = "01USER000000000000000001"
_EVIDENCE = "01EVIDENCE00000000000001"


def _period_window() -> tuple[datetime, datetime]:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    return start, start + timedelta(days=90)


def test_control_status_preserves_unknown_future_values() -> None:
    status = ControlStatus.parse("partially_satisfied")
    assert status.value == "partially_satisfied"
    assert status.is_known is False


def test_control_status_never_rewrites_on_parse() -> None:
    raw = "requires_human_evidence"
    assert ControlStatus.parse(raw).value == raw


def test_confirmed_evidence_link_rejects_empty_evidence_id() -> None:
    with pytest.raises(ValueError, match="evidence_id"):
        ConfirmedEvidenceLink(
            evidence_id=" ",
            confirmed_by=_ACTOR,
            confirmed_at=datetime.now(UTC),
        )


def test_profile_activate_requires_frameworks() -> None:
    profile = ComplianceProfile.create(
        organization_id=_ORG,
        name="Empty",
        created_by=_ACTOR,
    )
    with pytest.raises(ControlAssessmentInvariantError, match="framework_keys"):
        profile.activate(activated_by=_ACTOR)


def test_profile_activate_emits_event() -> None:
    profile = ComplianceProfile.create(
        organization_id=_ORG,
        name="SOC Program",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_ACTOR,
    )
    profile.activate(activated_by=_ACTOR)
    assert profile.status is ProfileStatus.ACTIVE
    events = profile.collect_events()
    assert any(isinstance(e, ComplianceProfileActivated) for e in events)


def test_profile_rejects_forbidden_name() -> None:
    with pytest.raises(ControlAssessmentInvariantError, match="Forbidden"):
        ComplianceProfile.create(
            organization_id=_ORG,
            name="CERTIFIED",
            framework_keys=(FrameworkKey.SOC2,),
            created_by=_ACTOR,
        )


def test_period_open_close_lifecycle() -> None:
    start, end = _period_window()
    profile_id = EntityId.generate()
    period = AssessmentPeriod.create(
        organization_id=_ORG,
        profile_id=profile_id,
        name="FY26-H1",
        framework_key=FrameworkKey.SOC2,
        period_start=start,
        period_end=end,
        created_by=_ACTOR,
    )
    assert period.status is AssessmentPeriodStatus.PLANNED
    period.open(opened_by=_ACTOR)
    assert period.status is AssessmentPeriodStatus.OPEN
    period.close(closed_by=_ACTOR, assessments=())
    assert period.status is AssessmentPeriodStatus.CLOSED
    with pytest.raises(AssessmentPeriodNotOpenError):
        period.open(opened_by=_ACTOR)


def test_period_close_blocked_when_assessment_incomplete() -> None:
    from redforge.domain.compliance.exceptions import AssessmentPeriodCloseBlockedError

    start, end = _period_window()
    profile_id = EntityId.generate()
    period = AssessmentPeriod.create(
        organization_id=_ORG,
        profile_id=profile_id,
        name="FY26-blocked",
        framework_key=FrameworkKey.SOC2,
        period_start=start,
        period_end=end,
        created_by=_ACTOR,
    )
    period.open(opened_by=_ACTOR)
    assessment = ControlAssessment.create(
        organization_id=_ORG,
        profile_id=profile_id,
        period_id=period.id,
        requirement_id=EntityId.generate(),
        framework_key=FrameworkKey.SOC2,
        created_by=_ACTOR,
    )
    with pytest.raises(AssessmentPeriodCloseBlockedError):
        period.close(closed_by=_ACTOR, assessments=[assessment])


def test_period_close_allowed_when_all_technically_validated() -> None:
    start, end = _period_window()
    profile_id = EntityId.generate()
    period = AssessmentPeriod.create(
        organization_id=_ORG,
        profile_id=profile_id,
        name="FY26-ok",
        framework_key=FrameworkKey.SOC2,
        period_start=start,
        period_end=end,
        created_by=_ACTOR,
    )
    period.open(opened_by=_ACTOR)
    assessment = ControlAssessment.create(
        organization_id=_ORG,
        profile_id=profile_id,
        period_id=period.id,
        requirement_id=EntityId.generate(),
        framework_key=FrameworkKey.SOC2,
        created_by=_ACTOR,
    )
    assessment.confirm_evidence_link(evidence_id=_EVIDENCE, confirmed_by=_ACTOR)
    assessment.submit_for_confirmation(actor_id=_ACTOR)
    assessment.technically_validate(actor_id=_ACTOR)
    period.close(closed_by=_ACTOR, assessments=[assessment])
    assert period.status is AssessmentPeriodStatus.CLOSED


def test_activate_blocked_when_framework_already_claimed() -> None:
    from redforge.domain.compliance.exceptions import DuplicateActiveProfileFrameworkError

    first = ComplianceProfile.create(
        organization_id=_ORG,
        name="First",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_ACTOR,
    )
    first.activate(activated_by=_ACTOR, other_active_profiles=())
    second = ComplianceProfile.create(
        organization_id=_ORG,
        name="Second",
        framework_keys=(FrameworkKey.SOC2, FrameworkKey.ISO27001),
        created_by=_ACTOR,
    )
    with pytest.raises(DuplicateActiveProfileFrameworkError):
        second.activate(activated_by=_ACTOR, other_active_profiles=[first])


def test_control_assessment_lifecycle_with_evidence() -> None:
    profile_id = EntityId.generate()
    period_id = EntityId.generate()
    requirement_id = EntityId.generate()
    assessment = ControlAssessment.create(
        organization_id=_ORG,
        profile_id=profile_id,
        period_id=period_id,
        requirement_id=requirement_id,
        framework_key=FrameworkKey.SOC2,
        created_by=_ACTOR,
    )
    assert assessment.status.value == ControlStatusCode.NOT_ASSESSED
    assessment.confirm_evidence_link(evidence_id=_EVIDENCE, confirmed_by=_ACTOR)
    assert assessment.status.value == ControlStatusCode.COLLECTING_EVIDENCE
    assessment.submit_for_confirmation(actor_id=_ACTOR)
    assert assessment.status.value == ControlStatusCode.PENDING_CONFIRMATION
    assessment.technically_validate(actor_id=_ACTOR)
    assert assessment.status.value == ControlStatusCode.TECHNICALLY_VALIDATED
    events = assessment.collect_events()
    assert any(isinstance(e, ControlEvidenceLinkConfirmed) for e in events)
    assert any(isinstance(e, ControlStatusChanged) for e in events)


def test_duplicate_evidence_link_rejected() -> None:
    assessment = ControlAssessment.create(
        organization_id=_ORG,
        profile_id=EntityId.generate(),
        period_id=EntityId.generate(),
        requirement_id=EntityId.generate(),
        framework_key=FrameworkKey.SOC2,
        created_by=_ACTOR,
    )
    assessment.confirm_evidence_link(evidence_id=_EVIDENCE, confirmed_by=_ACTOR)
    with pytest.raises(DuplicateEvidenceLinkError):
        assessment.confirm_evidence_link(evidence_id=_EVIDENCE, confirmed_by=_ACTOR)


def test_cannot_validate_without_evidence() -> None:
    assessment = ControlAssessment.create(
        organization_id=_ORG,
        profile_id=EntityId.generate(),
        period_id=EntityId.generate(),
        requirement_id=EntityId.generate(),
        framework_key=FrameworkKey.ISO27001,
        created_by=_ACTOR,
    )
    assessment.begin_evidence_collection(actor_id=_ACTOR)
    with pytest.raises(InvalidControlStatusTransitionError, match="ConfirmedEvidenceLink"):
        assessment.submit_for_confirmation(actor_id=_ACTOR)


def test_unknown_status_cannot_be_transitioned() -> None:
    assessment = ControlAssessment.reconstitute(
        {
            "id": str(EntityId.generate()),
            "organization_id": _ORG,
            "profile_id": str(EntityId.generate()),
            "period_id": str(EntityId.generate()),
            "requirement_id": str(EntityId.generate()),
            "framework_key": FrameworkKey.SOC2.value,
            "status": "partially_satisfied",
            "evidence_links": [],
            "notes": "",
            "created_by": _ACTOR,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
    )
    assert assessment.status.value == "partially_satisfied"
    with pytest.raises(InvalidControlStatusTransitionError, match="unknown"):
        assessment.begin_evidence_collection(actor_id=_ACTOR)


def test_evaluator_rejects_skips() -> None:
    evaluator = ControlStatusEvaluator()
    with pytest.raises(InvalidControlStatusTransitionError):
        evaluator.evaluate_transition(
            ControlStatus.not_assessed(),
            ControlStatus.technically_validated(),
            evidence_count=1,
        )


def test_archived_profile_immutable() -> None:
    profile = ComplianceProfile.create(
        organization_id=_ORG,
        name="Archive Me",
        framework_keys=(FrameworkKey.CIS,),
        created_by=_ACTOR,
    )
    profile.activate(activated_by=_ACTOR)
    profile.archive()
    with pytest.raises(ProfileNotActiveError):
        profile.replace_framework_keys((FrameworkKey.SOC2,))


def test_period_end_must_follow_start() -> None:
    start, _ = _period_window()
    with pytest.raises(ControlAssessmentInvariantError, match="period_end"):
        AssessmentPeriod.create(
            organization_id=_ORG,
            profile_id=EntityId.generate(),
            name="Bad",
            framework_key=FrameworkKey.SOC2,
            period_start=start,
            period_end=start,
            created_by=_ACTOR,
        )
