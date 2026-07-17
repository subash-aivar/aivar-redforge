"""Application service tests for Organization Assessment (mocked repos)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from redforge.application.compliance.assessment_dtos import (
    ActivateProfileCommand,
    ConfirmEvidenceLinkCommand,
    CreatePeriodCommand,
    CreateProfileCommand,
)
from redforge.application.compliance.assessment_service import OrganizationAssessmentService
from redforge.domain.compliance.assessment import (
    AssessmentPeriod,
    ComplianceProfile,
    ControlAssessment,
)
from redforge.domain.compliance.entity import FrameworkDefinition
from redforge.domain.compliance.exceptions import (
    EvidenceReferenceNotFoundError,
    FrameworkNotFoundError,
    ProfileNotActiveError,
)
from redforge.domain.compliance.value_objects import (
    FrameworkKey,
    FrameworkMetadata,
    FrameworkStatus,
    ProfileStatus,
)
from redforge.shared.identifiers import EntityId

_ORG = "01ORG00000000000000000001"
_ACTOR = "01USER000000000000000001"


def _meta() -> FrameworkMetadata:
    return FrameworkMetadata(
        name="SOC 2",
        version="2017",
        issuing_body="AICPA",
        description="test",
        effective_date="2017-01-01",
        tags=("test",),
        external_url="",
    )


def _published_framework(key: FrameworkKey = FrameworkKey.SOC2) -> FrameworkDefinition:
    fw = FrameworkDefinition(
        id=EntityId.generate(),
        key=key,
        status=FrameworkStatus.PUBLISHED,
        metadata=_meta(),
        requirements={},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    return fw


@pytest.fixture
def service() -> OrganizationAssessmentService:
    factory = MagicMock()
    return OrganizationAssessmentService(factory)


@pytest.mark.asyncio
async def test_create_profile_rejects_unpublished_framework(
    service: OrganizationAssessmentService,
) -> None:
    session = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=None)
    begin_cm = MagicMock()
    begin_cm.__aenter__ = AsyncMock(return_value=None)
    begin_cm.__aexit__ = AsyncMock(return_value=None)
    session.begin = MagicMock(return_value=begin_cm)
    service._session_factory = MagicMock(return_value=cm)

    catalog = AsyncMock()
    catalog.get_framework = AsyncMock(return_value=None)
    service._catalog_repo = MagicMock(return_value=catalog)  # type: ignore[method-assign]

    with pytest.raises(FrameworkNotFoundError):
        await service.create_profile(
            CreateProfileCommand(
                organization_id=_ORG,
                name="P",
                description="",
                framework_keys=(FrameworkKey.SOC2,),
                created_by=_ACTOR,
            )
        )


@pytest.mark.asyncio
async def test_create_period_requires_active_profile(
    service: OrganizationAssessmentService,
) -> None:
    session = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=None)
    begin_cm = MagicMock()
    begin_cm.__aenter__ = AsyncMock(return_value=None)
    begin_cm.__aexit__ = AsyncMock(return_value=None)
    session.begin = MagicMock(return_value=begin_cm)
    service._session_factory = MagicMock(return_value=cm)

    profile = ComplianceProfile.create(
        organization_id=_ORG,
        name="Draft",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_ACTOR,
    )
    assert profile.status is ProfileStatus.DRAFT

    repo = AsyncMock()
    repo.get_profile = AsyncMock(return_value=profile)
    service._assessment_repo = MagicMock(return_value=repo)  # type: ignore[method-assign]

    start = datetime.now(UTC)
    with pytest.raises(ProfileNotActiveError):
        await service.create_period(
            CreatePeriodCommand(
                organization_id=_ORG,
                profile_id=profile.id,
                name="P1",
                framework_key=FrameworkKey.SOC2,
                period_start=start,
                period_end=start + timedelta(days=30),
                created_by=_ACTOR,
            )
        )


@pytest.mark.asyncio
async def test_confirm_evidence_requires_in_tenant_evidence(
    service: OrganizationAssessmentService,
) -> None:
    session = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=None)
    begin_cm = MagicMock()
    begin_cm.__aenter__ = AsyncMock(return_value=None)
    begin_cm.__aexit__ = AsyncMock(return_value=None)
    session.begin = MagicMock(return_value=begin_cm)
    service._session_factory = MagicMock(return_value=cm)

    profile_id = EntityId.generate()
    period = AssessmentPeriod.create(
        organization_id=_ORG,
        profile_id=profile_id,
        name="Open",
        framework_key=FrameworkKey.SOC2,
        period_start=datetime.now(UTC),
        period_end=datetime.now(UTC) + timedelta(days=10),
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

    repo = AsyncMock()
    repo.get_assessment = AsyncMock(return_value=assessment)
    repo.get_period = AsyncMock(return_value=period)
    service._assessment_repo = MagicMock(return_value=repo)  # type: ignore[method-assign]

    evidence_repo = AsyncMock()
    evidence_repo.get_by_id_for_organization = AsyncMock(return_value=None)
    service._evidence_repo = MagicMock(return_value=evidence_repo)  # type: ignore[method-assign]

    with pytest.raises(EvidenceReferenceNotFoundError):
        await service.confirm_evidence_link(
            ConfirmEvidenceLinkCommand(
                organization_id=_ORG,
                assessment_id=assessment.id,
                evidence_id="01EVIDENCE00000000000001",
                confirmed_by=_ACTOR,
            )
        )


@pytest.mark.asyncio
async def test_activate_profile_happy_path(
    service: OrganizationAssessmentService,
) -> None:
    session = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=None)
    begin_cm = MagicMock()
    begin_cm.__aenter__ = AsyncMock(return_value=None)
    begin_cm.__aexit__ = AsyncMock(return_value=None)
    session.begin = MagicMock(return_value=begin_cm)
    service._session_factory = MagicMock(return_value=cm)

    profile = ComplianceProfile.create(
        organization_id=_ORG,
        name="Ready",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_ACTOR,
    )
    repo = AsyncMock()
    repo.get_profile = AsyncMock(return_value=profile)
    repo.list_active_profiles = AsyncMock(return_value=[])
    repo.save_profile = AsyncMock()
    repo.replace_active_framework_claims = AsyncMock()
    service._assessment_repo = MagicMock(return_value=repo)  # type: ignore[method-assign]

    result = await service.activate_profile(
        ActivateProfileCommand(
            organization_id=_ORG,
            profile_id=profile.id,
            activated_by=_ACTOR,
        )
    )
    assert result.status is ProfileStatus.ACTIVE
    repo.save_profile.assert_awaited()
    repo.replace_active_framework_claims.assert_awaited()


@pytest.mark.asyncio
async def test_close_period_loads_assessments_and_enforces_invariant(
    service: OrganizationAssessmentService,
) -> None:
    from redforge.application.compliance.assessment_dtos import ClosePeriodCommand
    from redforge.domain.compliance.exceptions import AssessmentPeriodCloseBlockedError

    session = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=None)
    begin_cm = MagicMock()
    begin_cm.__aenter__ = AsyncMock(return_value=None)
    begin_cm.__aexit__ = AsyncMock(return_value=None)
    session.begin = MagicMock(return_value=begin_cm)
    service._session_factory = MagicMock(return_value=cm)

    profile_id = EntityId.generate()
    period = AssessmentPeriod.create(
        organization_id=_ORG,
        profile_id=profile_id,
        name="Open",
        framework_key=FrameworkKey.SOC2,
        period_start=datetime.now(UTC),
        period_end=datetime.now(UTC) + timedelta(days=10),
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
    repo = AsyncMock()
    repo.get_period = AsyncMock(return_value=period)
    repo.list_assessments = AsyncMock(return_value=[assessment])
    service._assessment_repo = MagicMock(return_value=repo)  # type: ignore[method-assign]

    with pytest.raises(AssessmentPeriodCloseBlockedError):
        await service.close_period(
            ClosePeriodCommand(
                organization_id=_ORG,
                period_id=period.id,
                closed_by=_ACTOR,
            )
        )


@pytest.mark.asyncio
async def test_activate_rejects_overlapping_active_framework(
    service: OrganizationAssessmentService,
) -> None:
    from redforge.domain.compliance.exceptions import DuplicateActiveProfileFrameworkError

    session = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=None)
    begin_cm = MagicMock()
    begin_cm.__aenter__ = AsyncMock(return_value=None)
    begin_cm.__aexit__ = AsyncMock(return_value=None)
    session.begin = MagicMock(return_value=begin_cm)
    service._session_factory = MagicMock(return_value=cm)

    existing = ComplianceProfile.create(
        organization_id=_ORG,
        name="Existing",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_ACTOR,
    )
    existing.activate(activated_by=_ACTOR, other_active_profiles=())
    candidate = ComplianceProfile.create(
        organization_id=_ORG,
        name="Candidate",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_ACTOR,
    )
    repo = AsyncMock()
    repo.get_profile = AsyncMock(return_value=candidate)
    repo.list_active_profiles = AsyncMock(return_value=[existing])
    service._assessment_repo = MagicMock(return_value=repo)  # type: ignore[method-assign]

    with pytest.raises(DuplicateActiveProfileFrameworkError):
        await service.activate_profile(
            ActivateProfileCommand(
                organization_id=_ORG,
                profile_id=candidate.id,
                activated_by=_ACTOR,
            )
        )
