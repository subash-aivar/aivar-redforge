"""PostgreSQL repository proofs for M24 Phase 2 Organization Assessment."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.domain.compliance.assessment import (
    AssessmentPeriod,
    ComplianceProfile,
    ControlAssessment,
)
from redforge.domain.compliance.value_objects import (
    ControlStatus,
    ControlStatusCode,
    FrameworkKey,
    ProfileStatus,
)
from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
    SqlAlchemyOrganizationAssessmentRepository,
)
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio(loop_scope="module")

_DB_NAME = "redforge_m24_assessment_proof"
_DB_URL = os.environ.get(
    "REDFORGE_M24_ASSESSMENT_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_DB_NAME}",
)

_ORG = "01ORG00000000000000000001"
_ACTOR = "01USER000000000000000001"


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


class TestOrganizationAssessmentPersistence:
    async def test_migration_head_is_0042(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(text("SELECT version_num FROM alembic_version"))
            # Phase 2 DB may remain at 0042; later heads are also acceptable.
            assert result.scalar_one() in {"0042", "0043"}

    async def test_profile_period_assessment_round_trip(self, session_factory) -> None:
        profile = ComplianceProfile.create(
            organization_id=_ORG,
            name=f"Program-{EntityId.generate()}",
            framework_keys=(FrameworkKey.SOC2, FrameworkKey.ISO27001),
            created_by=_ACTOR,
        )
        profile.activate(activated_by=_ACTOR)
        start = datetime.now(UTC)
        period = AssessmentPeriod.create(
            organization_id=_ORG,
            profile_id=profile.id,
            name=f"Period-{EntityId.generate()}",
            framework_key=FrameworkKey.SOC2,
            period_start=start,
            period_end=start + timedelta(days=30),
            created_by=_ACTOR,
        )
        period.open(opened_by=_ACTOR)
        assessment = ControlAssessment.create(
            organization_id=_ORG,
            profile_id=profile.id,
            period_id=period.id,
            requirement_id=EntityId.generate(),
            framework_key=FrameworkKey.SOC2,
            created_by=_ACTOR,
        )
        assessment.confirm_evidence_link(
            evidence_id="01EVIDENCE00000000000001",
            confirmed_by=_ACTOR,
            rationale="manual confirmation",
        )

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyOrganizationAssessmentRepository(session)
            await repo.save_profile(profile)
            await repo.save_period(period)
            await repo.save_assessment(assessment)

        async with session_factory() as session:
            repo = SqlAlchemyOrganizationAssessmentRepository(session)
            loaded_profile = await repo.get_profile(_ORG, profile.id)
            loaded_period = await repo.get_period(_ORG, period.id)
            loaded_assessment = await repo.get_assessment(_ORG, assessment.id)

        assert loaded_profile is not None
        assert loaded_profile.status is ProfileStatus.ACTIVE
        assert FrameworkKey.SOC2 in loaded_profile.framework_keys
        assert loaded_period is not None
        assert loaded_period.status.value == "open"
        assert loaded_assessment is not None
        assert loaded_assessment.status.value == ControlStatusCode.COLLECTING_EVIDENCE
        assert len(loaded_assessment.evidence_links) == 1
        assert loaded_assessment.evidence_links[0].evidence_id == "01EVIDENCE00000000000001"

    async def test_active_framework_claim_blocks_second_profile(
        self, session_factory
    ) -> None:
        from sqlalchemy.exc import IntegrityError

        from redforge.domain.compliance.exceptions import (
            DuplicateActiveProfileFrameworkError,
        )

        org = str(EntityId.generate())
        first = ComplianceProfile.create(
            organization_id=org,
            name=f"Claim-A-{EntityId.generate()}",
            framework_keys=(FrameworkKey.SOC2,),
            created_by=_ACTOR,
        )
        first.activate(activated_by=_ACTOR, other_active_profiles=())
        second = ComplianceProfile.create(
            organization_id=org,
            name=f"Claim-B-{EntityId.generate()}",
            framework_keys=(FrameworkKey.SOC2,),
            created_by=_ACTOR,
        )

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyOrganizationAssessmentRepository(session)
            await repo.save_profile(first)
            await repo.replace_active_framework_claims(
                organization_id=org,
                profile_id=first.id,
                framework_keys=first.framework_keys,
            )
            await repo.save_profile(second)

        # Domain rejects before DB
        with pytest.raises(DuplicateActiveProfileFrameworkError):
            second.activate(activated_by=_ACTOR, other_active_profiles=[first])

        # DB uniqueness also rejects concurrent claim insert
        with pytest.raises(IntegrityError):
            async with session_factory() as session, session.begin():
                repo = SqlAlchemyOrganizationAssessmentRepository(session)
                await repo.replace_active_framework_claims(
                    organization_id=org,
                    profile_id=second.id,
                    framework_keys=second.framework_keys,
                )

    async def test_period_close_requires_technically_validated_assessments(
        self, session_factory
    ) -> None:
        from redforge.domain.compliance.exceptions import (
            AssessmentPeriodCloseBlockedError,
        )

        org = str(EntityId.generate())
        profile = ComplianceProfile.create(
            organization_id=org,
            name=f"Close-{EntityId.generate()}",
            framework_keys=(FrameworkKey.NIST_CSF,),
            created_by=_ACTOR,
        )
        profile.activate(activated_by=_ACTOR, other_active_profiles=())
        start = datetime.now(UTC)
        period = AssessmentPeriod.create(
            organization_id=org,
            profile_id=profile.id,
            name=f"ClosePeriod-{EntityId.generate()}",
            framework_key=FrameworkKey.NIST_CSF,
            period_start=start,
            period_end=start + timedelta(days=14),
            created_by=_ACTOR,
        )
        period.open(opened_by=_ACTOR)
        assessment = ControlAssessment.create(
            organization_id=org,
            profile_id=profile.id,
            period_id=period.id,
            requirement_id=EntityId.generate(),
            framework_key=FrameworkKey.NIST_CSF,
            created_by=_ACTOR,
        )

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyOrganizationAssessmentRepository(session)
            await repo.save_profile(profile)
            await repo.replace_active_framework_claims(
                organization_id=org,
                profile_id=profile.id,
                framework_keys=profile.framework_keys,
            )
            await repo.save_period(period)
            await repo.save_assessment(assessment)

        async with session_factory() as session:
            repo = SqlAlchemyOrganizationAssessmentRepository(session)
            loaded_period = await repo.get_period(org, period.id)
            loaded_assessments = await repo.list_assessments(org, period_id=period.id)
            assert loaded_period is not None
            with pytest.raises(AssessmentPeriodCloseBlockedError):
                loaded_period.close(
                    closed_by=_ACTOR, assessments=loaded_assessments
                )

    async def test_unknown_status_preserved_verbatim(self, session_factory) -> None:
        """Forward-compatible: future statuses must not be rewritten."""
        profile = ComplianceProfile.create(
            organization_id=_ORG,
            name=f"Future-{EntityId.generate()}",
            framework_keys=(FrameworkKey.CIS,),
            created_by=_ACTOR,
        )
        profile.activate(activated_by=_ACTOR)
        start = datetime.now(UTC)
        period = AssessmentPeriod.create(
            organization_id=_ORG,
            profile_id=profile.id,
            name=f"FuturePeriod-{EntityId.generate()}",
            framework_key=FrameworkKey.CIS,
            period_start=start,
            period_end=start + timedelta(days=7),
            created_by=_ACTOR,
        )
        period.open(opened_by=_ACTOR)
        assessment = ControlAssessment.create(
            organization_id=_ORG,
            profile_id=profile.id,
            period_id=period.id,
            requirement_id=EntityId.generate(),
            framework_key=FrameworkKey.CIS,
            created_by=_ACTOR,
        )
        # Simulate a future-phase status written by a newer binary.
        assessment.status = ControlStatus.parse("partially_satisfied")

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyOrganizationAssessmentRepository(session)
            await repo.save_profile(profile)
            await repo.save_period(period)
            await repo.save_assessment(assessment)

        async with session_factory() as session:
            repo = SqlAlchemyOrganizationAssessmentRepository(session)
            loaded = await repo.get_assessment(_ORG, assessment.id)

        assert loaded is not None
        assert loaded.status.value == "partially_satisfied"
        assert loaded.status.is_known is False
