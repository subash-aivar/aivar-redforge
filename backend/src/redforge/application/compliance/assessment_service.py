"""Organization Assessment application services — M24 Phase 2.

No AutoLinkingEngine, workers, review queue, or analytics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError

from redforge.domain.compliance.assessment import (
    AssessmentPeriod,
    ComplianceProfile,
    ControlAssessment,
)
from redforge.domain.compliance.exceptions import (
    AssessmentPeriodNotFoundError,
    ControlAssessmentNotFoundError,
    ControlRequirementNotFoundError,
    DuplicateActiveProfileFrameworkError,
    DuplicateControlAssessmentError,
    EvidenceReferenceNotFoundError,
    FrameworkNotFoundError,
    FrameworkNotInProfileError,
    ProfileNotFoundError,
)
from redforge.domain.compliance.value_objects import FrameworkStatus, ProfileStatus
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.compliance.assessment_dtos import (
        ActivateProfileCommand,
        ClosePeriodCommand,
        ConfirmEvidenceLinkCommand,
        CreateAssessmentCommand,
        CreatePeriodCommand,
        CreateProfileCommand,
        OpenPeriodCommand,
        TransitionAssessmentCommand,
        UpdateProfileFrameworksCommand,
    )
    from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
        SqlAlchemyOrganizationAssessmentRepository,
    )
    from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
        SqlAlchemyControlCatalogRepository,
    )
    from redforge.infrastructure.database.repositories.evidence.repository import (
        SqlAlchemyEvidenceRepository,
    )


class OrganizationAssessmentService:
    """Orchestrates ComplianceProfile / AssessmentPeriod / ControlAssessment."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    def _assessment_repo(
        self, session: AsyncSession
    ) -> SqlAlchemyOrganizationAssessmentRepository:
        from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
            SqlAlchemyOrganizationAssessmentRepository as Repo,
        )

        return Repo(session)

    def _catalog_repo(self, session: AsyncSession) -> SqlAlchemyControlCatalogRepository:
        from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
            SqlAlchemyControlCatalogRepository as Repo,
        )

        return Repo(session)

    def _evidence_repo(self, session: AsyncSession) -> SqlAlchemyEvidenceRepository:
        from redforge.infrastructure.database.repositories.evidence.repository import (
            SqlAlchemyEvidenceRepository as Repo,
        )

        return Repo(session)

    async def create_profile(self, command: CreateProfileCommand) -> ComplianceProfile:
        async with self._session_factory() as session, session.begin():
            catalog = self._catalog_repo(session)
            for key in command.framework_keys:
                framework = await catalog.get_framework(key)
                if framework is None or framework.status != FrameworkStatus.PUBLISHED:
                    raise FrameworkNotFoundError(key.value)
            profile = ComplianceProfile.create(
                organization_id=command.organization_id,
                name=command.name,
                description=command.description,
                framework_keys=command.framework_keys,
                created_by=command.created_by,
            )
            await self._assessment_repo(session).save_profile(profile)
            profile.collect_events()
            return profile

    async def update_profile_frameworks(
        self, command: UpdateProfileFrameworksCommand
    ) -> ComplianceProfile:
        async with self._session_factory() as session, session.begin():
            repo = self._assessment_repo(session)
            profile = await repo.get_profile(command.organization_id, command.profile_id)
            if profile is None:
                raise ProfileNotFoundError(str(command.profile_id))
            catalog = self._catalog_repo(session)
            for key in command.framework_keys:
                framework = await catalog.get_framework(key)
                if framework is None or framework.status != FrameworkStatus.PUBLISHED:
                    raise FrameworkNotFoundError(key.value)
            others = await repo.list_active_profiles(
                command.organization_id, exclude_profile_id=command.profile_id
            )
            profile.replace_framework_keys(
                command.framework_keys, other_active_profiles=others
            )
            await repo.save_profile(profile)
            if profile.status is ProfileStatus.ACTIVE:
                try:
                    await repo.replace_active_framework_claims(
                        organization_id=command.organization_id,
                        profile_id=profile.id,
                        framework_keys=profile.framework_keys,
                    )
                except IntegrityError as exc:
                    framework_key_value = (
                        profile.framework_keys[0].value
                        if profile.framework_keys
                        else "unknown"
                    )
                    raise DuplicateActiveProfileFrameworkError(
                        command.organization_id,
                        framework_key_value,
                        "concurrent-claim",
                    ) from exc
            profile.collect_events()
            return profile

    async def activate_profile(
        self, command: ActivateProfileCommand
    ) -> ComplianceProfile:
        async with self._session_factory() as session, session.begin():
            repo = self._assessment_repo(session)
            profile = await repo.get_profile(command.organization_id, command.profile_id)
            if profile is None:
                raise ProfileNotFoundError(str(command.profile_id))
            others = await repo.list_active_profiles(
                command.organization_id, exclude_profile_id=command.profile_id
            )
            was_active = profile.status is ProfileStatus.ACTIVE
            profile.activate(
                activated_by=command.activated_by,
                other_active_profiles=others,
            )
            await repo.save_profile(profile)
            if not was_active and profile.status is ProfileStatus.ACTIVE:
                try:
                    await repo.replace_active_framework_claims(
                        organization_id=command.organization_id,
                        profile_id=profile.id,
                        framework_keys=profile.framework_keys,
                    )
                except IntegrityError as exc:
                    framework_key_value = (
                        profile.framework_keys[0].value
                        if profile.framework_keys
                        else "unknown"
                    )
                    raise DuplicateActiveProfileFrameworkError(
                        command.organization_id,
                        framework_key_value,
                        "concurrent-claim",
                    ) from exc
            profile.collect_events()
            return profile

    async def get_profile(
        self, organization_id: str, profile_id: EntityId
    ) -> ComplianceProfile:
        async with self._session_factory() as session:
            profile = await self._assessment_repo(session).get_profile(
                organization_id, profile_id
            )
            if profile is None:
                raise ProfileNotFoundError(str(profile_id))
            return profile

    async def list_profiles(self, organization_id: str) -> list[ComplianceProfile]:
        async with self._session_factory() as session:
            return await self._assessment_repo(session).list_profiles(organization_id)

    async def create_period(self, command: CreatePeriodCommand) -> AssessmentPeriod:
        async with self._session_factory() as session, session.begin():
            repo = self._assessment_repo(session)
            profile = await repo.get_profile(command.organization_id, command.profile_id)
            if profile is None:
                raise ProfileNotFoundError(str(command.profile_id))
            profile.assert_active()
            if command.framework_key not in profile.framework_keys:
                raise FrameworkNotInProfileError(
                    command.framework_key.value, str(profile.id)
                )
            catalog = self._catalog_repo(session)
            framework = await catalog.get_framework(command.framework_key)
            if framework is None or framework.status != FrameworkStatus.PUBLISHED:
                raise FrameworkNotFoundError(command.framework_key.value)
            period = AssessmentPeriod.create(
                organization_id=command.organization_id,
                profile_id=command.profile_id,
                name=command.name,
                framework_key=command.framework_key,
                period_start=command.period_start,
                period_end=command.period_end,
                created_by=command.created_by,
            )
            await repo.save_period(period)
            period.collect_events()
            return period

    async def open_period(self, command: OpenPeriodCommand) -> AssessmentPeriod:
        async with self._session_factory() as session, session.begin():
            repo = self._assessment_repo(session)
            period = await repo.get_period(command.organization_id, command.period_id)
            if period is None:
                raise AssessmentPeriodNotFoundError(str(command.period_id))
            profile = await repo.get_profile(command.organization_id, period.profile_id)
            if profile is None:
                raise ProfileNotFoundError(str(period.profile_id))
            profile.assert_active()
            period.open(opened_by=command.opened_by)
            await repo.save_period(period)
            period.collect_events()
            return period

    async def close_period(self, command: ClosePeriodCommand) -> AssessmentPeriod:
        async with self._session_factory() as session, session.begin():
            repo = self._assessment_repo(session)
            period = await repo.get_period(command.organization_id, command.period_id)
            if period is None:
                raise AssessmentPeriodNotFoundError(str(command.period_id))
            assessments = await repo.list_assessments(
                command.organization_id, period_id=period.id
            )
            period.close(closed_by=command.closed_by, assessments=assessments)
            await repo.save_period(period)
            period.collect_events()
            return period

    async def get_period(
        self, organization_id: str, period_id: EntityId
    ) -> AssessmentPeriod:
        async with self._session_factory() as session:
            period = await self._assessment_repo(session).get_period(
                organization_id, period_id
            )
            if period is None:
                raise AssessmentPeriodNotFoundError(str(period_id))
            return period

    async def list_periods(
        self, organization_id: str, *, profile_id: EntityId | None = None
    ) -> list[AssessmentPeriod]:
        async with self._session_factory() as session:
            return await self._assessment_repo(session).list_periods(
                organization_id, profile_id=profile_id
            )

    async def create_assessment(
        self, command: CreateAssessmentCommand
    ) -> ControlAssessment:
        async with self._session_factory() as session, session.begin():
            repo = self._assessment_repo(session)
            period = await repo.get_period(command.organization_id, command.period_id)
            if period is None:
                raise AssessmentPeriodNotFoundError(str(command.period_id))
            period.assert_open()
            existing = await repo.get_assessment_for_requirement(
                command.organization_id,
                command.period_id,
                command.requirement_id,
            )
            if existing is not None:
                raise DuplicateControlAssessmentError(
                    str(command.period_id), str(command.requirement_id)
                )
            requirement = await self._catalog_repo(session).get_requirement(
                command.requirement_id
            )
            if requirement is None:
                raise ControlRequirementNotFoundError(str(command.requirement_id))
            if requirement.framework_key != period.framework_key:
                raise ControlRequirementNotFoundError(str(command.requirement_id))
            assessment = ControlAssessment.create(
                organization_id=command.organization_id,
                profile_id=period.profile_id,
                period_id=period.id,
                requirement_id=command.requirement_id,
                framework_key=period.framework_key,
                created_by=command.created_by,
                notes=command.notes,
            )
            await repo.save_assessment(assessment)
            assessment.collect_events()
            return assessment

    async def confirm_evidence_link(
        self, command: ConfirmEvidenceLinkCommand
    ) -> ControlAssessment:
        async with self._session_factory() as session, session.begin():
            repo = self._assessment_repo(session)
            assessment = await repo.get_assessment(
                command.organization_id, command.assessment_id
            )
            if assessment is None:
                raise ControlAssessmentNotFoundError(str(command.assessment_id))
            period = await repo.get_period(
                command.organization_id, assessment.period_id
            )
            if period is None:
                raise AssessmentPeriodNotFoundError(str(assessment.period_id))
            period.assert_open()

            evidence = await self._evidence_repo(session).get_by_id_for_organization(
                command.evidence_id, command.organization_id
            )
            if evidence is None:
                raise EvidenceReferenceNotFoundError(command.evidence_id)

            assessment.confirm_evidence_link(
                evidence_id=command.evidence_id,
                confirmed_by=command.confirmed_by,
                rationale=command.rationale,
            )
            await repo.save_assessment(assessment)
            assessment.collect_events()
            return assessment

    async def begin_evidence_collection(
        self, command: TransitionAssessmentCommand
    ) -> ControlAssessment:
        return await self._transition(
            command, action=lambda a: a.begin_evidence_collection(actor_id=command.actor_id)
        )

    async def submit_for_confirmation(
        self, command: TransitionAssessmentCommand
    ) -> ControlAssessment:
        return await self._transition(
            command, action=lambda a: a.submit_for_confirmation(actor_id=command.actor_id)
        )

    async def technically_validate(
        self, command: TransitionAssessmentCommand
    ) -> ControlAssessment:
        return await self._transition(
            command, action=lambda a: a.technically_validate(actor_id=command.actor_id)
        )

    async def _transition(
        self,
        command: TransitionAssessmentCommand,
        *,
        action: Callable[[ControlAssessment], None],
    ) -> ControlAssessment:
        async with self._session_factory() as session, session.begin():
            repo = self._assessment_repo(session)
            assessment = await repo.get_assessment(
                command.organization_id, command.assessment_id
            )
            if assessment is None:
                raise ControlAssessmentNotFoundError(str(command.assessment_id))
            period = await repo.get_period(
                command.organization_id, assessment.period_id
            )
            if period is None:
                raise AssessmentPeriodNotFoundError(str(assessment.period_id))
            period.assert_open()
            action(assessment)
            await repo.save_assessment(assessment)
            assessment.collect_events()
            return assessment

    async def get_assessment(
        self, organization_id: str, assessment_id: EntityId
    ) -> ControlAssessment:
        async with self._session_factory() as session:
            assessment = await self._assessment_repo(session).get_assessment(
                organization_id, assessment_id
            )
            if assessment is None:
                raise ControlAssessmentNotFoundError(str(assessment_id))
            return assessment

    async def list_assessments(
        self, organization_id: str, *, period_id: EntityId
    ) -> list[ControlAssessment]:
        async with self._session_factory() as session:
            return await self._assessment_repo(session).list_assessments(
                organization_id, period_id=period_id
            )
