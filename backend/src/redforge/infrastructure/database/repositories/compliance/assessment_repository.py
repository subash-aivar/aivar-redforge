"""SQLAlchemy repository for Organization Assessment aggregates (M24 Phase 2)."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.domain.compliance.assessment import (
    AssessmentPeriod,
    ComplianceProfile,
    ControlAssessment,
)
from redforge.domain.compliance.value_objects import FrameworkKey, ProfileStatus
from redforge.infrastructure.database.models.compliance import (
    AssessmentPeriodModel,
    ComplianceActiveFrameworkClaimModel,
    ComplianceProfileModel,
    ControlAssessmentModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _serialize_link(link: Any) -> dict[str, Any]:
    return {
        "evidence_id": link.evidence_id,
        "confirmed_by": link.confirmed_by,
        "confirmed_at": link.confirmed_at.isoformat(),
        "rationale": link.rationale,
    }


def _deserialize_links(raw: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not raw:
        return []
    result: list[dict[str, Any]] = []
    for item in raw:
        confirmed_at = item["confirmed_at"]
        if isinstance(confirmed_at, str):
            confirmed_at = datetime.fromisoformat(confirmed_at)
        result.append(
            {
                "evidence_id": item["evidence_id"],
                "confirmed_by": item["confirmed_by"],
                "confirmed_at": confirmed_at,
                "rationale": item.get("rationale", ""),
            }
        )
    return result


class SqlAlchemyOrganizationAssessmentRepository:
    """Async SQLAlchemy implementation of OrganizationAssessmentRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_profile(self, profile: ComplianceProfile) -> None:
        existing = await self._session.scalar(
            select(ComplianceProfileModel).where(
                ComplianceProfileModel.id == str(profile.id),
                ComplianceProfileModel.organization_id == profile.organization_id,
            )
        )
        keys = [k.value for k in profile.framework_keys]
        if existing is None:
            self._session.add(
                ComplianceProfileModel(
                    id=str(profile.id),
                    organization_id=profile.organization_id,
                    name=profile.name,
                    description=profile.description,
                    framework_keys=keys,
                    status=profile.status.value,
                    created_by=profile.created_by,
                    created_at=profile.created_at,
                    updated_at=profile.updated_at,
                )
            )
        else:
            existing.name = profile.name
            existing.description = profile.description
            existing.framework_keys = keys
            existing.status = profile.status.value
            existing.updated_at = profile.updated_at

    async def get_profile(
        self, organization_id: str, profile_id: EntityId
    ) -> ComplianceProfile | None:
        row = await self._session.scalar(
            select(ComplianceProfileModel).where(
                ComplianceProfileModel.id == str(profile_id),
                ComplianceProfileModel.organization_id == organization_id,
            )
        )
        if row is None:
            return None
        return ComplianceProfile.reconstitute(
            {
                "id": row.id,
                "organization_id": row.organization_id,
                "name": row.name,
                "description": row.description,
                "framework_keys": list(row.framework_keys or []),
                "status": row.status,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )

    async def list_profiles(self, organization_id: str) -> list[ComplianceProfile]:
        rows = (
            await self._session.scalars(
                select(ComplianceProfileModel)
                .where(ComplianceProfileModel.organization_id == organization_id)
                .order_by(ComplianceProfileModel.created_at.desc())
            )
        ).all()
        return [
            ComplianceProfile.reconstitute(
                {
                    "id": row.id,
                    "organization_id": row.organization_id,
                    "name": row.name,
                    "description": row.description,
                    "framework_keys": list(row.framework_keys or []),
                    "status": row.status,
                    "created_by": row.created_by,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                }
            )
            for row in rows
        ]

    async def save_period(self, period: AssessmentPeriod) -> None:
        existing = await self._session.scalar(
            select(AssessmentPeriodModel).where(
                AssessmentPeriodModel.id == str(period.id),
                AssessmentPeriodModel.organization_id == period.organization_id,
            )
        )
        if existing is None:
            self._session.add(
                AssessmentPeriodModel(
                    id=str(period.id),
                    organization_id=period.organization_id,
                    profile_id=str(period.profile_id),
                    name=period.name,
                    framework_key=period.framework_key.value,
                    period_start=period.period_start,
                    period_end=period.period_end,
                    status=period.status.value,
                    created_by=period.created_by,
                    created_at=period.created_at,
                    updated_at=period.updated_at,
                )
            )
        else:
            existing.name = period.name
            existing.framework_key = period.framework_key.value
            existing.period_start = period.period_start
            existing.period_end = period.period_end
            existing.status = period.status.value
            existing.updated_at = period.updated_at

    async def get_period(
        self, organization_id: str, period_id: EntityId
    ) -> AssessmentPeriod | None:
        row = await self._session.scalar(
            select(AssessmentPeriodModel).where(
                AssessmentPeriodModel.id == str(period_id),
                AssessmentPeriodModel.organization_id == organization_id,
            )
        )
        if row is None:
            return None
        return AssessmentPeriod.reconstitute(
            {
                "id": row.id,
                "organization_id": row.organization_id,
                "profile_id": row.profile_id,
                "name": row.name,
                "framework_key": row.framework_key,
                "period_start": row.period_start,
                "period_end": row.period_end,
                "status": row.status,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )

    async def list_periods(
        self, organization_id: str, *, profile_id: EntityId | None = None
    ) -> list[AssessmentPeriod]:
        stmt = select(AssessmentPeriodModel).where(
            AssessmentPeriodModel.organization_id == organization_id
        )
        if profile_id is not None:
            stmt = stmt.where(AssessmentPeriodModel.profile_id == str(profile_id))
        stmt = stmt.order_by(AssessmentPeriodModel.period_start.desc())
        rows = (await self._session.scalars(stmt)).all()
        return [
            AssessmentPeriod.reconstitute(
                {
                    "id": row.id,
                    "organization_id": row.organization_id,
                    "profile_id": row.profile_id,
                    "name": row.name,
                    "framework_key": row.framework_key,
                    "period_start": row.period_start,
                    "period_end": row.period_end,
                    "status": row.status,
                    "created_by": row.created_by,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                }
            )
            for row in rows
        ]

    async def save_assessment(self, assessment: ControlAssessment) -> None:
        # Persist status.value verbatim — never rewrite unknown future states.
        payload = [_serialize_link(link) for link in assessment.evidence_links]
        existing = await self._session.scalar(
            select(ControlAssessmentModel).where(
                ControlAssessmentModel.id == str(assessment.id),
                ControlAssessmentModel.organization_id == assessment.organization_id,
            )
        )
        if existing is None:
            self._session.add(
                ControlAssessmentModel(
                    id=str(assessment.id),
                    organization_id=assessment.organization_id,
                    profile_id=str(assessment.profile_id),
                    period_id=str(assessment.period_id),
                    requirement_id=str(assessment.requirement_id),
                    framework_key=assessment.framework_key.value,
                    status=assessment.status.value,
                    evidence_links=payload,
                    notes=assessment.notes,
                    created_by=assessment.created_by,
                    created_at=assessment.created_at,
                    updated_at=assessment.updated_at,
                )
            )
        else:
            existing.status = assessment.status.value
            existing.evidence_links = payload
            existing.notes = assessment.notes
            existing.updated_at = assessment.updated_at

    async def get_assessment(
        self, organization_id: str, assessment_id: EntityId
    ) -> ControlAssessment | None:
        row = await self._session.scalar(
            select(ControlAssessmentModel).where(
                ControlAssessmentModel.id == str(assessment_id),
                ControlAssessmentModel.organization_id == organization_id,
            )
        )
        if row is None:
            return None
        return self._assessment_from_row(row)

    async def get_assessment_for_requirement(
        self,
        organization_id: str,
        period_id: EntityId,
        requirement_id: EntityId,
    ) -> ControlAssessment | None:
        row = await self._session.scalar(
            select(ControlAssessmentModel).where(
                ControlAssessmentModel.organization_id == organization_id,
                ControlAssessmentModel.period_id == str(period_id),
                ControlAssessmentModel.requirement_id == str(requirement_id),
            )
        )
        if row is None:
            return None
        return self._assessment_from_row(row)

    async def list_assessments(
        self, organization_id: str, *, period_id: EntityId
    ) -> list[ControlAssessment]:
        rows = (
            await self._session.scalars(
                select(ControlAssessmentModel)
                .where(
                    ControlAssessmentModel.organization_id == organization_id,
                    ControlAssessmentModel.period_id == str(period_id),
                )
                .order_by(ControlAssessmentModel.created_at.asc())
            )
        ).all()
        return [self._assessment_from_row(row) for row in rows]

    async def list_active_profiles(
        self, organization_id: str, *, exclude_profile_id: EntityId | None = None
    ) -> list[ComplianceProfile]:
        stmt = select(ComplianceProfileModel).where(
            ComplianceProfileModel.organization_id == organization_id,
            ComplianceProfileModel.status == ProfileStatus.ACTIVE.value,
        )
        if exclude_profile_id is not None:
            stmt = stmt.where(ComplianceProfileModel.id != str(exclude_profile_id))
        rows = (await self._session.scalars(stmt)).all()
        return [
            ComplianceProfile.reconstitute(
                {
                    "id": row.id,
                    "organization_id": row.organization_id,
                    "name": row.name,
                    "description": row.description,
                    "framework_keys": list(row.framework_keys or []),
                    "status": row.status,
                    "created_by": row.created_by,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                }
            )
            for row in rows
        ]

    async def replace_active_framework_claims(
        self,
        *,
        organization_id: str,
        profile_id: EntityId,
        framework_keys: tuple[FrameworkKey, ...],
    ) -> None:
        """Atomically replace this profile's active framework claims.

        Primary key on (organization_id, framework_key) provides concurrency
        safety against two activations racing for the same framework.
        """
        from datetime import UTC, datetime

        from sqlalchemy import delete

        await self._session.execute(
            delete(ComplianceActiveFrameworkClaimModel).where(
                ComplianceActiveFrameworkClaimModel.organization_id == organization_id,
                ComplianceActiveFrameworkClaimModel.profile_id == str(profile_id),
            )
        )
        now = datetime.now(UTC)
        for key in framework_keys:
            self._session.add(
                ComplianceActiveFrameworkClaimModel(
                    organization_id=organization_id,
                    framework_key=key.value,
                    profile_id=str(profile_id),
                    claimed_at=now,
                )
            )
        await self._session.flush()

    async def release_active_framework_claims(
        self, *, organization_id: str, profile_id: EntityId
    ) -> None:
        from sqlalchemy import delete

        await self._session.execute(
            delete(ComplianceActiveFrameworkClaimModel).where(
                ComplianceActiveFrameworkClaimModel.organization_id == organization_id,
                ComplianceActiveFrameworkClaimModel.profile_id == str(profile_id),
            )
        )

    def _assessment_from_row(self, row: ControlAssessmentModel) -> ControlAssessment:
        return ControlAssessment.reconstitute(
            {
                "id": row.id,
                "organization_id": row.organization_id,
                "profile_id": row.profile_id,
                "period_id": row.period_id,
                "requirement_id": row.requirement_id,
                "framework_key": row.framework_key,
                "status": row.status,
                "evidence_links": _deserialize_links(list(row.evidence_links or [])),
                "notes": row.notes,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )
