"""PostgreSQL repositories for lessons_learned.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across the other converted bounded contexts. Neither repository has a
domain ABC (domain/repositories/ is empty in this context) — these are
structurally compatible with the in-memory repos they replace, same as the
convention already in place here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import delete, select

from lessons_learned.domain.aggregates.lessons_learned import (
    ImprovementAction,
    LessonItem,
    LessonsLearned,
    Recommendation,
)
from lessons_learned.domain.aggregates.post_incident_report import PostIncidentReport
from lessons_learned.domain.value_objects.enums import (
    ActionItemPriority,
    ActionItemStatus,
    LessonCategory,
    LLStatus,
    PostIncidentReportStatus,
    ReportFormat,
)
from lessons_learned.domain.value_objects.identifiers import (
    LessonsLearnedId,
    PostIncidentReportId,
    TenantId,
)
from lessons_learned.infrastructure.persistence.models.orm_models import (
    ActionItemModel,
    LessonItemModel,
    LessonsLearnedRecordModel,
    PostIncidentReportModel,
    RecommendationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


# ── LessonsLearned ───────────────────────────────────────────────────────────


def _ll_to_row(ll: LessonsLearned) -> LessonsLearnedRecordModel:
    return LessonsLearnedRecordModel(
        ll_id=ll.ll_id.value,
        tenant_id=ll.tenant_id.value,
        incident_id=UUID(ll.incident_id),
        status=ll.status.value,
        reviewed_by=ll.reviewed_by,
        reviewed_at=ll.reviewed_at,
        finalized_by=ll.finalized_by,
        finalized_at=ll.finalized_at,
        campaign_retargeting_suggestion_ref=ll.campaign_retargeting_suggestion_ref,
        confirmed_technique_ids=list(ll.confirmed_technique_ids),
        created_at=ll.created_at,
    )


class PgLessonsLearnedRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _load(self, session: AsyncSession, row: LessonsLearnedRecordModel) -> LessonsLearned:
        ll = LessonsLearned(
            LessonsLearnedId(row.ll_id),
            TenantId(row.tenant_id),
            str(row.incident_id),
            LLStatus(row.status),
            row.created_at,
        )
        ll.reviewed_by = row.reviewed_by
        ll.reviewed_at = row.reviewed_at
        ll.finalized_by = row.finalized_by
        ll.finalized_at = row.finalized_at
        ll.campaign_retargeting_suggestion_ref = row.campaign_retargeting_suggestion_ref
        ll.confirmed_technique_ids = list(row.confirmed_technique_ids or [])

        item_rows = (
            await session.execute(
                select(LessonItemModel).where(LessonItemModel.ll_id == row.ll_id)
            )
        ).scalars().all()
        ll.lessons = [
            LessonItem(
                item_id=str(i.item_id),
                category=LessonCategory(i.category),
                description=i.description,
                impact_summary=i.impact_summary,
            )
            for i in item_rows
        ]

        action_rows = (
            await session.execute(
                select(ActionItemModel).where(ActionItemModel.ll_id == row.ll_id)
            )
        ).scalars().all()
        ll.action_items = [
            ImprovementAction(
                action_id=str(a.action_id),
                title=a.title,
                description=a.description,
                owner=a.owner,
                priority=ActionItemPriority(a.priority),
                due_date=a.due_date,
                status=ActionItemStatus(a.status),
                notes=a.notes or "",
            )
            for a in action_rows
        ]

        rec_rows = (
            await session.execute(
                select(RecommendationModel).where(RecommendationModel.ll_id == row.ll_id)
            )
        ).scalars().all()
        ll.recommendations = [
            Recommendation(
                recommendation_id=str(r.recommendation_id),
                text=r.text,
                technique_ids=list(r.technique_ids or []),
            )
            for r in rec_rows
        ]
        return ll

    async def find_by_id(
        self, tenant_id: TenantId, ll_id: LessonsLearnedId
    ) -> LessonsLearned | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(LessonsLearnedRecordModel).where(
                        LessonsLearnedRecordModel.tenant_id == tenant_id.value,
                        LessonsLearnedRecordModel.ll_id == ll_id.value,
                    )
                )
            ).scalar_one_or_none()
            return await self._load(session, row) if row is not None else None

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: str
    ) -> LessonsLearned | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(LessonsLearnedRecordModel).where(
                        LessonsLearnedRecordModel.tenant_id == tenant_id.value,
                        LessonsLearnedRecordModel.incident_id == UUID(incident_id),
                    )
                )
            ).scalar_one_or_none()
            return await self._load(session, row) if row is not None else None

    async def save(self, tenant_id: TenantId, ll: LessonsLearned) -> None:
        async with self._session_factory() as session:
            await session.merge(_ll_to_row(ll))

            await session.execute(
                delete(LessonItemModel).where(LessonItemModel.ll_id == ll.ll_id.value)
            )
            for item in ll.lessons:
                session.add(
                    LessonItemModel(
                        item_id=UUID(item.item_id),
                        ll_id=ll.ll_id.value,
                        tenant_id=tenant_id.value,
                        category=item.category.value,
                        description=item.description,
                        impact_summary=item.impact_summary,
                    )
                )

            await session.execute(
                delete(ActionItemModel).where(ActionItemModel.ll_id == ll.ll_id.value)
            )
            for action in ll.action_items:
                session.add(
                    ActionItemModel(
                        action_id=UUID(action.action_id),
                        ll_id=ll.ll_id.value,
                        tenant_id=tenant_id.value,
                        title=action.title,
                        description=action.description,
                        owner=action.owner,
                        priority=action.priority.value,
                        due_date=action.due_date,
                        status=action.status.value,
                        notes=action.notes,
                    )
                )

            await session.execute(
                delete(RecommendationModel).where(RecommendationModel.ll_id == ll.ll_id.value)
            )
            for rec in ll.recommendations:
                session.add(
                    RecommendationModel(
                        recommendation_id=UUID(rec.recommendation_id),
                        ll_id=ll.ll_id.value,
                        tenant_id=tenant_id.value,
                        text=rec.text,
                        technique_ids=list(rec.technique_ids),
                    )
                )

            await session.commit()


# ── PostIncidentReport ───────────────────────────────────────────────────────


def _report_to_row(report: PostIncidentReport) -> PostIncidentReportModel:
    return PostIncidentReportModel(
        report_id=report.report_id.value,
        tenant_id=report.tenant_id.value,
        incident_id=UUID(report.incident_id),
        lessons_learned_id=report.lessons_learned_id.value,
        format=report.format.value,
        artifact_ref=report.artifact_ref,
        artifact_bytes=report.artifact_bytes or None,
        status=report.status.value,
        generated_at=report.generated_at,
        exported_at=report.exported_at,
        exported_to=report.exported_to,
    )


def _row_to_report(row: PostIncidentReportModel) -> PostIncidentReport:
    report = PostIncidentReport(
        PostIncidentReportId(row.report_id),
        TenantId(row.tenant_id),
        str(row.incident_id),
        LessonsLearnedId(row.lessons_learned_id),
        ReportFormat(row.format),
        PostIncidentReportStatus(row.status),
    )
    report.artifact_ref = row.artifact_ref
    report.artifact_bytes = bytes(row.artifact_bytes) if row.artifact_bytes else b""
    report.generated_at = row.generated_at
    report.exported_at = row.exported_at
    report.exported_to = row.exported_to
    return report


class PgPostIncidentReportRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_id(
        self, tenant_id: TenantId, report_id: PostIncidentReportId
    ) -> PostIncidentReport | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(PostIncidentReportModel).where(
                        PostIncidentReportModel.tenant_id == tenant_id.value,
                        PostIncidentReportModel.report_id == report_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_report(row) if row is not None else None

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: str
    ) -> list[PostIncidentReport]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(PostIncidentReportModel).where(
                        PostIncidentReportModel.tenant_id == tenant_id.value,
                        PostIncidentReportModel.incident_id == UUID(incident_id),
                    )
                )
            ).scalars().all()
            return [_row_to_report(r) for r in rows]

    async def save(self, tenant_id: TenantId, report: PostIncidentReport) -> None:
        async with self._session_factory() as session:
            await session.merge(_report_to_row(report))
            await session.commit()
