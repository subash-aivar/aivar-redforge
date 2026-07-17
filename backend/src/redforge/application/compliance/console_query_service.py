"""Compliance Operations Console read service — M24 Phase 4 (scalable queries).

CQRS-lite: org-scoped aggregations and paginated lists only.
Does not mutate domain aggregates or enforce workflow transitions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from redforge.infrastructure.database.repositories.compliance.console_query_repository import (
    SqlAlchemyComplianceConsoleQueryRepository,
)
from redforge.infrastructure.database.repositories.compliance.recommendation_repository import (
    recommendation_from_row,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.domain.compliance.recommendation import EvidenceRecommendation

SortDir = Literal["asc", "desc"]


class ComplianceConsoleQueryService:
    """Read-model facade for the Compliance Operations Console."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def overview(self, organization_id: str) -> dict[str, Any]:
        async with self._session_factory() as session:
            repo = SqlAlchemyComplianceConsoleQueryRepository(session)
            return await repo.overview_summary(organization_id)

    async def list_assessments(
        self,
        organization_id: str,
        *,
        period_id: str | None = None,
        status: str | None = None,
        framework_key: str | None = None,
        search: str | None = None,
        sort: str = "updated_at",
        sort_dir: SortDir = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        async with self._session_factory() as session:
            repo = SqlAlchemyComplianceConsoleQueryRepository(session)
            return await repo.list_assessments_page(
                organization_id,
                period_id=period_id,
                status=status,
                framework_key=framework_key,
                search=search,
                sort=sort,
                sort_dir=sort_dir,
                limit=limit,
                offset=offset,
            )

    async def list_recommendations(
        self,
        organization_id: str,
        *,
        status: str | None = None,
        confidence: str | None = None,
        framework_key: str | None = None,
        assessment_id: str | None = None,
        period_id: str | None = None,
        search: str | None = None,
        sort: str = "updated_at",
        sort_dir: SortDir = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[EvidenceRecommendation], int]:
        async with self._session_factory() as session:
            repo = SqlAlchemyComplianceConsoleQueryRepository(session)
            rows, total = await repo.list_recommendations_page(
                organization_id,
                status=status,
                confidence=confidence,
                framework_key=framework_key,
                assessment_id=assessment_id,
                period_id=period_id,
                search=search,
                sort=sort,
                sort_dir=sort_dir,
                limit=limit,
                offset=offset,
            )
            return [recommendation_from_row(row) for row in rows], total

    async def list_evidence(
        self,
        organization_id: str,
        *,
        category: str | None = None,
        search: str | None = None,
        sort: str = "updated_at",
        sort_dir: SortDir = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        async with self._session_factory() as session:
            repo = SqlAlchemyComplianceConsoleQueryRepository(session)
            return await repo.list_evidence_page(
                organization_id,
                category=category,
                search=search,
                sort=sort,
                sort_dir=sort_dir,
                limit=limit,
                offset=offset,
            )

    async def list_timeline(
        self,
        organization_id: str,
        *,
        kind: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        async with self._session_factory() as session:
            repo = SqlAlchemyComplianceConsoleQueryRepository(session)
            return await repo.list_timeline_page(
                organization_id,
                kind=kind,
                search=search,
                limit=limit,
                offset=offset,
            )

    async def analytics(self, organization_id: str) -> dict[str, Any]:
        async with self._session_factory() as session:
            repo = SqlAlchemyComplianceConsoleQueryRepository(session)
            return await repo.analytics(organization_id)
