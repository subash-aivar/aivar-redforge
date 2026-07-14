"""Read-only query service over canonical indicators and their cached
enrichments — backs the Intelligence panel's "recently enriched
indicators" list and per-indicator drill-down."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redforge.infrastructure.database.repositories.threat_intel_repository import (
    SqlAlchemyThreatIntelEnrichmentRepository,
    SqlAlchemyThreatIntelIndicatorRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class IndicatorDTO:
    id: str
    indicator: str
    indicator_type: str
    first_seen_at: str
    last_seen_at: str


@dataclass(frozen=True, slots=True)
class EnrichmentDTO:
    provider_name: str
    kind: str
    success: bool
    error_category: str | None
    data: dict[str, Any]
    fetched_at: str
    expires_at: str


class IndicatorQueryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_recent(
        self,
        organization_id: str,
        limit: int,
        offset: int,
    ) -> list[IndicatorDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyThreatIntelIndicatorRepository(uow.session)
            rows = await repo.list_recent(organization_id, limit, offset)
        return [
            IndicatorDTO(
                id=r.id,
                indicator=r.indicator,
                indicator_type=r.indicator_type,
                first_seen_at=r.first_seen_at.isoformat(),
                last_seen_at=r.last_seen_at.isoformat(),
            )
            for r in rows
        ]

    async def list_enrichments(
        self,
        organization_id: str,
        indicator_id: str,
    ) -> list[EnrichmentDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyThreatIntelEnrichmentRepository(uow.session)
            rows = await repo.list_for_indicator(organization_id, indicator_id)
        return [
            EnrichmentDTO(
                provider_name=r.provider_name,
                kind=r.kind,
                success=r.success,
                error_category=r.error_category,
                data=r.data,
                fetched_at=r.fetched_at.isoformat(),
                expires_at=r.expires_at.isoformat(),
            )
            for r in rows
        ]
