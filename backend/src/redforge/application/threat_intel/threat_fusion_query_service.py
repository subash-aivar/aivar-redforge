"""Threat Fusion query service — M22 Phase 4."""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.threat_intel.fusion_entity import FusedIndicator, FusedRelationship
from redforge.domain.threat_intel.fusion_value_objects import (
    CanonicalIndicatorKey,
    FusedIndicatorType,
    IndicatorLifecycle,
)
from redforge.infrastructure.database.repositories.threat_fusion_repository import (
    SqlAlchemyFusedIndicatorRepository,
    SqlAlchemyFusedRelationshipRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class ThreatFusionQueryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_indicator(self, indicator_id: str) -> FusedIndicator | None:
        async with self._session_factory() as session:
            return await SqlAlchemyFusedIndicatorRepository(session).get_by_id(
                indicator_id
            )

    async def get_by_canonical_key(self, key: str) -> FusedIndicator | None:
        async with self._session_factory() as session:
            return await SqlAlchemyFusedIndicatorRepository(
                session
            ).get_by_canonical_key(CanonicalIndicatorKey(key))

    async def list_indicators(
        self,
        indicator_type: FusedIndicatorType,
        *,
        lifecycle: IndicatorLifecycle | None = IndicatorLifecycle.ACTIVE,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FusedIndicator]:
        async with self._session_factory() as session:
            return await SqlAlchemyFusedIndicatorRepository(session).list_by_type(
                indicator_type, lifecycle=lifecycle, limit=limit, offset=offset
            )

    async def list_relationships_for_indicator(
        self, indicator_id: str, *, limit: int = 200
    ) -> list[FusedRelationship]:
        async with self._session_factory() as session:
            return await SqlAlchemyFusedRelationshipRepository(session).list_for_indicator(
                indicator_id, limit=limit
            )
