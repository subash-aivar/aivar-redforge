"""Tenant-facing intelligence catalog reads — M22 Phase 6/7.

Reads fused indicators (global catalog) for UI surfaces. Does not mutate
fusion state and does not expose platform admin weight controls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redforge.domain.threat_intel.fusion_value_objects import (
    FusedIndicatorType,
    IndicatorLifecycle,
)
from redforge.infrastructure.database.repositories.threat_fusion_repository import (
    SqlAlchemyFusedIndicatorRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class CatalogIndicatorView:
    id: str
    canonical_key: str
    indicator_type: str
    display_name: str
    confidence: str | None
    risk_state: str
    metadata: dict[str, Any]


class IntelligenceCatalogQueryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_by_type(
        self,
        indicator_type: FusedIndicatorType,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CatalogIndicatorView]:
        async with self._session_factory() as session, session.begin():
            repo = SqlAlchemyFusedIndicatorRepository(session)
            items = await repo.list_by_type(
                indicator_type,
                lifecycle=IndicatorLifecycle.ACTIVE,
                limit=limit,
                offset=offset,
            )
            return [
                CatalogIndicatorView(
                    id=i.id,
                    canonical_key=i.canonical_key.value,
                    indicator_type=i.indicator_type.value,
                    display_name=i.display_name,
                    confidence=i.confidence.value if i.confidence else None,
                    risk_state=i.aggregated_risk.state.value,
                    metadata=dict(i.metadata),
                )
                for i in items
            ]
