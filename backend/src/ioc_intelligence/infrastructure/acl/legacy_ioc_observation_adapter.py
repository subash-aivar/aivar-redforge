"""SqlAlchemyLegacyIocObservationAdapter — real, read-only
implementation of `ILegacyIocObservationPort` (M51.2 Phase A5).

Reads `ThreatIntelIndicatorModel` through the existing, unmodified
`SqlAlchemyThreatIntelIndicatorRepository` — never a raw ORM query in
this module, never a second repository implementation for the same
table. This adapter never writes, deletes, or mutates a legacy row;
`ThreatIntelIndicatorModel` remains RedForge's own lookup/audit
ledger, untouched by IOC ingestion.

The legacy `indicator` column is NOT trusted as pre-normalized — the
ingestion orchestrator (not this adapter) re-normalizes every
candidate through the certified `IndicatorCanonicalKey.for_type`
before it can become part of an `IOC`'s identity. This adapter's own
`normalized_value` field is a straight, unvalidated passthrough of the
legacy `indicator` string, named to make that distinction obvious to
callers, not to claim it is already canonical."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ioc_intelligence.application.ports.i_legacy_ioc_observation_port import (
    ILegacyIocObservationPort,
    LegacyIocObservationDTO,
)
from redforge.infrastructure.database.repositories.threat_intel_repository import (
    SqlAlchemyThreatIntelIndicatorRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.infrastructure.database.models.threat_intel import ThreatIntelIndicatorModel


def _to_dto(row: ThreatIntelIndicatorModel) -> LegacyIocObservationDTO:
    return LegacyIocObservationDTO(
        legacy_indicator_id=row.id,
        ioc_type=row.indicator_type,
        normalized_value=row.indicator,
        first_seen_at=row.first_seen_at.isoformat(),
        last_seen_at=row.last_seen_at.isoformat(),
    )


class SqlAlchemyLegacyIocObservationAdapter(ILegacyIocObservationPort):
    def __init__(self, session: AsyncSession) -> None:
        self._repo = SqlAlchemyThreatIntelIndicatorRepository(session)

    async def find_observation(
        self, tenant_id: str, ioc_type: str, normalized_value: str
    ) -> LegacyIocObservationDTO | None:
        row = await self._repo.get_by_natural_key(tenant_id, ioc_type, normalized_value)
        return _to_dto(row) if row is not None else None

    async def list_recent_observations(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[LegacyIocObservationDTO]:
        rows = await self._repo.list_recent(tenant_id, limit, offset)
        return [_to_dto(row) for row in rows]
