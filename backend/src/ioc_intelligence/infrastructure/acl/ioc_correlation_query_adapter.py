"""SqlAlchemyIocCorrelationQueryAdapter — real, read-only
implementation of `IIocCorrelationQueryPort` (M51.2 Phase A5).

Reads `ThreatIntelEnrichmentModel` rows with `kind=EnrichmentKind.
IOC_MATCH` — the exact rows `IocCorrelationService.correlate_recent()`
already persists (see `redforge.application.threat_intel.
correlation_service._persist`). This adapter does not call, wrap, or
re-implement any part of `IocCorrelationService`'s matching logic — it
only reads what that service has already decided and stored, through
the existing `SqlAlchemyThreatIntelEnrichmentRepository`. No duplicate
correlation engine, no network provider call.

A `success=True` row with an empty `data` payload means "the provider
call succeeded but found no match" (see `IocCorrelationService.
_persist`: `data=asdict(match) if match else {}`) — this adapter only
reports rows that carry a real match payload (`data["provider"]`
present), never treating "we asked and got nothing" as a match."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ioc_intelligence.application.ports.i_ioc_correlation_query_port import (
    CorrelationMatchDTO,
    IIocCorrelationQueryPort,
)
from redforge.domain.threat_intel.value_objects import EnrichmentKind
from redforge.infrastructure.database.repositories.threat_intel_repository import (
    SqlAlchemyThreatIntelEnrichmentRepository,
    SqlAlchemyThreatIntelIndicatorRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyIocCorrelationQueryAdapter(IIocCorrelationQueryPort):
    def __init__(self, session: AsyncSession) -> None:
        self._indicators = SqlAlchemyThreatIntelIndicatorRepository(session)
        self._enrichments = SqlAlchemyThreatIntelEnrichmentRepository(session)

    async def get_correlation_matches(
        self, tenant_id: str, ioc_type: str, normalized_value: str
    ) -> list[CorrelationMatchDTO]:
        indicator = await self._indicators.get_by_natural_key(tenant_id, ioc_type, normalized_value)
        if indicator is None:
            return []
        rows = await self._enrichments.list_for_indicator(tenant_id, indicator.id)
        matches: list[CorrelationMatchDTO] = []
        for row in rows:
            if row.kind != EnrichmentKind.IOC_MATCH.value or not row.success:
                continue
            if not row.data.get("provider"):
                continue  # real call, no match found — not a correlation result
            matches.append(
                CorrelationMatchDTO(
                    provider_name=row.provider_name,
                    matched=True,
                    detail=row.detail,
                    matched_at=row.fetched_at.isoformat(),
                    provider_reference_id=row.data.get("provider_reference_id"),
                )
            )
        return matches
