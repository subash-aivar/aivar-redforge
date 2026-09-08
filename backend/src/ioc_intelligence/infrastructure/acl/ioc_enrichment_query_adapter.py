"""SqlAlchemyIocEnrichmentQueryAdapter — real, read-only implementation
of `IIocEnrichmentQueryPort` (M51.2 Phase A5).

Reads cached `ThreatIntelEnrichmentModel` rows through the existing,
unmodified `SqlAlchemyThreatIntelEnrichmentRepository` — no network
provider call anywhere in this module, no second enrichment engine.
Only `EnrichmentKind.REPUTATION` rows carry a real, provider-defined
confidence signal (`ReputationEvidence.confidence_score`); geolocation/
ASN enrichment kinds carry no trust signal at all and this adapter
never fabricates one for them — callers simply get `confidence_score=
None` for any kind other than `reputation`, which the ingestion
orchestrator treats as "not evidence, enrichment context only" and
never turns into a `SourceAttribution`.

`is_expired` is computed from the row's own `expires_at` — the exact
same TTL-cache boundary `IocCorrelationService`/`enrichment_service`
already use to decide whether to re-fetch; this adapter does not
invent a second expiry policy."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ioc_intelligence.application.ports.i_ioc_enrichment_query_port import (
    EnrichmentSummaryDTO,
    IIocEnrichmentQueryPort,
)
from redforge.domain.threat_intel.value_objects import EnrichmentKind
from redforge.infrastructure.database.repositories.threat_intel_repository import (
    SqlAlchemyThreatIntelEnrichmentRepository,
    SqlAlchemyThreatIntelIndicatorRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.infrastructure.database.models.threat_intel import ThreatIntelEnrichmentModel


def _to_dto(row: ThreatIntelEnrichmentModel, *, now: datetime) -> EnrichmentSummaryDTO:
    confidence_score: float | None = None
    provider_reference_id: str | None = None
    if row.kind == EnrichmentKind.REPUTATION.value:
        confidence_score = row.data.get("confidence_score")
        provider_reference_id = row.data.get("provider_reference_id")
    expires_at = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    return EnrichmentSummaryDTO(
        provider_name=row.provider_name,
        kind=row.kind,
        success=row.success,
        fetched_at=row.fetched_at.isoformat(),
        expires_at=row.expires_at.isoformat(),
        is_expired=expires_at < now,
        confidence_score=confidence_score,
        provider_reference_id=provider_reference_id,
    )


class SqlAlchemyIocEnrichmentQueryAdapter(IIocEnrichmentQueryPort):
    def __init__(self, session: AsyncSession) -> None:
        self._indicators = SqlAlchemyThreatIntelIndicatorRepository(session)
        self._enrichments = SqlAlchemyThreatIntelEnrichmentRepository(session)

    async def get_latest_enrichment(
        self, tenant_id: str, ioc_type: str, normalized_value: str, kind: str
    ) -> EnrichmentSummaryDTO | None:
        indicator = await self._indicators.get_by_natural_key(tenant_id, ioc_type, normalized_value)
        if indicator is None:
            return None
        rows = await self._enrichments.list_for_indicator(tenant_id, indicator.id)
        candidates = [r for r in rows if r.kind == kind]
        if not candidates:
            return None
        latest = max(candidates, key=lambda r: r.fetched_at)
        return _to_dto(latest, now=datetime.now(UTC))
