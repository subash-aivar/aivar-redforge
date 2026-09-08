"""IIocEnrichmentQueryPort — the future adaptation seam for
`redforge.infrastructure.database.models.threat_intel.
ThreatIntelEnrichmentModel` (M51.2 Phase A.1 decision: a
provider-response cache/projection, not an ownership conflict).

Contract only — no concrete adapter exists yet, and this module never
imports `redforge.domain.threat_intel` or any ORM/infrastructure type.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EnrichmentSummaryDTO:
    provider_name: str
    kind: str
    success: bool
    fetched_at: str
    expires_at: str
    is_expired: bool
    # Provider-native confidence, AS THE PROVIDER DEFINED IT (e.g.
    # AbuseIPDB's 0-100 abuseConfidenceScore) — `None` when the
    # underlying cached row carries no such field (M51.2 Phase A5: the
    # adapter never invents one). `provider_reference_id` is the
    # provider's own record/report identifier when the cached payload
    # includes one.
    confidence_score: float | None = None
    provider_reference_id: str | None = None


class IIocEnrichmentQueryPort(ABC):
    @abstractmethod
    async def get_latest_enrichment(
        self, tenant_id: str, ioc_type: str, normalized_value: str, kind: str
    ) -> EnrichmentSummaryDTO | None: ...
