"""ILegacyIocObservationPort — the future adaptation seam for
`redforge.infrastructure.database.models.threat_intel.
ThreatIntelIndicatorModel` (M51.2 Phase A.1 ownership-reconciliation
decision: legacy lookup/audit ledger, a future IOC input source, never
a second identity owner).

Contract only — no concrete adapter exists yet, and this module never
imports `redforge.domain.threat_intel` or any ORM/infrastructure type.
A future adapter translates a legacy indicator row into
`LegacyIocObservationDTO`, keyed by the same normalized
`(ioc_type, normalized_value)` pair `IndicatorCanonicalKey` already
uses, so a future reconciliation step can join them without a second,
independently-keyed identity."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LegacyIocObservationDTO:
    legacy_indicator_id: str
    ioc_type: str
    normalized_value: str
    first_seen_at: str
    last_seen_at: str


class ILegacyIocObservationPort(ABC):
    @abstractmethod
    async def find_observation(
        self, tenant_id: str, ioc_type: str, normalized_value: str
    ) -> LegacyIocObservationDTO | None: ...

    @abstractmethod
    async def list_recent_observations(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[LegacyIocObservationDTO]:
        """Bounded, explicitly-paged read of this tenant's legacy
        observation rows (M51.2 Phase A5) — the seed candidate list for
        ingestion. Callers control the window via `limit`/`offset`;
        this port never scans unboundedly on its own."""
        ...
