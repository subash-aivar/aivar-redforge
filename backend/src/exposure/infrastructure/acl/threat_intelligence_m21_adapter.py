"""M21 threat intelligence ACL adapter — seedable until live M21 wiring."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from exposure.domain.ports.i_threat_intelligence_query_port import (
    IThreatIntelligenceQueryPort,
    ThreatActorMatch,
    ThreatActorMatchResult,
)

if TYPE_CHECKING:
    from exposure.domain.value_objects.identifiers import TenantId


class ThreatIntelligenceM21Adapter(IThreatIntelligenceQueryPort):
    """In-process seedable adapter (ops injects live M21 client in production)."""

    def __init__(self) -> None:
        self._catalog: list[ThreatActorMatch] = []
        self._unavailable = False
        self.data_freshness: datetime | None = None

    def seed(self, match: ThreatActorMatch) -> None:
        self._catalog.append(match)
        self.data_freshness = datetime.now(UTC)

    def mark_unavailable(self) -> None:
        self._unavailable = True

    def mark_available(self) -> None:
        self._unavailable = False

    async def query_threat_actor_matches(
        self,
        tenant_id: TenantId,
        cve_ids: list[str],
        asset_classes: list[str],
    ) -> ThreatActorMatchResult:
        del tenant_id
        if self._unavailable:
            raise ConnectionError("M21 threat intelligence unavailable")
        cve_set = set(cve_ids)
        class_set = set(asset_classes)
        matched: list[ThreatActorMatch] = []
        for row in self._catalog:
            if cve_set.intersection(row.matched_cve_ids) or class_set.intersection(
                row.matched_asset_classes
            ):
                matched.append(row)
        now = datetime.now(UTC)
        return ThreatActorMatchResult(
            matches=tuple(matched),
            queried_at=now,
            data_freshness=self.data_freshness or now,
        )
