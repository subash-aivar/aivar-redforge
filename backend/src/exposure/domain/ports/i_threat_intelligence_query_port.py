"""ACL port → M21 threat intelligence (Phase 3 hybrid model)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from exposure.domain.value_objects.identifiers import TenantId


class ConfidenceLevel(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True, slots=True)
class ThreatActorMatch:
    threat_actor_ref: str
    matched_cve_ids: tuple[str, ...] = ()
    matched_asset_classes: tuple[str, ...] = ()
    matched_techniques: tuple[str, ...] = ()  # ATT&CK / TTP
    matched_iocs: tuple[str, ...] = ()
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM


@dataclass(frozen=True, slots=True)
class ThreatActorMatchResult:
    matches: tuple[ThreatActorMatch, ...] = ()
    queried_at: datetime | None = None
    data_freshness: datetime | None = None


class IThreatIntelligenceQueryPort(ABC):
    @abstractmethod
    async def query_threat_actor_matches(
        self,
        tenant_id: TenantId,
        cve_ids: list[str],
        asset_classes: list[str],
    ) -> ThreatActorMatchResult: ...
