"""IExposureScopeQueryPort — M30-owned ACL port (Finalization D4).

M30 owns this interface and DTOs. M32 implements the service;
the M30-side adapter translates M32 responses into these DTOs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from campaign.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class ExposureScopeRequest:
    tenant_id: TenantId
    max_assets: int = 100
    min_exposure_score: float | None = None
    amplifier_filter: tuple[str, ...] = ()
    asset_kind_filter: tuple[str, ...] = ()
    include_stale_scores: bool = False
    requested_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ScopedAsset:
    asset_ref_id: str
    exposure_score: float
    dominant_amplifiers: tuple[str, ...] = ()
    business_criticality: str | None = None
    snapshot_computed_at: str = ""
    is_score_stale: bool = False


@dataclass(frozen=True, slots=True)
class ExposureScopeResponse:
    tenant_id: str
    assets: tuple[ScopedAsset, ...] = ()
    total_eligible: int = 0
    score_version: str = "0"
    queried_at: str = ""
    has_stale_scores: bool = False
    query_duration_ms: int = 0
    metadata: dict[str, object] = field(default_factory=dict)


class IExposureScopeQueryPort(ABC):
    @abstractmethod
    async def query_scope(self, request: ExposureScopeRequest) -> ExposureScopeResponse: ...
