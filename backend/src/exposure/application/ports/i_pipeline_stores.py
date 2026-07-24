"""Application ports for score pipeline persistence (debounce / idempotency / profiles)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from exposure.domain.value_objects.identifiers import TenantId


@dataclass(slots=True)
class PendingRecomputation:
    tenant_id: TenantId
    asset_ref_id: UUID
    marked_at: datetime
    debounce_override_seconds: int | None = None
    bypass_debounce: bool = False


@dataclass(slots=True)
class TenantExposureProfile:
    tenant_id: TenantId
    asset_scores: dict[str, float] = field(default_factory=dict)
    recomputing: bool = False
    recomputation_failed_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def tenant_exposure_score(self) -> float:
        if not self.asset_scores:
            return 0.0
        return sum(self.asset_scores.values()) / len(self.asset_scores)


class IPendingRecomputationStore(ABC):
    @abstractmethod
    async def upsert(
        self,
        tenant_id: TenantId,
        asset_ref_id: UUID,
        marked_at: datetime,
        *,
        debounce_override_seconds: int | None = None,
        bypass_debounce: bool = False,
    ) -> None: ...

    @abstractmethod
    async def upsert_all_assets(
        self,
        tenant_id: TenantId,
        asset_ref_ids: list[UUID],
        marked_at: datetime,
        *,
        debounce_override_seconds: int | None = None,
    ) -> None: ...

    @abstractmethod
    async def list_eligible(
        self, now: datetime, default_debounce_seconds: int = 300, limit: int = 1000
    ) -> list[PendingRecomputation]: ...

    @abstractmethod
    async def delete(self, tenant_id: TenantId, asset_ref_id: UUID) -> None: ...

    @abstractmethod
    async def count_for_tenant(self, tenant_id: TenantId) -> int: ...

    @abstractmethod
    async def flush_tenant(self, tenant_id: TenantId) -> list[UUID]: ...


class IProcessedExposureSignalStore(ABC):
    @abstractmethod
    async def already_processed(self, tenant_id: TenantId, event_id: str) -> bool: ...

    @abstractmethod
    async def mark_processed(self, tenant_id: TenantId, event_id: str) -> None: ...


class ITenantExposureProfileStore(ABC):
    @abstractmethod
    async def load(self, tenant_id: TenantId) -> TenantExposureProfile: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, profile: TenantExposureProfile) -> None: ...
