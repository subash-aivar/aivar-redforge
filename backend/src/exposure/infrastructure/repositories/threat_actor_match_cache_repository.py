"""ThreatActorMatchCache repository (Phase 3)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from exposure.infrastructure.projections.threat_actor_match_cache import (
    ThreatActorMatchCache,
)

if TYPE_CHECKING:
    from exposure.domain.value_objects.identifiers import TenantId


class IThreatActorMatchCacheRepository(ABC):
    @abstractmethod
    async def load(self, tenant_id: TenantId) -> ThreatActorMatchCache: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, cache: ThreatActorMatchCache) -> None: ...


class InMemoryThreatActorMatchCacheRepository(IThreatActorMatchCacheRepository):
    def __init__(self) -> None:
        self._caches: dict[str, ThreatActorMatchCache] = {}

    async def load(self, tenant_id: TenantId) -> ThreatActorMatchCache:
        key = str(tenant_id)
        if key not in self._caches:
            self._caches[key] = ThreatActorMatchCache(tenant_id=tenant_id)
        return self._caches[key]

    async def save(self, tenant_id: TenantId, cache: ThreatActorMatchCache) -> None:
        self._caches[str(tenant_id)] = cache
