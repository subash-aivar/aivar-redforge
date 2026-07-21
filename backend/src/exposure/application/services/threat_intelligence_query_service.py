"""CQRS read models for threat intelligence cache (Phase 3)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure.application._auth import require_at_least
from exposure.domain.value_objects.enums import ExposureRole
from exposure.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID

    from exposure.infrastructure.repositories.threat_actor_match_cache_repository import (
        IThreatActorMatchCacheRepository,
    )


class ThreatIntelligenceQueryService:
    def __init__(self, cache_repo: IThreatActorMatchCacheRepository) -> None:
        self._cache_repo = cache_repo

    async def get_threat_actor_targeting(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> dict[str, object]:
        require_at_least(actor_roles, ExposureRole.VIEWER)
        cache = await self._cache_repo.load(TenantId(tenant_id))
        return cache.to_dict()
