from __future__ import annotations

from uuid import UUID

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.aggregates.threat_hunt_configuration import ThreatHuntConfiguration
from threat_hunt.domain.repositories.i_repositories import (
    IThreatHuntCandidateRepository,
    IThreatHuntConfigurationRepository,
)
from threat_hunt.domain.value_objects.enums import ThreatHuntCandidateStatus
from threat_hunt.domain.value_objects.identifiers import TenantId


class InMemoryThreatHuntCandidateRepository(IThreatHuntCandidateRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, ThreatHuntCandidate]] = {}

    async def save(self, candidate: ThreatHuntCandidate, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(candidate.candidate_id)] = candidate

    async def find_pending_review(
        self, tenant_id: TenantId, limit: int
    ) -> list[ThreatHuntCandidate]:
        rows = [
            c
            for c in self._items.get(str(tenant_id), {}).values()
            if c.candidate_status
            in {ThreatHuntCandidateStatus.CANDIDATE, ThreatHuntCandidateStatus.UNDER_REVIEW}
        ]
        return rows[:limit]

    async def find_by_id(
        self, candidate_id: UUID, tenant_id: TenantId
    ) -> ThreatHuntCandidate | None:
        return self._items.get(str(tenant_id), {}).get(str(candidate_id))


class InMemoryThreatHuntConfigurationRepository(IThreatHuntConfigurationRepository):
    def __init__(self) -> None:
        self._items: dict[str, ThreatHuntConfiguration] = {}

    async def get_or_create_default(self, tenant_id: TenantId) -> ThreatHuntConfiguration:
        key = str(tenant_id)
        if key not in self._items:
            self._items[key] = ThreatHuntConfiguration.default(tenant_id)
        return self._items[key]
