from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.aggregates.threat_hunt_configuration import ThreatHuntConfiguration
from threat_hunt.domain.value_objects.identifiers import TenantId


class IThreatHuntCandidateRepository(ABC):
    @abstractmethod
    async def save(self, candidate: ThreatHuntCandidate, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_pending_review(
        self, tenant_id: TenantId, limit: int
    ) -> list[ThreatHuntCandidate]: ...

    @abstractmethod
    async def find_by_id(
        self, candidate_id: UUID, tenant_id: TenantId
    ) -> ThreatHuntCandidate | None: ...


class IThreatHuntConfigurationRepository(ABC):
    @abstractmethod
    async def get_or_create_default(self, tenant_id: TenantId) -> ThreatHuntConfiguration: ...
