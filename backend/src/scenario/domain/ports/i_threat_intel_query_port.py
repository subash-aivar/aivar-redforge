"""IThreatIntelQueryPort — outbound ACL to M21 threat intelligence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scenario.domain.value_objects.identifiers import TenantId
    from scenario.domain.value_objects.scenario_vos import ThreatActorRef


class IThreatIntelQueryPort(ABC):
    @abstractmethod
    async def resolve_threat_actor(
        self,
        threat_actor_id: str,
        tenant_id: TenantId,
    ) -> ThreatActorRef | None:
        """Resolve a threat actor reference from M21 intelligence context."""
