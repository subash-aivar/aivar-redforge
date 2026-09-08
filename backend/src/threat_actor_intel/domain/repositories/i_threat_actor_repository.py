"""IThreatActorRepository — no `tenant_id` parameter, per ADR-M51.1-01/
02: `ThreatActor` is the platform's single canonical, global reference
model. Implementation-independent (no ORM/DB types), per M51.1
Phase 2 scope — the concrete Postgres adapter is Phase 3 work."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
    from threat_actor_intel.domain.value_objects.enums import ActivityStatus, ThreatActorOrigin
    from threat_actor_intel.domain.value_objects.identifiers import ThreatActorId


class IThreatActorRepository(ABC):
    @abstractmethod
    async def save(self, actor: ThreatActor) -> None: ...

    @abstractmethod
    async def get(self, threat_actor_id: ThreatActorId) -> ThreatActor | None: ...

    @abstractmethod
    async def list(
        self,
        status: ActivityStatus | None = None,
        origin: ThreatActorOrigin | None = None,
    ) -> list[ThreatActor]: ...
