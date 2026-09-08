"""IEventPublisher — local, per-context port mirroring every other
mature bounded context's convention (`exposure.IEventPublisher`,
`risk_engine`'s equivalent). ADR-M51.1-04: threat_actor_intel does
NOT wire into the platform-wide `PlatformEventPublisher`/EventStore
in M51.1 — that is an explicitly deferred, separately-tracked
decision. No `StructlogEventPublisher` concrete implementation exists
yet either (Phase 3), per this phase's scope — only the abstract
contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_actor_intel.domain.events.base import BaseDomainEvent


class IEventPublisher(ABC):
    @abstractmethod
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None: ...
