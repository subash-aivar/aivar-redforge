"""IEventPublisher — local, per-context port mirroring every other
bounded context's convention (`threat_actor_intel.IEventPublisher`).
ioc_intelligence does NOT wire into any platform-wide event bus in
Phase A2 — that is explicitly deferred. No concrete implementation
exists yet either — only the abstract contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ioc_intelligence.domain.events.base import BaseDomainEvent


class IEventPublisher(ABC):
    @abstractmethod
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None: ...
