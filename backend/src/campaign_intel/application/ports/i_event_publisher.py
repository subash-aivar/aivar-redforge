"""IEventPublisher — local, per-context port mirroring
`malware_intel.application.ports.i_event_publisher.IEventPublisher`."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from campaign_intel.domain.events.base import BaseDomainEvent


class IEventPublisher(ABC):
    @abstractmethod
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None: ...
