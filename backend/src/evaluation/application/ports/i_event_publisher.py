"""IEventPublisher — application port for evaluation domain events."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.domain.events.base import BaseDomainEvent


class IEventPublisher(ABC):
    @abstractmethod
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None: ...
