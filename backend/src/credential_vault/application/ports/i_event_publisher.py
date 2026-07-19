"""IEventPublisher — post-commit domain event publication port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.events.base import BaseDomainEvent


class IEventPublisher(ABC):
    """Publishes domain events after a successful unit-of-work commit."""

    @abstractmethod
    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        """
        Publish a batch of domain events.

        An empty ``events`` list is a valid input; implementations treat it as a
        no-op. Callers must still invoke this method for consistency.
        """
