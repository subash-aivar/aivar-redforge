"""Anti-Corruption Layer port: engagement query interface (ACL to M29)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass
class EngagementStatus:
    engagement_id: UUID
    state: str
    kill_switch_state: str
    # None = no scope restriction; empty list = no targets in scope (all blocked)
    allowed_target_ids: list[UUID] | None = field(default=None)


class IEngagementQueryPort(ABC):
    """ACL interface for querying M29 engagement state.

    Implementations translate M29 responses into EngagementStatus without
    leaking M29 domain concepts into the campaign bounded context.
    """

    @abstractmethod
    async def get_engagement_status(
        self,
        engagement_id: UUID,
        tenant_id: UUID,
    ) -> EngagementStatus | None:
        """Return the current status of the specified engagement, or None if not found."""
