"""IPlanInvalidationPort — cascade plan supersede on payload revoke."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


class IPlanInvalidationPort(ABC):
    @abstractmethod
    async def invalidate_plans_for_payload(
        self, tenant_id: UUID, payload_id: UUID
    ) -> int:
        """Supersede SIGNED/EXECUTING plan versions referencing payload_id.

        Returns count of superseded plan versions.
        """
        ...
