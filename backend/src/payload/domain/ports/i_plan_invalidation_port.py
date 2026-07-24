"""IPlanInvalidationPort — cascade plan supersede on payload revoke."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from payload.domain.value_objects.identifiers import TenantId


class IPlanInvalidationPort(ABC):
    @abstractmethod
    async def invalidate_plans_for_payload(
        self, tenant_id: TenantId, payload_id: UUID
    ) -> int:
        """Supersede SIGNED/EXECUTING plan versions referencing payload_id.

        Returns count of superseded plan versions.
        """
        ...
