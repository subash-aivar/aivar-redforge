"""IReportDeliveryPort — abstract delivery (Phase 2 noop stub)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from reporting.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


class IReportDeliveryPort(ABC):
    @abstractmethod
    async def deliver(
        self,
        tenant_id: TenantId,
        instance_id: UUID,
        recipients: list[str],
        artifact_ref: str,
    ) -> int:
        """Return recipient count delivered. Phase 2 may no-op and return 0."""
        ...
