"""IEngagementQueryPort — ACL to engagement governance (refs only)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from operation.domain.value_objects.identifiers import EngagementId, TenantId


class IEngagementQueryPort(ABC):
    @abstractmethod
    async def get_engagement_state(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> str:
        """Return engagement state string (e.g. Active, Suspended)."""

    @abstractmethod
    async def is_active(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> bool:
        ...

    @abstractmethod
    async def get_authorized_targets(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> set[UUID]:
        """Asset UUIDs authorized in TargetScope."""

    @abstractmethod
    async def get_allowed_techniques(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> set[str]:
        """Technique IDs allowed by Rules of Engagement."""
