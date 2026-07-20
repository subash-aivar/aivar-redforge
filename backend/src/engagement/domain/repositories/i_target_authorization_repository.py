"""ITargetAuthorizationRepository port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engagement.domain.aggregates.target_authorization import TargetAuthorization
    from engagement.domain.value_objects.engagement_vos import TargetRef
    from engagement.domain.value_objects.identifiers import (
        EngagementId,
        TargetAuthorizationId,
        TenantId,
    )


class ITargetAuthorizationRepository(ABC):
    @abstractmethod
    async def save(self, authorization: TargetAuthorization) -> None:
        """Persist authorization with optimistic locking."""

    @abstractmethod
    async def find_by_id(
        self,
        authorization_id: TargetAuthorizationId,
        tenant_id: TenantId,
    ) -> TargetAuthorization | None:
        """Tenant-scoped lookup."""

    @abstractmethod
    async def find_active_for_target(
        self,
        target_ref: TargetRef,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> TargetAuthorization | None:
        """Active authorization for target within engagement."""

    @abstractmethod
    async def find_by_engagement(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> list[TargetAuthorization]:
        """All authorizations for an engagement."""
