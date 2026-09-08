"""IInfrastructureRepository — implementation-independent (no ORM/DB
types). `tenant_id=None` addresses the global scope; a real `TenantId`
addresses that tenant's own scope only. A concrete adapter must never
return a record whose `tenant_id` does not exactly match the requested
scope, mirroring `IToolRepository`'s exact not-found-semantics
discipline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
    from infrastructure_intel.domain.value_objects.enums import (
        CloudProvider,
        InfrastructureLifecycleStatus,
        InfrastructureType,
    )
    from infrastructure_intel.domain.value_objects.identifiers import (
        InfrastructureId,
        TenantId,
    )


class IInfrastructureRepository(ABC):
    @abstractmethod
    async def save(self, record: Infrastructure) -> None: ...

    @abstractmethod
    async def get(
        self, tenant_id: TenantId | None, infrastructure_id: InfrastructureId
    ) -> Infrastructure | None: ...

    @abstractmethod
    async def get_any(self, infrastructure_id: InfrastructureId) -> Infrastructure | None:
        """Unscoped lookup by ID only — used exclusively to resolve an
        Infrastructure record's ownership scope (its `tenant_id`) for the
        API layer's ownership-based authorization decision. The caller
        must authorize before using anything from the returned aggregate
        beyond `.tenant_id`."""
        ...

    @abstractmethod
    async def get_by_identity(
        self,
        tenant_id: TenantId | None,
        infrastructure_type: InfrastructureType,
        normalized_identifier: str,
    ) -> Infrastructure | None: ...

    @abstractmethod
    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: InfrastructureLifecycleStatus | None = None,
        infrastructure_type: InfrastructureType | None = None,
        cloud_provider: CloudProvider | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Infrastructure]: ...
