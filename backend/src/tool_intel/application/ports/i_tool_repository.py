"""IToolRepository — implementation-independent (no ORM/DB types).
`tenant_id=None` addresses the global scope; a real `TenantId` addresses
that tenant's own scope only. A concrete adapter must never return a
record whose `tenant_id` does not exactly match the requested scope,
mirroring `ICampaignRepository`'s exact not-found-semantics
discipline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tool_intel.domain.aggregates.tool import Tool
    from tool_intel.domain.value_objects.enums import (
        ToolCapability,
        ToolCategory,
        ToolLifecycleStatus,
        ToolPlatform,
    )
    from tool_intel.domain.value_objects.identifiers import TenantId, ToolId


class IToolRepository(ABC):
    @abstractmethod
    async def save(self, tool: Tool) -> None: ...

    @abstractmethod
    async def get(self, tenant_id: TenantId | None, tool_id: ToolId) -> Tool | None: ...

    @abstractmethod
    async def get_any(self, tool_id: ToolId) -> Tool | None:
        """Unscoped lookup by ID only — used exclusively to resolve a
        Tool's ownership scope (its `tenant_id`) for the API layer's
        ownership-based authorization decision. The caller must
        authorize before using anything from the returned aggregate
        beyond `.tenant_id`."""
        ...

    @abstractmethod
    async def get_by_canonical_name(
        self, tenant_id: TenantId | None, canonical_name: str
    ) -> Tool | None: ...

    @abstractmethod
    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: ToolLifecycleStatus | None = None,
        category: ToolCategory | None = None,
        platform: ToolPlatform | None = None,
        capability: ToolCapability | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Tool]: ...
