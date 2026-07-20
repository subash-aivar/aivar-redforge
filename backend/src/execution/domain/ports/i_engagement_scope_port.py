"""IEngagementScopePort — ACL to engagement scope without importing engagement domain."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from execution.domain.value_objects.execution_vos import ScopeSnapshot
    from execution.domain.value_objects.identifiers import EngagementId, TenantId


class IEngagementScopePort(ABC):
    @abstractmethod
    async def get_scope_snapshot(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> ScopeSnapshot:
        """Return authorized targets, scope_hash, window, and technique allowlist."""
        ...
