"""ACL query port → ai_agent_governance deviation stats."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from ai_posture.domain.value_objects.identifiers import TenantId


class IAgentDeviationStatsPort(ABC):
    @abstractmethod
    async def recent_deviation_count(
        self, tenant_id: TenantId, asset_id: UUID, *, limit: int = 100
    ) -> int: ...

    @abstractmethod
    async def list_deviation_summaries(self, tenant_id: TenantId) -> list[dict[str, str]]: ...

    @abstractmethod
    async def has_active_envelope(self, tenant_id: TenantId, asset_id: UUID) -> bool: ...

    @abstractmethod
    async def human_approval_history(
        self, tenant_id: TenantId, envelope_id: UUID
    ) -> list[dict[str, str]]: ...
