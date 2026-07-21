from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_agent_governance.domain.aggregates.agent_deviation_event import (
        AgentDeviationEvent,
    )
    from ai_agent_governance.domain.value_objects.identifiers import (
        AgentDeviationEventId,
        AISystemAssetId,
        TenantId,
    )


class IAgentDeviationEventRepository(ABC):
    @abstractmethod
    async def save(self, deviation: AgentDeviationEvent) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, deviation_id: AgentDeviationEventId, tenant_id: TenantId
    ) -> AgentDeviationEvent | None: ...

    @abstractmethod
    async def find_unreviewed_by_tenant(self, tenant_id: TenantId) -> list[AgentDeviationEvent]: ...

    @abstractmethod
    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId, limit: int
    ) -> list[AgentDeviationEvent]: ...

    @abstractmethod
    async def find_by_idempotency_key(
        self, tenant_id: TenantId, idempotency_key: str
    ) -> AgentDeviationEvent | None: ...

    @abstractmethod
    async def record_idempotent_action(
        self, tenant_id: TenantId, idempotency_key: str, result: str
    ) -> bool:
        """Return False if key already seen (idempotent no-op)."""
        ...
