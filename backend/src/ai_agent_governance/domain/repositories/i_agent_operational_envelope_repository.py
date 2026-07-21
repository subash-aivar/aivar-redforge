from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from ai_agent_governance.domain.aggregates.agent_operational_envelope import (
        AgentOperationalEnvelope,
    )
    from ai_agent_governance.domain.value_objects.identifiers import (
        AgentOperationalEnvelopeId,
        AISystemAssetId,
        TenantId,
    )


class IAgentOperationalEnvelopeRepository(ABC):
    @abstractmethod
    async def save(self, envelope: AgentOperationalEnvelope) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, envelope_id: AgentOperationalEnvelopeId, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None: ...

    @abstractmethod
    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None: ...

    @abstractmethod
    async def find_active_version_at(
        self, asset_id: AISystemAssetId, at: datetime, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None: ...

    @abstractmethod
    async def save_version_snapshot(self, envelope: AgentOperationalEnvelope) -> None:
        """Retain prior versions for historical deviation evaluation."""
        ...
