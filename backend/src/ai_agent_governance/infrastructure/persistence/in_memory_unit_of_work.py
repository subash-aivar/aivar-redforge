from __future__ import annotations

import copy
from typing import TYPE_CHECKING

from ai_agent_governance.application.ports.i_unit_of_work import IUnitOfWork
from ai_agent_governance.domain.repositories.i_agent_deviation_event_repository import (
    IAgentDeviationEventRepository,
)
from ai_agent_governance.domain.repositories.i_agent_operational_envelope_repository import (
    IAgentOperationalEnvelopeRepository,
)
from ai_agent_governance.domain.value_objects.enums import ReviewState

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

    from ai_agent_governance.domain.aggregates.agent_deviation_event import (
        AgentDeviationEvent,
    )
    from ai_agent_governance.domain.aggregates.agent_operational_envelope import (
        AgentOperationalEnvelope,
    )
    from ai_agent_governance.domain.value_objects.identifiers import (
        AgentDeviationEventId,
        AgentOperationalEnvelopeId,
        AISystemAssetId,
        TenantId,
    )


class InMemoryEnvelopeRepository(IAgentOperationalEnvelopeRepository):
    def __init__(self) -> None:
        self.current: dict[str, AgentOperationalEnvelope] = {}
        self.versions: list[AgentOperationalEnvelope] = []

    async def save(self, envelope: AgentOperationalEnvelope) -> None:
        self.current[str(envelope.envelope_id)] = envelope

    async def save_version_snapshot(self, envelope: AgentOperationalEnvelope) -> None:
        for prior in self.versions:
            if (
                prior.tenant_id == envelope.tenant_id
                and prior.ai_system_asset_id == envelope.ai_system_asset_id
                and prior.envelope_version < envelope.envelope_version
                and prior.effective_until is None
            ):
                prior.effective_until = envelope.effective_from
        self.versions.append(copy.deepcopy(envelope))

    async def find_by_id(
        self, envelope_id: AgentOperationalEnvelopeId, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None:
        env = self.current.get(str(envelope_id))
        if env is None or env.tenant_id != tenant_id:
            return None
        return env

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None:
        for env in self.current.values():
            if env.tenant_id == tenant_id and env.ai_system_asset_id == asset_id:
                return env
        return None

    async def find_active_version_at(
        self, asset_id: AISystemAssetId, at: datetime, tenant_id: TenantId
    ) -> AgentOperationalEnvelope | None:
        candidates = [
            e
            for e in self.versions
            if e.tenant_id == tenant_id
            and e.ai_system_asset_id == asset_id
            and e.is_effective_at(at)
        ]
        if not candidates:
            # fallback to current if effective
            current = await self.find_by_asset(asset_id, tenant_id)
            if current is not None and current.is_effective_at(at):
                return current
            return None
        candidates.sort(key=lambda e: (e.effective_from, e.envelope_version), reverse=True)
        return candidates[0]


class InMemoryDeviationRepository(IAgentDeviationEventRepository):
    def __init__(self) -> None:
        self.items: dict[str, AgentDeviationEvent] = {}
        self.idempotency: dict[tuple[str, str], str] = {}

    async def save(self, deviation: AgentDeviationEvent) -> None:
        self.items[str(deviation.deviation_id)] = deviation

    async def find_by_id(
        self, deviation_id: AgentDeviationEventId, tenant_id: TenantId
    ) -> AgentDeviationEvent | None:
        d = self.items.get(str(deviation_id))
        if d is None or d.tenant_id != tenant_id:
            return None
        return d

    async def find_unreviewed_by_tenant(self, tenant_id: TenantId) -> list[AgentDeviationEvent]:
        return [
            d
            for d in self.items.values()
            if d.tenant_id == tenant_id and d.review_state == ReviewState.UNREVIEWED
        ]

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId, limit: int
    ) -> list[AgentDeviationEvent]:
        items = [
            d
            for d in self.items.values()
            if d.tenant_id == tenant_id and d.ai_system_asset_id == asset_id
        ]
        items.sort(key=lambda d: d.detected_at, reverse=True)
        return items[:limit]

    async def find_by_idempotency_key(
        self, tenant_id: TenantId, idempotency_key: str
    ) -> AgentDeviationEvent | None:
        for d in self.items.values():
            if d.tenant_id == tenant_id and d.observed_action.idempotency_key == idempotency_key:
                return d
        return None

    async def record_idempotent_action(
        self, tenant_id: TenantId, idempotency_key: str, result: str
    ) -> bool:
        key = (str(tenant_id), idempotency_key)
        if key in self.idempotency and self.idempotency[key] != "pending":
            return False
        if key in self.idempotency and result == "pending":
            return False
        self.idempotency[key] = result
        return True


class InMemoryUnitOfWork(IUnitOfWork):
    def __init__(self) -> None:
        super().__init__()
        self.envelopes = InMemoryEnvelopeRepository()
        self.deviations = InMemoryDeviationRepository()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        pass

    async def __aenter__(self) -> InMemoryUnitOfWork:
        self._committed = False
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None or not self._committed:
            await self.rollback()
