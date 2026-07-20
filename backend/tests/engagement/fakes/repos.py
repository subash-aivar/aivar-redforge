"""In-memory fakes for engagement application / repository contract tests."""

from __future__ import annotations

from types import TracebackType
from typing import Self
from uuid import UUID

from engagement.application.ports.i_event_publisher import IEventPublisher
from engagement.application.ports.i_unit_of_work import IUnitOfWork
from engagement.domain.aggregates.engagement import Engagement
from engagement.domain.aggregates.target_authorization import TargetAuthorization
from engagement.domain.events.base import BaseDomainEvent
from engagement.domain.ports.i_asset_query_port import IAssetQueryPort
from engagement.domain.ports.i_digital_signature_port import IDigitalSignaturePort
from engagement.domain.repositories.i_engagement_repository import IEngagementRepository
from engagement.domain.repositories.i_target_authorization_repository import (
    ITargetAuthorizationRepository,
)
from engagement.domain.value_objects.engagement_vos import TargetRef
from engagement.domain.value_objects.enums import AuthorizationState, EngagementState
from engagement.domain.value_objects.identifiers import (
    EngagementId,
    TargetAuthorizationId,
    TenantId,
)


class InMemoryEngagementRepository(IEngagementRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], Engagement] = {}

    async def save(self, engagement: Engagement) -> None:
        self.by_id[(engagement.engagement_id.value, engagement.tenant_id.value)] = engagement

    async def find_by_id(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> Engagement | None:
        return self.by_id.get((engagement_id.value, tenant_id.value))

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[Engagement]:
        return [
            e
            for (_, tid), e in self.by_id.items()
            if tid == tenant_id.value and e.state == EngagementState.ACTIVE
        ]

    async def find_by_state(
        self,
        state: EngagementState,
        tenant_id: TenantId,
    ) -> list[Engagement]:
        return [
            e
            for (_, tid), e in self.by_id.items()
            if tid == tenant_id.value and e.state == state
        ]


class InMemoryTargetAuthorizationRepository(ITargetAuthorizationRepository):
    def __init__(self) -> None:
        self.by_id: dict[tuple[UUID, UUID], TargetAuthorization] = {}

    async def save(self, authorization: TargetAuthorization) -> None:
        self.by_id[
            (authorization.authorization_id.value, authorization.tenant_id.value)
        ] = authorization

    async def find_by_id(
        self,
        authorization_id: TargetAuthorizationId,
        tenant_id: TenantId,
    ) -> TargetAuthorization | None:
        return self.by_id.get((authorization_id.value, tenant_id.value))

    async def find_active_for_target(
        self,
        target_ref: TargetRef,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> TargetAuthorization | None:
        for auth in self.by_id.values():
            if (
                auth.tenant_id == tenant_id
                and auth.engagement_id == engagement_id
                and auth.target_ref.asset_id == target_ref.asset_id
                and auth.state == AuthorizationState.ACTIVE
            ):
                return auth
        return None

    async def find_by_engagement(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> list[TargetAuthorization]:
        return [
            a
            for a in self.by_id.values()
            if a.tenant_id == tenant_id and a.engagement_id == engagement_id
        ]


class FakeEngagementUnitOfWork(IUnitOfWork):
    def __init__(
        self,
        engagements: InMemoryEngagementRepository | None = None,
        authorizations: InMemoryTargetAuthorizationRepository | None = None,
    ) -> None:
        super().__init__()
        self.engagements = engagements or InMemoryEngagementRepository()
        self.target_authorizations = authorizations or InMemoryTargetAuthorizationRepository()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class FakeEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published: list[BaseDomainEvent] = []

    async def publish(self, event: BaseDomainEvent) -> None:
        self.published.append(event)

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published.extend(events)


class FakeAssetQueryPort(IAssetQueryPort):
    def __init__(self, names: dict[UUID, str] | None = None) -> None:
        self.names = names or {}

    async def resolve_target_ref(
        self,
        asset_id: UUID,
        tenant_id: TenantId,
    ) -> TargetRef | None:
        name = self.names.get(asset_id)
        return TargetRef(asset_id=asset_id, display_name=name)


class FakeDigitalSignaturePort(IDigitalSignaturePort):
    def sign(self, payload: str) -> str:
        return f"signed:{payload}"

    def verify(self, payload: str, signature: str, identity: str) -> bool:
        return signature == self.sign(payload)
