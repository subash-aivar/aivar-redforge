"""NetworkMonitoringPolicyService — M16. Application-layer lifecycle
operations for NetworkMonitoringPolicy, mirroring
application/continuous_validation/policy_service.py's own shape."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.core.exceptions import NotFoundError, ValidationError
from redforge.domain.network_security.entity import NetworkMonitoringPolicy
from redforge.domain.network_security.exceptions import NetworkMonitoringPolicyNotFoundError
from redforge.domain.network_security.value_objects import (
    NetworkValidationProfile,
    PolicyLifecycle,
    ValidationCadence,
)
from redforge.infrastructure.database.repositories.network_security.event_repository import (
    SqlAlchemyNetworkPolicyLifecycleEventRepository,
)
from redforge.infrastructure.database.repositories.network_security.policy_repository import (
    SqlAlchemyNetworkMonitoringPolicyRepository,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class NetworkMonitoringPolicyDTO:
    id: str
    organization_id: str
    target_asset_id: str
    requester_user_id: str
    profile: str
    cadence: str
    lifecycle: str
    next_due_at: str | None
    last_scheduled_at: str | None


def _to_dto(policy: NetworkMonitoringPolicy) -> NetworkMonitoringPolicyDTO:
    return NetworkMonitoringPolicyDTO(
        id=str(policy.id), organization_id=str(policy.organization_id),
        target_asset_id=str(policy.target_asset_id),
        requester_user_id=str(policy.requester_user_id), profile=str(policy.profile),
        cadence=str(policy.cadence), lifecycle=str(policy.lifecycle),
        next_due_at=policy.next_due_at.isoformat() if policy.next_due_at else None,
        last_scheduled_at=policy.last_scheduled_at.isoformat()
        if policy.last_scheduled_at else None,
    )


class NetworkMonitoringPolicyService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(
        self,
        organization_id: str,
        target_asset_id: str,
        requester_user_id: str,
        profile: NetworkValidationProfile,
        cadence: ValidationCadence,
    ) -> NetworkMonitoringPolicyDTO:
        try:
            safe_target_asset_id = EntityId.from_string(target_asset_id)
        except ValueError as exc:
            raise ValidationError(f"Invalid target_asset_id: '{target_asset_id}'") from exc

        policy = NetworkMonitoringPolicy.create(
            organization_id=EntityId.from_string(organization_id),
            target_asset_id=safe_target_asset_id,
            requester_user_id=EntityId.from_string(requester_user_id),
            profile=profile, cadence=cadence,
        )
        await self._save_and_log(policy, "created")
        return _to_dto(policy)

    async def get_for_org(self, policy_id: str, organization_id: str) -> NetworkMonitoringPolicyDTO:
        policy = await self._get(policy_id, organization_id)
        return _to_dto(policy)

    async def list_for_org(
        self, organization_id: str, lifecycle: str | None = None,
        limit: int = 100, offset: int = 0,
    ) -> list[NetworkMonitoringPolicyDTO]:
        safe_lifecycle: PolicyLifecycle | None = None
        if lifecycle:
            try:
                safe_lifecycle = PolicyLifecycle(lifecycle)
            except ValueError as exc:
                raise ValidationError(f"Invalid lifecycle filter: '{lifecycle}'") from exc

        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            policies = await repo.list_for_organization(
                EntityId.from_string(organization_id), safe_lifecycle, limit, offset,
            )
        return [_to_dto(p) for p in policies]

    async def activate(self, policy_id: str, organization_id: str) -> NetworkMonitoringPolicyDTO:
        policy = await self._get(policy_id, organization_id)
        policy.activate(utc_now())
        await self._save_and_log(policy, "activated")
        return _to_dto(policy)

    async def pause(self, policy_id: str, organization_id: str) -> NetworkMonitoringPolicyDTO:
        policy = await self._get(policy_id, organization_id)
        policy.pause(utc_now())
        await self._save_and_log(policy, "paused")
        return _to_dto(policy)

    async def resume(self, policy_id: str, organization_id: str) -> NetworkMonitoringPolicyDTO:
        policy = await self._get(policy_id, organization_id)
        policy.resume(utc_now())
        await self._save_and_log(policy, "resumed")
        return _to_dto(policy)

    async def disable(self, policy_id: str, organization_id: str) -> NetworkMonitoringPolicyDTO:
        policy = await self._get(policy_id, organization_id)
        policy.disable(utc_now())
        await self._save_and_log(policy, "disabled")
        return _to_dto(policy)

    async def _get(self, policy_id: str, organization_id: str) -> NetworkMonitoringPolicy:
        try:
            safe_policy_id = EntityId.from_string(policy_id)
            safe_org_id = EntityId.from_string(organization_id)
        except ValueError as exc:
            raise NetworkMonitoringPolicyNotFoundError(policy_id) from exc
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            policy = await repo.get_by_id_for_organization(safe_policy_id, safe_org_id)
        if policy is None:
            raise NotFoundError("NetworkMonitoringPolicy", policy_id)
        return policy

    async def _save_and_log(self, policy: NetworkMonitoringPolicy, event_type: str) -> None:
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            await repo.save(policy)
            event_repo = SqlAlchemyNetworkPolicyLifecycleEventRepository(session)
            await event_repo.append(
                organization_id=str(policy.organization_id), policy_id=str(policy.id),
                event_type=event_type, detail={}, occurred_at=utc_now(),
            )
            await session.commit()
        policy.collect_events()
