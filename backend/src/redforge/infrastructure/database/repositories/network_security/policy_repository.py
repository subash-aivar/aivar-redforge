"""SqlAlchemy repository for the NetworkMonitoringPolicy aggregate (M16).

Mirrors infrastructure/database/repositories/continuous_validation/
repository.py exactly (same claim idiom, same row-lock discipline).
Receives an active AsyncSession; never commits.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, or_, select, update

from redforge.domain.network_security.entity import NetworkMonitoringPolicy
from redforge.domain.network_security.value_objects import (
    CLAIM_LEASE_SECONDS,
    NetworkValidationProfile,
    PolicyLifecycle,
    ValidationCadence,
)
from redforge.infrastructure.database.models.network_security import (
    NetworkMonitoringPolicyModel,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


def _to_entity(model: NetworkMonitoringPolicyModel) -> NetworkMonitoringPolicy:
    return NetworkMonitoringPolicy(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        target_asset_id=EntityId.from_string(model.target_asset_id),
        requester_user_id=EntityId.from_string(model.requester_user_id),
        profile=NetworkValidationProfile(model.profile),
        cadence=ValidationCadence(model.cadence),
        lifecycle=PolicyLifecycle(model.lifecycle),
        timestamps=AuditTimestamps(created_at=model.created_at, updated_at=model.updated_at),
        next_due_at=model.next_due_at,
        last_scheduled_at=model.last_scheduled_at,
        claimed_at=model.claimed_at,
        claim_owner=model.claim_owner,
    )


def _to_model(policy: NetworkMonitoringPolicy) -> NetworkMonitoringPolicyModel:
    return NetworkMonitoringPolicyModel(
        id=str(policy.id),
        organization_id=str(policy.organization_id),
        target_asset_id=str(policy.target_asset_id),
        requester_user_id=str(policy.requester_user_id),
        profile=str(policy.profile),
        cadence=str(policy.cadence),
        lifecycle=str(policy.lifecycle),
        next_due_at=policy.next_due_at,
        last_scheduled_at=policy.last_scheduled_at,
        claimed_at=policy.claimed_at,
        claim_owner=policy.claim_owner,
        created_at=policy.timestamps.created_at,
        updated_at=policy.timestamps.updated_at,
    )


class SqlAlchemyNetworkMonitoringPolicyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id_for_organization(
        self, policy_id: EntityId, organization_id: EntityId,
    ) -> NetworkMonitoringPolicy | None:
        model = await self._get_model(str(policy_id), str(organization_id))
        return _to_entity(model) if model is not None else None

    async def get_by_id_for_organization_for_update(
        self, policy_id: EntityId, organization_id: EntityId,
    ) -> NetworkMonitoringPolicy | None:
        model = await self._get_model(str(policy_id), str(organization_id), for_update=True)
        return _to_entity(model) if model is not None else None

    async def list_for_organization(
        self,
        organization_id: EntityId,
        lifecycle: PolicyLifecycle | None,
        limit: int,
        offset: int,
    ) -> list[NetworkMonitoringPolicy]:
        stmt = select(NetworkMonitoringPolicyModel).where(
            NetworkMonitoringPolicyModel.organization_id == str(organization_id)
        )
        if lifecycle is not None:
            stmt = stmt.where(NetworkMonitoringPolicyModel.lifecycle == str(lifecycle))
        stmt = (
            stmt.order_by(NetworkMonitoringPolicyModel.created_at.desc())
            .limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_to_entity(m) for m in result.scalars().all()]

    async def count_for_organization(
        self, organization_id: EntityId, lifecycle: PolicyLifecycle | None,
    ) -> int:
        stmt = select(func.count(NetworkMonitoringPolicyModel.id)).where(
            NetworkMonitoringPolicyModel.organization_id == str(organization_id)
        )
        if lifecycle is not None:
            stmt = stmt.where(NetworkMonitoringPolicyModel.lifecycle == str(lifecycle))
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def save(self, policy: NetworkMonitoringPolicy) -> None:
        existing = await self._get_model(str(policy.id), str(policy.organization_id))
        model = _to_model(policy)
        if existing is None:
            self._session.add(model)
        else:
            existing.lifecycle = model.lifecycle
            existing.next_due_at = model.next_due_at
            existing.last_scheduled_at = model.last_scheduled_at
            existing.claimed_at = model.claimed_at
            existing.claim_owner = model.claim_owner
            existing.updated_at = model.updated_at
        await self._session.flush()

    async def claim_one_due_policy(
        self, now: datetime, worker_id: str, lease_seconds: int = CLAIM_LEASE_SECONDS,
    ) -> NetworkMonitoringPolicy | None:
        """Atomically claim exactly one due, unclaimed-or-lease-expired
        ACTIVE policy — identical `UPDATE ... WHERE id = (SELECT ... FOR
        UPDATE SKIP LOCKED) RETURNING *` idiom as M14's own claim.
        Postgres-only."""
        lease_cutoff = now - timedelta(seconds=lease_seconds)
        candidate = (
            select(NetworkMonitoringPolicyModel.id)
            .where(
                NetworkMonitoringPolicyModel.lifecycle == str(PolicyLifecycle.ACTIVE),
                NetworkMonitoringPolicyModel.next_due_at <= now,
                or_(
                    NetworkMonitoringPolicyModel.claimed_at.is_(None),
                    NetworkMonitoringPolicyModel.claimed_at < lease_cutoff,
                ),
            )
            .order_by(NetworkMonitoringPolicyModel.next_due_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        stmt = (
            update(NetworkMonitoringPolicyModel)
            .where(NetworkMonitoringPolicyModel.id == candidate)
            .values(claimed_at=now, claim_owner=worker_id)
            .returning(NetworkMonitoringPolicyModel)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        await self._session.flush()
        return _to_entity(model) if model is not None else None

    async def _get_model(
        self, policy_id: str, organization_id: str, *, for_update: bool = False,
    ) -> NetworkMonitoringPolicyModel | None:
        stmt = select(NetworkMonitoringPolicyModel).where(
            NetworkMonitoringPolicyModel.id == policy_id,
            NetworkMonitoringPolicyModel.organization_id == organization_id,
        )
        if for_update:
            stmt = stmt.with_for_update()
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
