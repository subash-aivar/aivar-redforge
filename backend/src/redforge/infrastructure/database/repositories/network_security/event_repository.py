"""SqlAlchemy repositories for the append-only NetworkValidationRun and
NetworkMonitoringPolicy lifecycle event logs (M16) — feed the M15
Security Operations projection registry exactly like
validation_execution/event_repository.py and policy_lifecycle_repository.py
do for M11/M14."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.infrastructure.database.models.network_security import (
    NetworkMonitoringPolicyLifecycleEventModel,
    NetworkValidationRunEventModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class NetworkRunEventRow:
    id: str
    organization_id: str
    run_id: str
    event_type: str
    payload: dict[str, str]
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class NetworkPolicyLifecycleEventRow:
    id: str
    organization_id: str
    policy_id: str
    event_type: str
    detail: dict[str, Any]
    occurred_at: datetime


class SqlAlchemyNetworkRunEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self, *, organization_id: str, run_id: str, event_type: str,
        payload: dict[str, str], occurred_at: datetime,
    ) -> None:
        self._session.add(
            NetworkValidationRunEventModel(
                id=str(EntityId.generate()), organization_id=organization_id, run_id=run_id,
                event_type=event_type, payload=payload, occurred_at=occurred_at,
            )
        )
        await self._session.flush()

    async def list_for_organization_since(
        self, organization_id: str, since: datetime, limit: int,
    ) -> list[NetworkRunEventRow]:
        stmt = (
            select(NetworkValidationRunEventModel)
            .where(
                NetworkValidationRunEventModel.organization_id == organization_id,
                NetworkValidationRunEventModel.occurred_at >= since,
            )
            .order_by(NetworkValidationRunEventModel.occurred_at)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [
            NetworkRunEventRow(
                id=m.id, organization_id=m.organization_id, run_id=m.run_id,
                event_type=m.event_type, payload=m.payload, occurred_at=m.occurred_at,
            )
            for m in result.scalars().all()
        ]


class SqlAlchemyNetworkPolicyLifecycleEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self, *, organization_id: str, policy_id: str, event_type: str,
        detail: dict[str, Any], occurred_at: datetime,
    ) -> None:
        self._session.add(
            NetworkMonitoringPolicyLifecycleEventModel(
                id=str(EntityId.generate()), organization_id=organization_id,
                policy_id=policy_id, event_type=event_type, detail=detail,
                occurred_at=occurred_at,
            )
        )
        await self._session.flush()

    async def list_for_organization_since(
        self, organization_id: str, since: datetime, limit: int,
    ) -> list[NetworkPolicyLifecycleEventRow]:
        stmt = (
            select(NetworkMonitoringPolicyLifecycleEventModel)
            .where(
                NetworkMonitoringPolicyLifecycleEventModel.organization_id == organization_id,
                NetworkMonitoringPolicyLifecycleEventModel.occurred_at >= since,
            )
            .order_by(NetworkMonitoringPolicyLifecycleEventModel.occurred_at)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [
            NetworkPolicyLifecycleEventRow(
                id=m.id, organization_id=m.organization_id, policy_id=m.policy_id,
                event_type=m.event_type, detail=m.detail, occurred_at=m.occurred_at,
            )
            for m in result.scalars().all()
        ]
