"""SqlAlchemy repository for the append-only
ContinuousValidationPolicyLifecycleEvent log (M15).

Receives an active AsyncSession. Never commits — the caller's own unit
of work owns the transaction, matching every other repository in this
codebase. No update()/delete() — append-only, mirroring
SecurityDriftEventRepository's own convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.infrastructure.database.models.security_operations import (
    ContinuousValidationPolicyLifecycleEventModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class PolicyLifecycleEventRow:
    id: str
    organization_id: str
    policy_id: str
    event_type: str
    detail: dict[str, Any]
    occurred_at: datetime


def _to_row(model: ContinuousValidationPolicyLifecycleEventModel) -> PolicyLifecycleEventRow:
    return PolicyLifecycleEventRow(
        id=model.id, organization_id=model.organization_id, policy_id=model.policy_id,
        event_type=model.event_type, detail=model.detail, occurred_at=model.occurred_at,
    )


class SqlAlchemyPolicyLifecycleEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        *,
        event_id: str,
        organization_id: str,
        policy_id: str,
        event_type: str,
        detail: dict[str, Any],
        occurred_at: datetime,
    ) -> None:
        self._session.add(
            ContinuousValidationPolicyLifecycleEventModel(
                id=event_id, organization_id=organization_id, policy_id=policy_id,
                event_type=event_type, detail=detail, occurred_at=occurred_at,
            )
        )
        await self._session.flush()

    async def list_for_organization_since(
        self, organization_id: str, since: datetime, limit: int,
    ) -> list[PolicyLifecycleEventRow]:
        stmt = (
            select(ContinuousValidationPolicyLifecycleEventModel)
            .where(
                ContinuousValidationPolicyLifecycleEventModel.organization_id == organization_id,
                ContinuousValidationPolicyLifecycleEventModel.occurred_at >= since,
            )
            .order_by(ContinuousValidationPolicyLifecycleEventModel.occurred_at)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_to_row(m) for m in result.scalars().all()]
