"""SqlAlchemy repository for the immutable ExecutionPolicyDecision audit
log. Receives an active AsyncSession. NEVER commits or rolls back.

Every decision — ALLOW, DENY, and APPROVAL_REQUIRED alike — is written
here. Rows are never updated or deleted (no update()/delete() method
exists on this repository by design).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.infrastructure.database.models.authorization import (
    SecurityAuthorizationDecisionModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.authorization.value_objects import ExecutionPolicyDecision


class SqlAlchemyExecutionPolicyDecisionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        organization_id: EntityId,
        actor_user_id: EntityId,
        decision: ExecutionPolicyDecision,
        *,
        raw_action_class: str,
    ) -> str:
        decision_id = str(EntityId.generate())
        model = SecurityAuthorizationDecisionModel(
            id=decision_id,
            organization_id=str(organization_id),
            actor_user_id=str(actor_user_id),
            authorization_id=decision.authorization_id,
            action_class=str(decision.action_class) if decision.action_class else None,
            raw_action_class=raw_action_class,
            entity_refs=[
                {"entity_type": str(e.entity_type), "entity_id": e.entity_id}
                for e in decision.entity_refs
            ],
            decision=str(decision.decision),
            reason_code=str(decision.reason_code),
            evaluated_at=decision.evaluated_at,
        )
        self._session.add(model)
        await self._session.flush()
        return decision_id

    async def list_by_organization(
        self, organization_id: EntityId, limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        stmt = (
            select(SecurityAuthorizationDecisionModel)
            .where(SecurityAuthorizationDecisionModel.organization_id == str(organization_id))
            .order_by(SecurityAuthorizationDecisionModel.evaluated_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [
            {
                "id": row.id,
                "organization_id": row.organization_id,
                "actor_user_id": row.actor_user_id,
                "authorization_id": row.authorization_id,
                "action_class": row.action_class,
                "raw_action_class": row.raw_action_class,
                "entity_refs": row.entity_refs,
                "decision": row.decision,
                "reason_code": row.reason_code,
                "evaluated_at": row.evaluated_at.isoformat(),
            }
            for row in rows
        ]
