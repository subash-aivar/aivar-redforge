"""SqlAlchemy repository for the AuthorizationApproval entity.

Receives an active AsyncSession. NEVER commits or rolls back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from redforge.infrastructure.database.mappings.authorization_mapper import (
    approval_to_entity,
    approval_to_model,
)
from redforge.infrastructure.database.models.authorization import (
    SecurityAuthorizationApprovalModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.authorization.entity import AuthorizationApproval
    from redforge.shared.identifiers import EntityId


class SqlAlchemyAuthorizationApprovalRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_authorization_id(
        self, authorization_id: EntityId, organization_id: EntityId
    ) -> AuthorizationApproval | None:
        stmt = select(SecurityAuthorizationApprovalModel).where(
            SecurityAuthorizationApprovalModel.authorization_id == str(authorization_id),
            SecurityAuthorizationApprovalModel.organization_id == str(organization_id),
        ).order_by(SecurityAuthorizationApprovalModel.requested_at.desc())
        result = await self._session.execute(stmt)
        model = result.scalars().first()
        return approval_to_entity(model) if model is not None else None

    async def get_by_authorization_id_for_update(
        self, authorization_id: EntityId, organization_id: EntityId
    ) -> AuthorizationApproval | None:
        """Same as get_by_authorization_id, but takes a row lock (SELECT
        ... FOR UPDATE) held for the rest of the caller's transaction.

        This is what makes concurrent approve()/reject() calls on the
        SAME authorization race-free: the second concurrent transaction
        blocks here until the first commits or rolls back, then its
        read observes the winner's already-decided state — so
        AuthorizationApproval.decide() raises ApprovalAlreadyDecidedError
        for the loser instead of silently overwriting the winner's
        decision. (SQLite, used in unit/isolation tests, does not
        support row locking and silently ignores this — the guarantee
        is real only against PostgreSQL; see
        tests/integration/test_authorization_race.py.)
        """
        stmt = (
            select(SecurityAuthorizationApprovalModel)
            .where(
                SecurityAuthorizationApprovalModel.authorization_id == str(authorization_id),
                SecurityAuthorizationApprovalModel.organization_id == str(organization_id),
            )
            .order_by(SecurityAuthorizationApprovalModel.requested_at.desc())
            .with_for_update()
        )
        result = await self._session.execute(stmt)
        model = result.scalars().first()
        return approval_to_entity(model) if model is not None else None

    async def save(self, approval: AuthorizationApproval) -> None:
        stmt = select(SecurityAuthorizationApprovalModel).where(
            SecurityAuthorizationApprovalModel.id == str(approval.id)
        )
        result = await self._session.execute(stmt)
        existing = result.scalar_one_or_none()
        model = approval_to_model(approval)
        if existing is None:
            self._session.add(model)
        else:
            existing.approver_user_id = model.approver_user_id
            existing.decision = model.decision
            existing.reason = model.reason
            existing.decided_at = model.decided_at
        await self._session.flush()
