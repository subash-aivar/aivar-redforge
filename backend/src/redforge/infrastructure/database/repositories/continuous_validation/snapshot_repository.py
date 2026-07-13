"""SqlAlchemy repository for the immutable ValidationStateSnapshot (M14).

Receives an active AsyncSession. NEVER commits or rolls back. No
update()/delete() anywhere — a snapshot is built once and never mutated
(see ValidationStateSnapshot's own docstring).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from redforge.infrastructure.database.mappings.continuous_validation_mapper import (
    snapshot_to_entity,
    snapshot_to_model,
)
from redforge.infrastructure.database.models.continuous_validation import (
    ValidationStateSnapshotModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.continuous_validation.entity import ValidationStateSnapshot
    from redforge.shared.identifiers import EntityId


class SqlAlchemyValidationStateSnapshotRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, snapshot: ValidationStateSnapshot) -> None:
        self._session.add(snapshot_to_model(snapshot))
        await self._session.flush()

    async def get_latest_for_policy(
        self, continuous_policy_id: EntityId, organization_id: EntityId,
    ) -> ValidationStateSnapshot | None:
        stmt = (
            select(ValidationStateSnapshotModel)
            .where(
                ValidationStateSnapshotModel.continuous_policy_id == str(continuous_policy_id),
                ValidationStateSnapshotModel.organization_id == str(organization_id),
            )
            .order_by(ValidationStateSnapshotModel.captured_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return snapshot_to_entity(model) if model is not None else None
