"""SqlAlchemy repository for the SecurityAuthorization aggregate.

Receives an active AsyncSession. NEVER commits or rolls back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import delete, func, select

from redforge.infrastructure.database.mappings.authorization_mapper import (
    authorization_to_entity,
    authorization_to_model,
    scope_to_models,
)
from redforge.infrastructure.database.models.authorization import (
    SecurityAuthorizationModel,
    SecurityAuthorizationScopeModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.authorization.entity import SecurityAuthorization
    from redforge.domain.authorization.value_objects import AuthorizationStatus
    from redforge.shared.identifiers import EntityId


class SqlAlchemySecurityAuthorizationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id_for_organization(
        self, authorization_id: EntityId, organization_id: EntityId
    ) -> SecurityAuthorization | None:
        model = await self._get_model(str(authorization_id), str(organization_id))
        if model is None:
            return None
        scope_models = await self._scope_models(str(authorization_id))
        return authorization_to_entity(model, scope_models)

    async def get_by_id_for_organization_for_update(
        self, authorization_id: EntityId, organization_id: EntityId
    ) -> SecurityAuthorization | None:
        """Locked read (SELECT ... FOR UPDATE against PostgreSQL). Any
        caller about to transition lifecycle status (approve/reject/
        revoke) under potential concurrency must use this instead of
        get_by_id_for_organization — see approval_repository's sibling
        method for the full race-freedom reasoning."""
        model = await self._get_model(
            str(authorization_id), str(organization_id), for_update=True,
        )
        if model is None:
            return None
        scope_models = await self._scope_models(str(authorization_id))
        return authorization_to_entity(model, scope_models)

    async def list_by_organization(
        self,
        organization_id: EntityId,
        status: AuthorizationStatus | None,
        limit: int,
        offset: int,
    ) -> list[SecurityAuthorization]:
        stmt = select(SecurityAuthorizationModel).where(
            SecurityAuthorizationModel.organization_id == str(organization_id)
        )
        if status is not None:
            stmt = stmt.where(SecurityAuthorizationModel.status == str(status))
        stmt = (
            stmt.order_by(SecurityAuthorizationModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        models = list(result.scalars().all())

        entities: list[SecurityAuthorization] = []
        for model in models:
            scope_models = await self._scope_models(model.id)
            entities.append(authorization_to_entity(model, scope_models))
        return entities

    async def count_by_status(self, organization_id: EntityId) -> dict[str, int]:
        """Backend-derived counts per AuthorizationStatus for one
        organization. Never a client-computed/fabricated aggregate —
        this is a real GROUP BY COUNT against the persisted rows."""
        stmt = (
            select(SecurityAuthorizationModel.status, func.count())
            .where(SecurityAuthorizationModel.organization_id == str(organization_id))
            .group_by(SecurityAuthorizationModel.status)
        )
        result = await self._session.execute(stmt)
        return {status: count for status, count in result.all()}

    async def find_active_covering(
        self, organization_id: EntityId
    ) -> list[SecurityAuthorization]:
        from redforge.domain.authorization.value_objects import AuthorizationStatus

        return await self.list_by_organization(
            organization_id, AuthorizationStatus.ACTIVE, limit=1000, offset=0,
        )

    async def save(self, authorization: SecurityAuthorization) -> None:
        existing = await self._get_model(str(authorization.id), str(authorization.organization_id))
        model = authorization_to_model(authorization)
        if existing is None:
            self._session.add(model)
        else:
            existing.status = model.status
            existing.action_classes = model.action_classes
            existing.valid_from = model.valid_from
            existing.valid_until = model.valid_until
            existing.updated_at = model.updated_at

        # Scope is only mutated while DRAFT (see SecurityAuthorization's
        # invariants) — replacing it wholesale on every save is simple
        # and correct given that low-frequency, single-writer usage
        # pattern (no need for incremental diffing).
        await self._session.execute(
            delete(SecurityAuthorizationScopeModel).where(
                SecurityAuthorizationScopeModel.authorization_id == str(authorization.id)
            )
        )
        for scope_model in scope_to_models(authorization):
            self._session.add(scope_model)

        await self._session.flush()

    async def _get_model(
        self, authorization_id: str, organization_id: str, *, for_update: bool = False,
    ) -> SecurityAuthorizationModel | None:
        stmt = select(SecurityAuthorizationModel).where(
            SecurityAuthorizationModel.id == authorization_id,
            SecurityAuthorizationModel.organization_id == organization_id,
        )
        if for_update:
            stmt = stmt.with_for_update()
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def _scope_models(
        self, authorization_id: str
    ) -> list[SecurityAuthorizationScopeModel]:
        stmt = select(SecurityAuthorizationScopeModel).where(
            SecurityAuthorizationScopeModel.authorization_id == authorization_id
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
