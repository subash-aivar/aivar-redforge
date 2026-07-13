"""SqlAlchemy repositories for the RBAC bounded context — M17.

Three repositories, one file (mirrors models/rbac.py's own multi-class
grouping): roles, groups, and a read-only query repository used by
api/security.py's `get_tenant_context` enrichment (effective additional
permissions) and by the Access Explorer read model.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import delete, insert, select
from sqlalchemy.exc import IntegrityError

from redforge.domain.identity.value_objects import Permission
from redforge.domain.rbac.entity import OrganizationGroup, OrganizationRole, normalize_name
from redforge.infrastructure.database.mappings import rbac_mapper
from redforge.infrastructure.database.models.rbac import (
    OrganizationGroupMembershipModel,
    OrganizationGroupModel,
    OrganizationGroupRoleModel,
    OrganizationRoleModel,
    OrganizationRolePermissionModel,
    OrganizationUserRoleModel,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class DuplicateAssignmentError(Exception):
    """Raised when a unique-constrained join row already exists —
    callers treat this as an idempotent no-op, never a 500."""


class SqlAlchemyRoleRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id_for_organization(
        self, role_id: EntityId, organization_id: EntityId,
    ) -> OrganizationRole | None:
        model = await self._get_model(str(role_id), str(organization_id))
        if model is None:
            return None
        return rbac_mapper.role_to_entity(model, await self._permissions_for(model.id))

    async def get_by_normalized_name(
        self, organization_id: EntityId, normalized: str,
    ) -> OrganizationRole | None:
        stmt = select(OrganizationRoleModel).where(
            OrganizationRoleModel.organization_id == str(organization_id),
            OrganizationRoleModel.normalized_name == normalized,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return rbac_mapper.role_to_entity(model, await self._permissions_for(model.id))

    async def list_for_organization(self, organization_id: EntityId) -> list[OrganizationRole]:
        stmt = select(OrganizationRoleModel).where(
            OrganizationRoleModel.organization_id == str(organization_id),
        ).order_by(OrganizationRoleModel.name.asc())
        result = await self._session.execute(stmt)
        models = result.scalars().all()
        roles = []
        for m in models:
            roles.append(rbac_mapper.role_to_entity(m, await self._permissions_for(m.id)))
        return roles

    async def save(self, role: OrganizationRole) -> None:
        model = rbac_mapper.role_to_model(role, normalize_name(role.name))
        await self._session.merge(model)
        # Permissions are replaced wholesale on every save — the role's
        # in-memory `permissions` frozenset is always the full desired
        # state, never a delta, so delete+reinsert is correct and simple.
        await self._session.execute(
            delete(OrganizationRolePermissionModel).where(
                OrganizationRolePermissionModel.role_id == str(role.id),
            )
        )
        for perm in role.permissions:
            await self._session.execute(
                insert(OrganizationRolePermissionModel).values(
                    role_id=str(role.id), permission=perm.value,
                )
            )
        await self._session.flush()

    async def delete(self, role_id: EntityId, organization_id: EntityId) -> None:
        await self._session.execute(
            delete(OrganizationRoleModel).where(
                OrganizationRoleModel.id == str(role_id),
                OrganizationRoleModel.organization_id == str(organization_id),
            )
        )
        await self._session.flush()

    async def count_assignments(self, role_id: EntityId) -> int:
        direct_stmt = select(OrganizationUserRoleModel.id).where(
            OrganizationUserRoleModel.role_id == str(role_id),
        )
        group_stmt = select(OrganizationGroupRoleModel.id).where(
            OrganizationGroupRoleModel.role_id == str(role_id),
        )
        direct = (await self._session.execute(direct_stmt)).all()
        group = (await self._session.execute(group_stmt)).all()
        return len(direct) + len(group)

    async def _permissions_for(self, role_id: str) -> frozenset[Permission]:
        stmt = select(OrganizationRolePermissionModel.permission).where(
            OrganizationRolePermissionModel.role_id == role_id,
        )
        result = await self._session.execute(stmt)
        return frozenset(Permission(p) for p in result.scalars().all())

    async def _get_model(
        self, role_id: str, organization_id: str,
    ) -> OrganizationRoleModel | None:
        stmt = select(OrganizationRoleModel).where(
            OrganizationRoleModel.id == role_id,
            OrganizationRoleModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def assign_direct_role(
        self, organization_id: EntityId, user_id: EntityId, role_id: EntityId,
    ) -> None:
        try:
            await self._session.execute(
                insert(OrganizationUserRoleModel).values(
                    id=str(EntityId.generate()), organization_id=str(organization_id),
                    user_id=str(user_id), role_id=str(role_id), assigned_at=utc_now(),
                )
            )
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise DuplicateAssignmentError from exc

    async def revoke_direct_role(
        self, organization_id: EntityId, user_id: EntityId, role_id: EntityId,
    ) -> None:
        await self._session.execute(
            delete(OrganizationUserRoleModel).where(
                OrganizationUserRoleModel.organization_id == str(organization_id),
                OrganizationUserRoleModel.user_id == str(user_id),
                OrganizationUserRoleModel.role_id == str(role_id),
            )
        )
        await self._session.flush()

    async def list_direct_role_ids_for_user(
        self, organization_id: EntityId, user_id: EntityId,
    ) -> list[str]:
        stmt = select(OrganizationUserRoleModel.role_id).where(
            OrganizationUserRoleModel.organization_id == str(organization_id),
            OrganizationUserRoleModel.user_id == str(user_id),
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class SqlAlchemyGroupRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id_for_organization(
        self, group_id: EntityId, organization_id: EntityId,
    ) -> OrganizationGroup | None:
        model = await self._get_model(str(group_id), str(organization_id))
        return rbac_mapper.group_to_entity(model) if model is not None else None

    async def get_by_normalized_name(
        self, organization_id: EntityId, normalized: str,
    ) -> OrganizationGroup | None:
        stmt = select(OrganizationGroupModel).where(
            OrganizationGroupModel.organization_id == str(organization_id),
            OrganizationGroupModel.normalized_name == normalized,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return rbac_mapper.group_to_entity(model) if model is not None else None

    async def list_for_organization(self, organization_id: EntityId) -> list[OrganizationGroup]:
        stmt = select(OrganizationGroupModel).where(
            OrganizationGroupModel.organization_id == str(organization_id),
        ).order_by(OrganizationGroupModel.name.asc())
        result = await self._session.execute(stmt)
        return [rbac_mapper.group_to_entity(m) for m in result.scalars().all()]

    async def save(self, group: OrganizationGroup) -> None:
        model = rbac_mapper.group_to_model(group, normalize_name(group.name))
        await self._session.merge(model)
        await self._session.flush()

    async def delete(self, group_id: EntityId, organization_id: EntityId) -> None:
        await self._session.execute(
            delete(OrganizationGroupModel).where(
                OrganizationGroupModel.id == str(group_id),
                OrganizationGroupModel.organization_id == str(organization_id),
            )
        )
        await self._session.flush()

    async def _get_model(
        self, group_id: str, organization_id: str,
    ) -> OrganizationGroupModel | None:
        stmt = select(OrganizationGroupModel).where(
            OrganizationGroupModel.id == group_id,
            OrganizationGroupModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def add_member(
        self, organization_id: EntityId, group_id: EntityId, user_id: EntityId,
    ) -> None:
        try:
            await self._session.execute(
                insert(OrganizationGroupMembershipModel).values(
                    id=str(EntityId.generate()), organization_id=str(organization_id),
                    group_id=str(group_id), user_id=str(user_id), added_at=utc_now(),
                )
            )
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise DuplicateAssignmentError from exc

    async def remove_member(self, group_id: EntityId, user_id: EntityId) -> None:
        await self._session.execute(
            delete(OrganizationGroupMembershipModel).where(
                OrganizationGroupMembershipModel.group_id == str(group_id),
                OrganizationGroupMembershipModel.user_id == str(user_id),
            )
        )
        await self._session.flush()

    async def list_member_ids(self, group_id: EntityId) -> list[str]:
        stmt = select(OrganizationGroupMembershipModel.user_id).where(
            OrganizationGroupMembershipModel.group_id == str(group_id),
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_members(self, group_id: EntityId) -> int:
        return len(await self.list_member_ids(group_id))

    async def list_group_ids_for_user(
        self, organization_id: EntityId, user_id: EntityId,
    ) -> list[str]:
        stmt = select(OrganizationGroupMembershipModel.group_id).where(
            OrganizationGroupMembershipModel.organization_id == str(organization_id),
            OrganizationGroupMembershipModel.user_id == str(user_id),
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def assign_role(
        self, organization_id: EntityId, group_id: EntityId, role_id: EntityId,
    ) -> None:
        try:
            await self._session.execute(
                insert(OrganizationGroupRoleModel).values(
                    id=str(EntityId.generate()), organization_id=str(organization_id),
                    group_id=str(group_id), role_id=str(role_id), assigned_at=utc_now(),
                )
            )
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise DuplicateAssignmentError from exc

    async def revoke_role(self, group_id: EntityId, role_id: EntityId) -> None:
        await self._session.execute(
            delete(OrganizationGroupRoleModel).where(
                OrganizationGroupRoleModel.group_id == str(group_id),
                OrganizationGroupRoleModel.role_id == str(role_id),
            )
        )
        await self._session.flush()

    async def list_role_ids_for_group(self, group_id: EntityId) -> list[str]:
        stmt = select(OrganizationGroupRoleModel.role_id).where(
            OrganizationGroupRoleModel.group_id == str(group_id),
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class SqlAlchemyRbacQueryRepository:
    """Read-only cross-cutting queries used by effective-access
    calculation and by `get_tenant_context`'s per-request enrichment."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_additional_permissions(
        self, organization_id: EntityId, user_id: EntityId,
    ) -> frozenset[Permission]:
        """Union of (a) permissions from custom roles assigned DIRECTLY
        to this user, and (b) permissions from custom roles assigned to
        any group this user belongs to — both scoped to this
        organization. Returns an EMPTY set (near-zero query cost, no
        behavior change) for the overwhelming majority of
        organizations that have not configured any M17 custom
        roles/groups yet."""
        direct_stmt = (
            select(OrganizationRolePermissionModel.permission)
            .join(
                OrganizationUserRoleModel,
                OrganizationUserRoleModel.role_id == OrganizationRolePermissionModel.role_id,
            )
            .where(
                OrganizationUserRoleModel.organization_id == str(organization_id),
                OrganizationUserRoleModel.user_id == str(user_id),
            )
        )
        group_stmt = (
            select(OrganizationRolePermissionModel.permission)
            .join(
                OrganizationGroupRoleModel,
                OrganizationGroupRoleModel.role_id == OrganizationRolePermissionModel.role_id,
            )
            .join(
                OrganizationGroupMembershipModel,
                OrganizationGroupMembershipModel.group_id == OrganizationGroupRoleModel.group_id,
            )
            .where(
                OrganizationGroupRoleModel.organization_id == str(organization_id),
                OrganizationGroupMembershipModel.user_id == str(user_id),
            )
        )
        direct = (await self._session.execute(direct_stmt)).scalars().all()
        group = (await self._session.execute(group_stmt)).scalars().all()
        values = set(direct) | set(group)
        return frozenset(Permission(v) for v in values)
