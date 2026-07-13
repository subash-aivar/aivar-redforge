"""Effective-access explanation read model — M17.

Answers "why does this user have this permission?" for one user in one
organization: fixed-role permissions (the pre-existing M1-M16 system),
plus custom-role permissions assigned directly, plus custom-role
permissions derived through group membership — deduplicated into one
final effective set. Deterministic, tenant-scoped, and read-only: this
service never mutates anything.

Platform Super Admin authority is NEVER included here — it is a wholly
separate authorization plane (domain.platform_identity) and mixing it
into an organization-scoped explanation would misrepresent where a
permission actually comes from.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.identity.exceptions import MembershipNotFoundError
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, Permission
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class GroupAccessDTO:
    group_id: str
    group_name: str
    role_ids: list[str]
    role_names: list[str]
    permissions: list[str]


@dataclass(frozen=True, slots=True)
class EffectiveAccessDTO:
    user_id: str
    organization_id: str
    membership_role: str
    membership_permissions: list[str]
    direct_role_ids: list[str]
    direct_role_names: list[str]
    direct_role_permissions: list[str]
    groups: list[GroupAccessDTO]
    effective_permissions: list[str]


class EffectiveAccessService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_additional_permissions(
        self, organization_id: str, user_id: str,
    ) -> frozenset[Permission]:
        """Fast path used by api/security.py's `get_tenant_context` on
        every authenticated request: the union of custom-role
        permissions granted directly to this user or through any group
        they belong to, in this organization. Purely additive — see
        module docstring — and near-zero cost (two indexed joins,
        empty result) for organizations with no M17 custom roles/groups
        configured."""
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyRbacQueryRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        uid = EntityId.from_string(user_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRbacQueryRepository(uow.session)
            return await repo.get_additional_permissions(org_id, uid)

    async def is_membership_active(self, organization_id: str, user_id: str) -> bool:
        """Live per-request check used by `get_tenant_context` — a
        membership suspended/removed AFTER a token was issued must lose
        access immediately, the same "never trust the JWT for standing"
        discipline already applied to global user status and
        organization suspension."""
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        uid = EntityId.from_string(user_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMembershipRepository(uow.session)
            membership = await repo.get_by_user_and_org(uid, org_id)
            return membership is not None and membership.is_active

    async def explain(self, organization_id: str, user_id: str) -> EffectiveAccessDTO:
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        target_user_id = EntityId.from_string(user_id)

        async with SessionUnitOfWork(self._session_factory) as uow:
            membership_repo = SqlAlchemyMembershipRepository(uow.session)
            membership = await membership_repo.get_by_user_and_org(target_user_id, org_id)
            if membership is None:
                raise MembershipNotFoundError(user_id)

            role_repo = SqlAlchemyRoleRepository(uow.session)
            group_repo = SqlAlchemyGroupRepository(uow.session)

            membership_permissions = frozenset(
                ROLE_PERMISSIONS[membership.role]
            ) if membership.is_active else frozenset()

            direct_role_ids = await role_repo.list_direct_role_ids_for_user(org_id, target_user_id)
            direct_roles = [
                r for r in [
                    await role_repo.get_by_id_for_organization(EntityId.from_string(rid), org_id)
                    for rid in direct_role_ids
                ] if r is not None
            ]
            direct_permissions: frozenset[Permission] = frozenset()
            for r in direct_roles:
                direct_permissions |= r.permissions

            group_ids = await group_repo.list_group_ids_for_user(org_id, target_user_id)
            groups: list[GroupAccessDTO] = []
            group_permissions: frozenset[Permission] = frozenset()
            for gid in group_ids:
                group = await group_repo.get_by_id_for_organization(
                    EntityId.from_string(gid), org_id,
                )
                if group is None:
                    continue
                role_ids = await group_repo.list_role_ids_for_group(group.id)
                roles = [
                    r for r in [
                        await role_repo.get_by_id_for_organization(
                            EntityId.from_string(rid), org_id,
                        )
                        for rid in role_ids
                    ] if r is not None
                ]
                perms: frozenset[Permission] = frozenset()
                for r in roles:
                    perms |= r.permissions
                group_permissions |= perms
                groups.append(GroupAccessDTO(
                    group_id=str(group.id), group_name=group.name,
                    role_ids=[str(r.id) for r in roles], role_names=[r.name for r in roles],
                    permissions=sorted(p.value for p in perms),
                ))

            effective = membership_permissions | direct_permissions | group_permissions

        return EffectiveAccessDTO(
            user_id=user_id, organization_id=organization_id,
            membership_role=str(membership.role), membership_permissions=sorted(
                p.value for p in membership_permissions
            ),
            direct_role_ids=[str(r.id) for r in direct_roles],
            direct_role_names=[r.name for r in direct_roles],
            direct_role_permissions=sorted(p.value for p in direct_permissions),
            groups=groups,
            effective_permissions=sorted(p.value for p in effective),
        )
