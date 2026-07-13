"""Tenant-scoped security Group administration — M17."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError

from redforge.application.rbac.grant_policy import assert_can_grant
from redforge.application.rbac.role_service import SYSTEM_ROLE_PREFIX
from redforge.domain.identity.exceptions import MembershipNotFoundError
from redforge.domain.identity.value_objects import Permission
from redforge.domain.rbac.entity import OrganizationGroup, normalize_name
from redforge.domain.rbac.exceptions import (
    DuplicateGroupNameError,
    GroupHasMembersError,
    GroupNotFoundError,
    RoleNotFoundError,
)
from redforge.infrastructure.audit.contracts import AuditAction
from redforge.infrastructure.audit.organization_admin_audit_log import (
    PostgresOrganizationAdminAuditLog,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.infrastructure.database.repositories.rbac_repository import (
        SqlAlchemyGroupRepository,
    )


@dataclass(frozen=True, slots=True)
class GroupDTO:
    id: str
    organization_id: str
    name: str
    description: str
    member_count: int
    role_count: int
    created_at: str
    updated_at: str
    version: int

    @classmethod
    def from_entity(cls, group: OrganizationGroup, member_count: int, role_count: int) -> GroupDTO:
        return cls(
            id=str(group.id), organization_id=str(group.organization_id), name=group.name,
            description=group.description, member_count=member_count, role_count=role_count,
            created_at=group.timestamps.created_at.isoformat(),
            updated_at=group.timestamps.updated_at.isoformat(), version=group.version,
        )


class GroupService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_groups(self, organization_id: str) -> list[GroupDTO]:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            groups = await repo.list_for_organization(EntityId.from_string(organization_id))
            dtos = []
            for g in groups:
                member_count = await repo.count_members(g.id)
                role_count = len(await repo.list_role_ids_for_group(g.id))
                dtos.append(GroupDTO.from_entity(g, member_count, role_count))
        return dtos

    async def get_group(self, organization_id: str, group_id: str) -> GroupDTO:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            group = await self._load(repo, group_id, org_id)
            member_count = await repo.count_members(group.id)
            role_count = len(await repo.list_role_ids_for_group(group.id))
        return GroupDTO.from_entity(group, member_count, role_count)

    async def create_group(
        self, actor_user_id: str, organization_id: str, name: str, description: str,
    ) -> GroupDTO:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        normalized = normalize_name(name)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            if await repo.get_by_normalized_name(org_id, normalized) is not None:
                raise DuplicateGroupNameError(name)
            group = OrganizationGroup.create(org_id, name, description)
            try:
                await repo.save(group)
            except IntegrityError as exc:
                await uow.session.rollback()
                raise DuplicateGroupNameError(name) from exc
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_GROUP_CREATED, target_type="organization_group",
                target_id=str(group.id), metadata={"name": name},
            )
            await uow.commit()
        return GroupDTO.from_entity(group, 0, 0)

    async def update_group(
        self, actor_user_id: str, organization_id: str, group_id: str, name: str, description: str,
    ) -> GroupDTO:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        normalized = normalize_name(name)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            group = await self._load(repo, group_id, org_id)
            existing = await repo.get_by_normalized_name(org_id, normalized)
            if existing is not None and str(existing.id) != str(group.id):
                raise DuplicateGroupNameError(name)
            group.rename(name, description)
            try:
                await repo.save(group)
            except IntegrityError as exc:
                await uow.session.rollback()
                raise DuplicateGroupNameError(name) from exc
            member_count = await repo.count_members(group.id)
            role_count = len(await repo.list_role_ids_for_group(group.id))
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_GROUP_UPDATED, target_type="organization_group",
                target_id=group_id, metadata={"name": name},
            )
            await uow.commit()
        return GroupDTO.from_entity(group, member_count, role_count)

    async def delete_group(self, actor_user_id: str, organization_id: str, group_id: str) -> None:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            group = await self._load(repo, group_id, org_id)
            if await repo.count_members(group.id) > 0:
                raise GroupHasMembersError(group_id)
            await repo.delete(group.id, org_id)
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_GROUP_DELETED, target_type="organization_group",
                target_id=group_id, metadata={"name": group.name},
            )
            await uow.commit()

    async def add_member(
        self, actor_user_id: str, organization_id: str, group_id: str, target_user_id: str,
    ) -> None:
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.repositories.rbac_repository import (
            DuplicateAssignmentError,
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        user_id = EntityId.from_string(target_user_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            group_repo = SqlAlchemyGroupRepository(uow.session)
            group = await self._load(group_repo, group_id, org_id)

            membership_repo = SqlAlchemyMembershipRepository(uow.session)
            membership = await membership_repo.get_by_user_and_org(user_id, org_id)
            if membership is None or not membership.is_active:
                raise MembershipNotFoundError(target_user_id)

            try:
                await group_repo.add_member(org_id, group.id, user_id)
            except DuplicateAssignmentError:
                await uow.commit()
                return
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_GROUP_MEMBER_ADDED, target_type="organization_group",
                target_id=group_id, metadata={"user_id": target_user_id},
            )
            await uow.commit()

    async def remove_member(
        self, actor_user_id: str, organization_id: str, group_id: str, target_user_id: str,
    ) -> None:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            await self._load(repo, group_id, org_id)  # 404 if cross-tenant/unknown
            await repo.remove_member(
                EntityId.from_string(group_id), EntityId.from_string(target_user_id),
            )
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_GROUP_MEMBER_REMOVED, target_type="organization_group",
                target_id=group_id, metadata={"user_id": target_user_id},
            )
            await uow.commit()

    async def list_members(self, organization_id: str, group_id: str) -> list[str]:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            await self._load(repo, group_id, org_id)
            return await repo.list_member_ids(EntityId.from_string(group_id))

    async def assign_role(
        self, actor_user_id: str, actor_permissions: frozenset[Permission],
        organization_id: str, group_id: str, role_id: str,
    ) -> None:
        if role_id.startswith(SYSTEM_ROLE_PREFIX):
            raise RoleNotFoundError(role_id)

        from redforge.infrastructure.database.repositories.rbac_repository import (
            DuplicateAssignmentError,
            SqlAlchemyGroupRepository,
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            group_repo = SqlAlchemyGroupRepository(uow.session)
            group = await self._load(group_repo, group_id, org_id)

            role_repo = SqlAlchemyRoleRepository(uow.session)
            role = await role_repo.get_by_id_for_organization(
                EntityId.from_string(role_id), org_id,
            )
            if role is None:
                raise RoleNotFoundError(role_id)
            assert_can_grant(actor_permissions, role.permissions)

            try:
                await group_repo.assign_role(org_id, group.id, role.id)
            except DuplicateAssignmentError:
                await uow.commit()
                return
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_GROUP_ROLE_ASSIGNED, target_type="organization_group",
                target_id=group_id, metadata={"role_id": role_id, "role_name": role.name},
            )
            await uow.commit()

    async def revoke_role(
        self, actor_user_id: str, organization_id: str, group_id: str, role_id: str,
    ) -> None:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            group = await self._load(repo, group_id, org_id)
            await repo.revoke_role(group.id, EntityId.from_string(role_id))
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_GROUP_ROLE_REVOKED, target_type="organization_group",
                target_id=group_id, metadata={"role_id": role_id},
            )
            await uow.commit()

    async def list_group_role_ids(self, organization_id: str, group_id: str) -> list[str]:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyGroupRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyGroupRepository(uow.session)
            await self._load(repo, group_id, org_id)
            return await repo.list_role_ids_for_group(EntityId.from_string(group_id))

    async def _load(
        self, repo: SqlAlchemyGroupRepository, group_id: str, org_id: EntityId,
    ) -> OrganizationGroup:
        try:
            safe_group_id = EntityId.from_string(group_id)
        except ValueError as exc:
            raise GroupNotFoundError(group_id) from exc
        group: OrganizationGroup | None = await repo.get_by_id_for_organization(
            safe_group_id, org_id,
        )
        if group is None:
            raise GroupNotFoundError(group_id)
        return group
