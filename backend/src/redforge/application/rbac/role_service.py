"""Custom organization Role administration — M17.

System roles (the pre-existing, fixed MembershipRole enum — OWNER/ADMIN/
SECURITY_MANAGER/ANALYST/MEMBER/VIEWER) are represented here as
synthetic, read-only RoleDTOs (id = "system:<role>") so the API/frontend
can list them alongside custom roles in one call. They are never
persisted as rows and therefore structurally cannot be mutated or
deleted through this service — `SystemRoleImmutableError` is the
explicit guard for defense-in-depth, but the deeper guarantee is that
there is simply no database row for a "system:..." id to load.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError

from redforge.application.rbac.grant_policy import assert_can_grant
from redforge.domain.identity.exceptions import MembershipNotFoundError
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole, Permission
from redforge.domain.rbac.entity import OrganizationRole, normalize_name
from redforge.domain.rbac.exceptions import (
    DuplicateRoleNameError,
    RoleHasActiveAssignmentsError,
    RoleNotFoundError,
    SystemRoleImmutableError,
    UnknownPermissionError,
)
from redforge.infrastructure.audit.contracts import AuditAction
from redforge.infrastructure.audit.organization_admin_audit_log import (
    PostgresOrganizationAdminAuditLog,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.infrastructure.database.repositories.rbac_repository import (
        SqlAlchemyRoleRepository,
    )

SYSTEM_ROLE_PREFIX = "system:"


@dataclass(frozen=True, slots=True)
class RoleDTO:
    id: str
    organization_id: str
    name: str
    description: str
    permissions: list[str]
    is_system: bool
    assignment_count: int
    created_at: str | None
    updated_at: str | None
    version: int

    @classmethod
    def from_entity(cls, role: OrganizationRole, assignment_count: int = 0) -> RoleDTO:
        return cls(
            id=str(role.id), organization_id=str(role.organization_id), name=role.name,
            description=role.description,
            permissions=sorted(p.value for p in role.permissions),
            is_system=role.is_system, assignment_count=assignment_count,
            created_at=role.timestamps.created_at.isoformat(),
            updated_at=role.timestamps.updated_at.isoformat(),
            version=role.version,
        )

    @classmethod
    def system(cls, organization_id: str, role: MembershipRole) -> RoleDTO:
        return cls(
            id=f"{SYSTEM_ROLE_PREFIX}{role.value}", organization_id=organization_id,
            name=role.value.replace("_", " ").title(),
            description=f"Built-in system role ({role.value}).",
            permissions=sorted(p.value for p in ROLE_PERMISSIONS[role]),
            is_system=True, assignment_count=0, created_at=None, updated_at=None, version=1,
        )


def _parse_permissions(values: list[str]) -> frozenset[Permission]:
    parsed = set()
    for v in values:
        try:
            parsed.add(Permission(v))
        except ValueError as exc:
            raise UnknownPermissionError(v) from exc
    return frozenset(parsed)


class RoleService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_roles(self, organization_id: str) -> list[RoleDTO]:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        system_roles = [RoleDTO.system(organization_id, r) for r in MembershipRole]
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRoleRepository(uow.session)
            custom = await repo.list_for_organization(EntityId.from_string(organization_id))
            dtos = []
            for role in custom:
                count = await repo.count_assignments(role.id)
                dtos.append(RoleDTO.from_entity(role, count))
        return system_roles + dtos

    async def get_role(self, organization_id: str, role_id: str) -> RoleDTO:
        if role_id.startswith(SYSTEM_ROLE_PREFIX):
            role_name = role_id[len(SYSTEM_ROLE_PREFIX):]
            try:
                return RoleDTO.system(organization_id, MembershipRole(role_name))
            except ValueError as exc:
                raise RoleNotFoundError(role_id) from exc

        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        try:
            safe_role_id = EntityId.from_string(role_id)
            safe_org_id = EntityId.from_string(organization_id)
        except ValueError as exc:
            raise RoleNotFoundError(role_id) from exc

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRoleRepository(uow.session)
            role = await repo.get_by_id_for_organization(safe_role_id, safe_org_id)
            if role is None:
                raise RoleNotFoundError(role_id)
            count = await repo.count_assignments(role.id)
        return RoleDTO.from_entity(role, count)

    async def create_role(
        self, actor_user_id: str, actor_permissions: frozenset[Permission],
        organization_id: str, name: str, description: str, permission_values: list[str],
    ) -> RoleDTO:
        requested = _parse_permissions(permission_values)
        assert_can_grant(actor_permissions, requested)

        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        normalized = normalize_name(name)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRoleRepository(uow.session)
            if await repo.get_by_normalized_name(org_id, normalized) is not None:
                raise DuplicateRoleNameError(name)
            role = OrganizationRole.create(org_id, name, description, requested)
            try:
                await repo.save(role)
            except IntegrityError as exc:
                # Defense-in-depth against the check-then-insert race above:
                # the DB's own unique constraint (organization_id,
                # normalized_name) is the real backstop if two concurrent
                # requests both pass the pre-check for the same name.
                await uow.session.rollback()
                raise DuplicateRoleNameError(name) from exc
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_ROLE_CREATED, target_type="organization_role",
                target_id=str(role.id),
                metadata={"name": name, "permissions": sorted(permission_values)},
            )
            await uow.commit()
        return RoleDTO.from_entity(role, 0)

    async def update_role_metadata(
        self, actor_user_id: str, organization_id: str, role_id: str, name: str, description: str,
    ) -> RoleDTO:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        normalized = normalize_name(name)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRoleRepository(uow.session)
            role = await self._load(repo, role_id, org_id)
            existing = await repo.get_by_normalized_name(org_id, normalized)
            if existing is not None and str(existing.id) != str(role.id):
                raise DuplicateRoleNameError(name)
            role.rename(name, description)
            try:
                await repo.save(role)
            except IntegrityError as exc:
                await uow.session.rollback()
                raise DuplicateRoleNameError(name) from exc
            count = await repo.count_assignments(role.id)
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_ROLE_UPDATED, target_type="organization_role",
                target_id=role_id, metadata={"name": name},
            )
            await uow.commit()
        return RoleDTO.from_entity(role, count)

    async def set_permissions(
        self, actor_user_id: str, actor_permissions: frozenset[Permission],
        organization_id: str, role_id: str, permission_values: list[str],
    ) -> RoleDTO:
        requested = _parse_permissions(permission_values)
        assert_can_grant(actor_permissions, requested)

        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRoleRepository(uow.session)
            role = await self._load(repo, role_id, org_id)
            role.set_permissions(requested)
            await repo.save(role)
            count = await repo.count_assignments(role.id)
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_ROLE_PERMISSIONS_CHANGED, target_type="organization_role",
                target_id=role_id, metadata={"permissions": sorted(permission_values)},
            )
            await uow.commit()
        return RoleDTO.from_entity(role, count)

    async def delete_role(self, actor_user_id: str, organization_id: str, role_id: str) -> None:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRoleRepository(uow.session)
            role = await self._load(repo, role_id, org_id)
            count = await repo.count_assignments(role.id)
            if count > 0:
                raise RoleHasActiveAssignmentsError(role_id)
            await repo.delete(role.id, org_id)
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_ROLE_DELETED, target_type="organization_role",
                target_id=role_id, metadata={"name": role.name},
            )
            await uow.commit()

    async def assign_direct_role(
        self, actor_user_id: str, actor_permissions: frozenset[Permission],
        organization_id: str, target_user_id: str, role_id: str,
    ) -> None:
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.repositories.rbac_repository import (
            DuplicateAssignmentError,
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        user_id = EntityId.from_string(target_user_id)

        async with SessionUnitOfWork(self._session_factory) as uow:
            role_repo = SqlAlchemyRoleRepository(uow.session)
            role = await self._load(role_repo, role_id, org_id)
            assert_can_grant(actor_permissions, role.permissions)

            membership_repo = SqlAlchemyMembershipRepository(uow.session)
            membership = await membership_repo.get_by_user_and_org(user_id, org_id)
            if membership is None or not membership.is_active:
                raise MembershipNotFoundError(target_user_id)

            try:
                await role_repo.assign_direct_role(org_id, user_id, role.id)
            except DuplicateAssignmentError:
                await uow.commit()
                return  # idempotent: already assigned

            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_USER_ROLE_ASSIGNED, target_type="user",
                target_id=target_user_id, metadata={"role_id": role_id, "role_name": role.name},
            )
            await uow.commit()

    async def revoke_direct_role(
        self, actor_user_id: str, organization_id: str, target_user_id: str, role_id: str,
    ) -> None:
        from redforge.infrastructure.database.repositories.rbac_repository import (
            SqlAlchemyRoleRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        user_id = EntityId.from_string(target_user_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRoleRepository(uow.session)
            await repo.revoke_direct_role(org_id, user_id, EntityId.from_string(role_id))
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id, actor_id=actor_user_id,
                action=AuditAction.RBAC_USER_ROLE_REVOKED, target_type="user",
                target_id=target_user_id, metadata={"role_id": role_id},
            )
            await uow.commit()

    async def _load(
        self, repo: SqlAlchemyRoleRepository, role_id: str, org_id: EntityId,
    ) -> OrganizationRole:
        if role_id.startswith(SYSTEM_ROLE_PREFIX):
            raise SystemRoleImmutableError
        try:
            safe_role_id = EntityId.from_string(role_id)
        except ValueError as exc:
            raise RoleNotFoundError(role_id) from exc
        role: OrganizationRole | None = await repo.get_by_id_for_organization(safe_role_id, org_id)
        if role is None:
            raise RoleNotFoundError(role_id)
        return role
