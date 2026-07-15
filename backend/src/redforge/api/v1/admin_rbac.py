"""Organization RBAC administration REST API — M17.

Every route is tenant-scoped via TenantContext; organization_id is
NEVER accepted from the client (path or body) — it always comes from
the caller's verified token (see api/security.py). This mirrors the
established M14-M16 convention (e.g. network_security.py) rather than
the older `/organizations/{organization_id}/members` path-parameter
style, precisely to remove an entire class of ID-confusion attempts
(there is no organization_id in the URL to mismatch).

ROLES_MANAGE/GROUPS_MANAGE additionally never bypass the canonical
grant-policy check (application.rbac.grant_policy.assert_can_grant) —
holding the permission lets an actor administer roles/groups, but never
lets them grant a permission they do not themselves already hold.
"""

from __future__ import annotations

import dataclasses

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_effective_access_service,
    get_group_service,
    get_role_service,
)
from redforge.api.security import TenantContext, require_permission
from redforge.application.rbac import (
    EffectiveAccessDTO,  # noqa: TC001
    EffectiveAccessService,  # noqa: TC001
    GroupDTO,  # noqa: TC001
    GroupService,  # noqa: TC001
    RoleDTO,  # noqa: TC001
    RoleService,  # noqa: TC001
)
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/admin", tags=["admin-rbac"])


# ─── Permission catalog ─────────────────────────────────────────────────────


class PermissionCatalogItem(BaseModel):
    key: str
    domain: str
    description: str


def _domain_for(permission: Permission) -> str:
    return permission.value.split(":", 1)[0]


_DESCRIPTIONS: dict[Permission, str] = {
    Permission.ORG_READ: "View organization details",
    Permission.ORG_MANAGE: "Manage organization settings",
    Permission.MEMBERS_READ: "View organization members",
    Permission.MEMBERS_INVITE: "Invite new members",
    Permission.MEMBERS_MANAGE: "Change member roles, suspend, or remove members",
    Permission.TARGETS_READ: "View AI targets",
    Permission.TARGETS_CREATE: "Register new AI targets",
    Permission.TARGETS_MANAGE: "Manage AI target lifecycle",
    Permission.VALIDATIONS_READ: "View validation runs",
    Permission.VALIDATIONS_RUN: "Launch validation runs",
    Permission.VALIDATIONS_MANAGE: "Manage validation lifecycle",
    Permission.EVIDENCE_READ: "View collected evidence",
    Permission.FINDINGS_READ: "View security findings",
    Permission.AUTHORIZATIONS_READ: "View authorization requests",
    Permission.AUTHORIZATIONS_CREATE: "Create authorization requests",
    Permission.AUTHORIZATIONS_APPROVE: "Approve authorization requests",
    Permission.AUTHORIZATIONS_APPROVE_CREDENTIAL: "Approve credential-scoped authorizations",
    Permission.AUTHORIZATIONS_EVALUATE: "Evaluate execution policy decisions",
    Permission.SECURITY_OPERATIONS_READ: "View Security Operations telemetry",
    Permission.NETWORK_SECURITY_READ: "View network security inventory and runs",
    Permission.NETWORK_SECURITY_MANAGE: "Manage network monitoring and launch validations",
    Permission.ROLES_READ: "View custom roles",
    Permission.ROLES_MANAGE: "Create, edit, and assign custom roles",
    Permission.GROUPS_READ: "View security groups",
    Permission.GROUPS_MANAGE: "Create, edit, and manage security groups",
    Permission.DDOS_READ: "View DDoS incidents, traffic analytics, and detection policies",
    Permission.DDOS_MANAGE: "Configure DDoS protected resources and detection policies",
    Permission.DDOS_MITIGATION_APPROVE: "Approve DDoS mitigation recommendations for execution",
}


@router.get("/permissions", response_model=list[PermissionCatalogItem])
async def list_permission_catalog(
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_READ)),
) -> list[PermissionCatalogItem]:
    """Backend-authoritative permission catalog for the role editor.
    The frontend never maintains a second copy of this list."""
    return [
        PermissionCatalogItem(
            key=p.value, domain=_domain_for(p), description=_DESCRIPTIONS.get(p, p.value),
        )
        for p in Permission
    ]


# ─── Roles ──────────────────────────────────────────────────────────────────


class RoleResponse(BaseModel):
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
    def from_dto(cls, dto: RoleDTO) -> RoleResponse:
        return cls(**dataclasses.asdict(dto))


class CreateRoleRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)
    permissions: list[str] = Field(default_factory=list)


class UpdateRoleRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)


class SetPermissionsRequest(BaseModel):
    permissions: list[str] = Field(default_factory=list)


@router.get("/roles", response_model=list[RoleResponse])
async def list_roles(
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_READ)),
    service: RoleService = Depends(get_role_service),
) -> list[RoleResponse]:
    dtos = await service.list_roles(tenant.organization_id)
    return [RoleResponse.from_dto(d) for d in dtos]


@router.post("/roles", response_model=RoleResponse, status_code=201)
async def create_role(
    body: CreateRoleRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_MANAGE)),
    service: RoleService = Depends(get_role_service),
) -> RoleResponse:
    dto = await service.create_role(
        tenant.user_id, tenant.permissions, tenant.organization_id,
        body.name, body.description, body.permissions,
    )
    return RoleResponse.from_dto(dto)


@router.get("/roles/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_READ)),
    service: RoleService = Depends(get_role_service),
) -> RoleResponse:
    dto = await service.get_role(tenant.organization_id, role_id)
    return RoleResponse.from_dto(dto)


@router.patch("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    body: UpdateRoleRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_MANAGE)),
    service: RoleService = Depends(get_role_service),
) -> RoleResponse:
    dto = await service.update_role_metadata(
        tenant.user_id, tenant.organization_id, role_id, body.name, body.description,
    )
    return RoleResponse.from_dto(dto)


@router.post("/roles/{role_id}/permissions", response_model=RoleResponse)
async def set_role_permissions(
    role_id: str,
    body: SetPermissionsRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_MANAGE)),
    service: RoleService = Depends(get_role_service),
) -> RoleResponse:
    dto = await service.set_permissions(
        tenant.user_id, tenant.permissions, tenant.organization_id, role_id, body.permissions,
    )
    return RoleResponse.from_dto(dto)


@router.delete("/roles/{role_id}", status_code=204)
async def delete_role(
    role_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_MANAGE)),
    service: RoleService = Depends(get_role_service),
) -> None:
    await service.delete_role(tenant.user_id, tenant.organization_id, role_id)


# ─── User role assignment ───────────────────────────────────────────────────


class AssignRoleRequest(BaseModel):
    role_id: str = Field(..., min_length=1)


@router.post("/users/{user_id}/roles", status_code=204)
async def assign_user_role(
    user_id: str,
    body: AssignRoleRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_MANAGE)),
    service: RoleService = Depends(get_role_service),
) -> None:
    await service.assign_direct_role(
        tenant.user_id, tenant.permissions, tenant.organization_id, user_id, body.role_id,
    )


@router.delete("/users/{user_id}/roles/{role_id}", status_code=204)
async def revoke_user_role(
    user_id: str,
    role_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_MANAGE)),
    service: RoleService = Depends(get_role_service),
) -> None:
    await service.revoke_direct_role(tenant.user_id, tenant.organization_id, user_id, role_id)


class EffectiveAccessResponse(BaseModel):
    user_id: str
    organization_id: str
    membership_role: str
    membership_permissions: list[str]
    direct_role_ids: list[str]
    direct_role_names: list[str]
    direct_role_permissions: list[str]
    groups: list[dict[str, object]]
    effective_permissions: list[str]

    @classmethod
    def from_dto(cls, dto: EffectiveAccessDTO) -> EffectiveAccessResponse:
        return cls(
            user_id=dto.user_id, organization_id=dto.organization_id,
            membership_role=dto.membership_role,
            membership_permissions=dto.membership_permissions,
            direct_role_ids=dto.direct_role_ids, direct_role_names=dto.direct_role_names,
            direct_role_permissions=dto.direct_role_permissions,
            groups=[dataclasses.asdict(g) for g in dto.groups],
            effective_permissions=dto.effective_permissions,
        )


@router.get("/users/{user_id}/effective-access", response_model=EffectiveAccessResponse)
async def get_effective_access(
    user_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: EffectiveAccessService = Depends(get_effective_access_service),
) -> EffectiveAccessResponse:
    """Self-service for any org member inspecting their OWN access;
    inspecting another user's access requires ROLES_READ (admin
    visibility). Both cases are tenant-scoped identically — a caller
    can never inspect a user outside their own organization since
    `tenant.organization_id` is the only organization_id ever used."""
    if user_id != tenant.user_id and not tenant.has_permission(Permission.ROLES_READ):
        from redforge.core.exceptions import AuthorizationError

        raise AuthorizationError("Missing required permission 'roles:read'")
    dto = await service.explain(tenant.organization_id, user_id)
    return EffectiveAccessResponse.from_dto(dto)


# ─── Groups ─────────────────────────────────────────────────────────────────


class GroupResponse(BaseModel):
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
    def from_dto(cls, dto: GroupDTO) -> GroupResponse:
        return cls(**dataclasses.asdict(dto))


class CreateGroupRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)


class UpdateGroupRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: str = Field(default="", max_length=500)


class AddMemberRequest(BaseModel):
    user_id: str = Field(..., min_length=1)


class AssignGroupRoleRequest(BaseModel):
    role_id: str = Field(..., min_length=1)


@router.get("/groups", response_model=list[GroupResponse])
async def list_groups(
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_READ)),
    service: GroupService = Depends(get_group_service),
) -> list[GroupResponse]:
    dtos = await service.list_groups(tenant.organization_id)
    return [GroupResponse.from_dto(d) for d in dtos]


@router.post("/groups", response_model=GroupResponse, status_code=201)
async def create_group(
    body: CreateGroupRequest,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_MANAGE)),
    service: GroupService = Depends(get_group_service),
) -> GroupResponse:
    dto = await service.create_group(
        tenant.user_id, tenant.organization_id, body.name, body.description,
    )
    return GroupResponse.from_dto(dto)


@router.get("/groups/{group_id}", response_model=GroupResponse)
async def get_group(
    group_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_READ)),
    service: GroupService = Depends(get_group_service),
) -> GroupResponse:
    dto = await service.get_group(tenant.organization_id, group_id)
    return GroupResponse.from_dto(dto)


@router.patch("/groups/{group_id}", response_model=GroupResponse)
async def update_group(
    group_id: str,
    body: UpdateGroupRequest,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_MANAGE)),
    service: GroupService = Depends(get_group_service),
) -> GroupResponse:
    dto = await service.update_group(
        tenant.user_id, tenant.organization_id, group_id, body.name, body.description,
    )
    return GroupResponse.from_dto(dto)


@router.delete("/groups/{group_id}", status_code=204)
async def delete_group(
    group_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_MANAGE)),
    service: GroupService = Depends(get_group_service),
) -> None:
    await service.delete_group(tenant.user_id, tenant.organization_id, group_id)


@router.get("/groups/{group_id}/members", response_model=list[str])
async def list_group_members(
    group_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_READ)),
    service: GroupService = Depends(get_group_service),
) -> list[str]:
    return await service.list_members(tenant.organization_id, group_id)


@router.post("/groups/{group_id}/members", status_code=204)
async def add_group_member(
    group_id: str,
    body: AddMemberRequest,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_MANAGE)),
    service: GroupService = Depends(get_group_service),
) -> None:
    await service.add_member(tenant.user_id, tenant.organization_id, group_id, body.user_id)


@router.delete("/groups/{group_id}/members/{user_id}", status_code=204)
async def remove_group_member(
    group_id: str,
    user_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_MANAGE)),
    service: GroupService = Depends(get_group_service),
) -> None:
    await service.remove_member(tenant.user_id, tenant.organization_id, group_id, user_id)


@router.get("/groups/{group_id}/roles", response_model=list[str])
async def list_group_roles(
    group_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_READ)),
    service: GroupService = Depends(get_group_service),
) -> list[str]:
    return await service.list_group_role_ids(tenant.organization_id, group_id)


@router.post("/groups/{group_id}/roles", status_code=204)
async def assign_group_role(
    group_id: str,
    body: AssignGroupRoleRequest,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_MANAGE)),
    service: GroupService = Depends(get_group_service),
) -> None:
    await service.assign_role(
        tenant.user_id, tenant.permissions, tenant.organization_id, group_id, body.role_id,
    )


@router.delete("/groups/{group_id}/roles/{role_id}", status_code=204)
async def revoke_group_role(
    group_id: str,
    role_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.GROUPS_MANAGE)),
    service: GroupService = Depends(get_group_service),
) -> None:
    await service.revoke_role(tenant.user_id, tenant.organization_id, group_id, role_id)


# ─── Administrative audit (organization-scoped) ─────────────────────────────


class AdminAuditEventResponse(BaseModel):
    actor_id: str
    action: str
    target_type: str
    target_id: str
    organization_id: str
    metadata: dict[str, object]
    occurred_at: str


@router.get("/audit-events", response_model=list[AdminAuditEventResponse])
async def list_admin_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.ROLES_READ)),
) -> list[AdminAuditEventResponse]:
    from redforge.api.dependencies import get_session_factory
    from redforge.infrastructure.audit.organization_admin_audit_log import (
        PostgresOrganizationAdminAuditLog,
    )
    from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

    async with SessionUnitOfWork(get_session_factory()) as uow:
        log = PostgresOrganizationAdminAuditLog(uow.session)
        entries = await log.query_for_organization(tenant.organization_id, limit, offset)
    return [
        AdminAuditEventResponse(
            actor_id=e.actor_id, action=e.action, target_type=e.target_type,
            target_id=e.target_id, organization_id=e.organization_id,
            metadata=e.metadata, occurred_at=e.occurred_at.isoformat(),
        )
        for e in entries
    ]
