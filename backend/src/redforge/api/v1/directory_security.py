"""Directory & Identity Security Visibility REST API — M5.

Tenant-scoped throughout: `organization_id` is ALWAYS
`tenant.organization_id` from the verified JWT. Read-only — there is
no endpoint to create/mutate an identity, group, or membership; those
are written exclusively by `TenantDirectorySecurityService` from
trusted discovery observations (see application/directory_security/).
Credential configuration is never exposed by these endpoints.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from redforge.api.dependencies import get_tenant_directory_security_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.directory_security.analysis_service import analyze
from redforge.core.exceptions import NotFoundError
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.directory_security.service import TenantDirectorySecurityService

router = APIRouter(tags=["directory-security"])


class DirectoryIdentityResponse(BaseModel):
    id: str
    organization_id: str
    connector_id: str
    external_id: str
    principal_category: str
    display_name: str
    principal_name: str
    source_enabled: bool
    privilege_classification: str
    privilege_reason: str
    observation_lifecycle: str
    first_observed_at: str
    last_observed_at: str


class DirectoryGroupResponse(BaseModel):
    id: str
    organization_id: str
    connector_id: str
    external_id: str
    display_name: str
    is_recognized_privileged: bool
    first_observed_at: str
    last_observed_at: str


class MembershipResponse(BaseModel):
    id: str
    identity_id: str
    group_id: str


class SecurityObservationResponse(BaseModel):
    rule_id: str
    title: str
    summary: str
    affected_identity_id: str
    affected_group_id: str | None


@router.get("/identities", response_model=list[DirectoryIdentityResponse])
async def list_identities(
    principal_category: str | None = Query(default=None),
    privilege_classification: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantDirectorySecurityService = Depends(get_tenant_directory_security_service),
) -> list[DirectoryIdentityResponse]:
    rows = await service.list_identities_for_org(
        tenant.organization_id, principal_category, privilege_classification, limit, offset,
    )
    return [DirectoryIdentityResponse(**dataclasses.asdict(r)) for r in rows]


@router.get("/identities/{identity_id}", response_model=DirectoryIdentityResponse)
async def get_identity(
    identity_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantDirectorySecurityService = Depends(get_tenant_directory_security_service),
) -> DirectoryIdentityResponse:
    try:
        row = await service.get_identity_for_org(identity_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return DirectoryIdentityResponse(**dataclasses.asdict(row))


@router.get("/identities/{identity_id}/memberships", response_model=list[MembershipResponse])
async def get_identity_memberships(
    identity_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantDirectorySecurityService = Depends(get_tenant_directory_security_service),
) -> list[MembershipResponse]:
    try:
        rows = await service.list_direct_memberships_for_identity(
            identity_id, tenant.organization_id
        )
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return [MembershipResponse(**dataclasses.asdict(r)) for r in rows]


@router.get("/directory-groups", response_model=list[DirectoryGroupResponse])
async def list_groups(
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantDirectorySecurityService = Depends(get_tenant_directory_security_service),
) -> list[DirectoryGroupResponse]:
    rows = await service.list_groups_for_org(tenant.organization_id, limit, offset)
    return [DirectoryGroupResponse(**dataclasses.asdict(r)) for r in rows]


@router.get("/directory-groups/{group_id}", response_model=DirectoryGroupResponse)
async def get_group(
    group_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantDirectorySecurityService = Depends(get_tenant_directory_security_service),
) -> DirectoryGroupResponse:
    try:
        row = await service.get_group_for_org(group_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return DirectoryGroupResponse(**dataclasses.asdict(row))


@router.get("/directory-groups/{group_id}/members", response_model=list[MembershipResponse])
async def get_group_members(
    group_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantDirectorySecurityService = Depends(get_tenant_directory_security_service),
) -> list[MembershipResponse]:
    try:
        rows = await service.list_direct_members_for_group(group_id, tenant.organization_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return [MembershipResponse(**dataclasses.asdict(r)) for r in rows]


@router.get("/identity-security/observations", response_model=list[SecurityObservationResponse])
async def list_security_observations(
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantDirectorySecurityService = Depends(get_tenant_directory_security_service),
) -> list[SecurityObservationResponse]:
    """Computed on read from current canonical state — deterministic,
    not persisted, so no duplicate-on-repeat-discovery concern arises
    (see application/directory_security/analysis_service.py)."""
    identities = await service.list_identities_for_org(tenant.organization_id, limit=200)
    groups = await service.list_groups_for_org(tenant.organization_id, limit=200)
    groups_by_id = {
        g.id: {
            "display_name": g.display_name,
            "is_recognized_privileged": g.is_recognized_privileged,
        }
        for g in groups
    }
    memberships: list[dict[str, str]] = []
    for identity in identities:
        rows = await service.list_direct_memberships_for_identity(
            identity.id, tenant.organization_id
        )
        memberships.extend({"identity_id": r.identity_id, "group_id": r.group_id} for r in rows)

    identity_dicts = [
        {
            "id": i.id, "display_name": i.display_name,
            "principal_category": i.principal_category,
            "source_enabled": i.source_enabled,
            "privilege_classification": i.privilege_classification,
        }
        for i in identities
    ]
    observations = analyze(identity_dicts, memberships, groups_by_id)
    return [SecurityObservationResponse(**dataclasses.asdict(o)) for o in observations]
