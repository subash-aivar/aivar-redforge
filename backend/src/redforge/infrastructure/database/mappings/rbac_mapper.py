"""Entity <-> ORM model mapping for the RBAC bounded context — M17."""

from __future__ import annotations

from redforge.domain.identity.value_objects import Permission
from redforge.domain.rbac.entity import OrganizationGroup, OrganizationRole
from redforge.infrastructure.database.models.rbac import (
    OrganizationGroupModel,
    OrganizationRoleModel,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def role_to_entity(
    model: OrganizationRoleModel, permissions: frozenset[Permission],
) -> OrganizationRole:
    return OrganizationRole(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        name=model.name,
        description=model.description,
        permissions=permissions,
        timestamps=AuditTimestamps(created_at=model.created_at, updated_at=model.updated_at),
        is_system=model.is_system,
        version=model.version,
    )


def role_to_model(role: OrganizationRole, normalized_name: str) -> OrganizationRoleModel:
    return OrganizationRoleModel(
        id=str(role.id),
        organization_id=str(role.organization_id),
        name=role.name,
        normalized_name=normalized_name,
        description=role.description,
        is_system=role.is_system,
        version=role.version,
        created_at=role.timestamps.created_at,
        updated_at=role.timestamps.updated_at,
    )


def group_to_entity(model: OrganizationGroupModel) -> OrganizationGroup:
    return OrganizationGroup(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        name=model.name,
        description=model.description,
        timestamps=AuditTimestamps(created_at=model.created_at, updated_at=model.updated_at),
        version=model.version,
    )


def group_to_model(group: OrganizationGroup, normalized_name: str) -> OrganizationGroupModel:
    return OrganizationGroupModel(
        id=str(group.id),
        organization_id=str(group.organization_id),
        name=group.name,
        normalized_name=normalized_name,
        description=group.description,
        version=group.version,
        created_at=group.timestamps.created_at,
        updated_at=group.timestamps.updated_at,
    )
