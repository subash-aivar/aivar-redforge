"""RBAC bounded context — M17.

Adds organization-scoped custom Roles and Groups on top of the
pre-existing fixed MembershipRole/Permission/ROLE_PERMISSIONS system
(domain.identity.value_objects), which is left entirely unchanged.

Reuse table:
  - Permission enum: reused unchanged. A custom OrganizationRole's
    permissions are a `frozenset[Permission]` — the exact same currency
    Membership.has_permission already uses. No new permission type, no
    ability to reference domain.platform_identity.PlatformPermission
    (structurally impossible: the type is Permission, not a bare string).
  - Platform Super Admin authority (domain.platform_identity): reused
    unchanged, untouched by this bounded context. Custom roles/groups are
    ORGANIZATION-scoped only and can never grant platform-wide authority.
  - EntityId/AuditTimestamps: reused unchanged (shared/).
  - Optimistic concurrency `version: int` pattern: reused from
    domain.platform_identity.entity.PlatformAssignment.
"""
