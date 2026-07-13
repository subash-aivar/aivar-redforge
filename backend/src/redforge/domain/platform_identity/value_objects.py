"""Value objects for the Platform Identity bounded context.

Mirrors the shape of `domain.identity.value_objects` (MembershipRole /
Permission / ROLE_PERMISSIONS) deliberately — same fixed-role RBAC pattern,
applied to the platform control plane instead of the tenant control plane.
There is intentionally no code path that lets a MembershipRole (tenant role)
influence a PlatformRole or PlatformPermission — the two enums, and the two
permission tables, are entirely separate universes.
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class PlatformRole(StrEnum):
    """Platform-wide roles, independent of any organization membership.

    The role set is not limited to a single hardcoded "the one Super
    Admin" concept — SUPER_ADMIN can be granted to more than one
    principal. As of M2, all four roles carry real, distinct permission
    semantics (see PLATFORM_ROLE_PERMISSIONS) — M1 shipped the enum with
    three of them deliberately empty pending this review.
    """

    SUPER_ADMIN = "platform_super_admin"
    SECURITY_ADMIN = "platform_security_admin"
    SUPPORT = "platform_support"
    AUDITOR = "platform_auditor"


@unique
class PlatformAssignmentStatus(StrEnum):
    """Lifecycle of a PlatformAssignment."""

    ACTIVE = "active"
    REVOKED = "revoked"


@unique
class PlatformPermission(StrEnum):
    """Fine-grained platform-control-plane permissions.

    Distinct namespace ("platform:") from the existing tenant Permission
    enum ("org:", "targets:", etc.) so the two can never be confused by
    string comparison, and are enforced by two entirely separate
    dependency chains (require_permission vs require_platform_permission).
    """

    PLATFORM_USERS_READ = "platform:users:read"
    PLATFORM_USERS_SUSPEND = "platform:users:suspend"
    PLATFORM_USERS_REACTIVATE = "platform:users:reactivate"
    PLATFORM_ORGANIZATIONS_READ = "platform:organizations:read"
    PLATFORM_ORGANIZATIONS_SUSPEND = "platform:organizations:suspend"
    PLATFORM_ORGANIZATIONS_REACTIVATE = "platform:organizations:reactivate"
    PLATFORM_ACCESS_READ = "platform:access:read"
    PLATFORM_ACCESS_GRANT = "platform:access:grant"
    PLATFORM_ACCESS_REVOKE = "platform:access:revoke"
    PLATFORM_AUDIT_READ = "platform:audit:read"
    PLATFORM_SECURITY_READ = "platform:security:read"


# Role -> Permission mapping for the platform control plane.
#
# Same single-source-of-truth pattern as domain.identity.value_objects.
# ROLE_PERMISSIONS: every platform authorization check goes through this
# table (require_platform_permission) — no router or service branches on
# role identity directly.
#
# M2 deliberate semantics (each role fills a distinct real job, not a
# placeholder):
#   SUPER_ADMIN     — every permission, including granting/revoking
#                      platform access itself. The only role that can
#                      create/remove other platform principals.
#   SECURITY_ADMIN  — can suspend/reactivate users and organizations
#                      (the day-to-day governance actions) and can read
#                      audit/security posture, but CANNOT grant or revoke
#                      platform access — creating new platform principals
#                      remains Super-Admin-only so a compromised Security
#                      Admin account cannot mint itself broader access.
#   SUPPORT         — read-only visibility into users/organizations/access
#                      assignments for helpdesk-style investigation; no
#                      mutation capability at all, and no audit-log access
#                      (audit is a security/compliance concern, not a
#                      support one).
#   AUDITOR         — read-only visibility into everything, including the
#                      audit log and security/MFA posture, for compliance
#                      review; zero mutation capability, matching the
#                      explicit requirement that PLATFORM_AUDITOR can
#                      never mutate platform state.
PLATFORM_ROLE_PERMISSIONS: dict[PlatformRole, frozenset[PlatformPermission]] = {
    PlatformRole.SUPER_ADMIN: frozenset(PlatformPermission),
    PlatformRole.SECURITY_ADMIN: frozenset({
        PlatformPermission.PLATFORM_USERS_READ,
        PlatformPermission.PLATFORM_USERS_SUSPEND,
        PlatformPermission.PLATFORM_USERS_REACTIVATE,
        PlatformPermission.PLATFORM_ORGANIZATIONS_READ,
        PlatformPermission.PLATFORM_ORGANIZATIONS_SUSPEND,
        PlatformPermission.PLATFORM_ORGANIZATIONS_REACTIVATE,
        PlatformPermission.PLATFORM_ACCESS_READ,
        PlatformPermission.PLATFORM_AUDIT_READ,
        PlatformPermission.PLATFORM_SECURITY_READ,
    }),
    PlatformRole.SUPPORT: frozenset({
        PlatformPermission.PLATFORM_USERS_READ,
        PlatformPermission.PLATFORM_ORGANIZATIONS_READ,
        PlatformPermission.PLATFORM_ACCESS_READ,
    }),
    PlatformRole.AUDITOR: frozenset({
        PlatformPermission.PLATFORM_USERS_READ,
        PlatformPermission.PLATFORM_ORGANIZATIONS_READ,
        PlatformPermission.PLATFORM_ACCESS_READ,
        PlatformPermission.PLATFORM_AUDIT_READ,
        PlatformPermission.PLATFORM_SECURITY_READ,
    }),
}

# Roles that PlatformAccessService.grant() will accept. All four M2 roles
# now have real permission semantics (above), so all four are grantable —
# unlike M1, where only SUPER_ADMIN was, because the other three shipped
# with deliberately empty permission sets.
GRANTABLE_PLATFORM_ROLES: frozenset[PlatformRole] = frozenset(PlatformRole)

# Backward-compatible alias for the M1 name — the M1 report and any
# external reference to GRANTABLE_PLATFORM_ROLES_M1 still resolves.
GRANTABLE_PLATFORM_ROLES_M1 = GRANTABLE_PLATFORM_ROLES
