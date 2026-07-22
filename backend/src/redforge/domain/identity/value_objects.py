"""Value objects for the Identity bounded context.

These value objects encapsulate the validation rules for user identity,
authentication credentials, roles, and permissions. All are immutable
and self-validating.
"""

from __future__ import annotations

import re
from enum import StrEnum, unique


@unique
class UserStatus(StrEnum):
    """Lifecycle status of a User account.

    - ACTIVE: User can authenticate and perform actions.
    - INACTIVE: User has been deactivated by an admin.
    - PENDING: User has been invited but has not completed registration.
    - SUSPENDED: User is suspended due to policy violation.
    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    SUSPENDED = "suspended"


@unique
class Permission(StrEnum):
    """Fine-grained permissions within an Organization.

    Permissions are assigned to roles, not directly to users.
    This set will grow as the platform adds capabilities.
    """

    # Organization management
    ORG_READ = "org:read"
    ORG_MANAGE = "org:manage"

    # Member management
    MEMBERS_READ = "members:read"
    MEMBERS_INVITE = "members:invite"
    MEMBERS_MANAGE = "members:manage"

    # Validation targets
    TARGETS_READ = "targets:read"
    TARGETS_CREATE = "targets:create"
    TARGETS_MANAGE = "targets:manage"

    # Validation runs
    VALIDATIONS_READ = "validations:read"
    VALIDATIONS_RUN = "validations:run"
    VALIDATIONS_MANAGE = "validations:manage"

    # Evidence & Findings
    EVIDENCE_READ = "evidence:read"
    FINDINGS_READ = "findings:read"

    # Security Authorization & Execution Policy control plane (M10).
    # AUTHORIZATIONS_APPROVE_CREDENTIAL is a strictly stronger tier than
    # AUTHORIZATIONS_APPROVE, required specifically to approve an
    # authorization whose scope includes CREDENTIAL_VALIDATION — see
    # domain.authorization.value_objects.STRONG_APPROVAL_ACTION_CLASSES.
    AUTHORIZATIONS_READ = "authorizations:read"
    AUTHORIZATIONS_CREATE = "authorizations:create"
    AUTHORIZATIONS_APPROVE = "authorizations:approve"
    AUTHORIZATIONS_APPROVE_CREDENTIAL = "authorizations:approve_credential"
    AUTHORIZATIONS_EVALUATE = "authorizations:evaluate"

    # Security Operations Command Center (M15) — a read-only projection
    # over data every role already reads via VALIDATIONS_READ/
    # AUTHORIZATIONS_READ/FINDINGS_READ, so this single permission gates
    # both the REST reads and the SSE stream identically (no separate
    # "stream" tier — the brief itself prefers one read permission when
    # visibility should match).
    SECURITY_OPERATIONS_READ = "security_operations:read"

    # Advanced Network Security & Continuous Network Monitoring (M16).
    # READ covers inventory/asset-detail/change-feed; MANAGE covers
    # monitoring-policy lifecycle and launching an authorized network
    # validation run. MANAGE never bypasses M10 — every concrete
    # address is still independently authorization-checked by
    # application/network_security/authorization_scope.py regardless of
    # this permission.
    NETWORK_SECURITY_READ = "network_security:read"
    NETWORK_SECURITY_MANAGE = "network_security:manage"

    # Enterprise Identity, Super Admin & RBAC Control Plane (M17).
    # Gates the ORGANIZATION-scoped custom role/group administration
    # surface (application/rbac/, api/v1/admin_rbac.py) — entirely
    # distinct from platform-wide PlatformPermission (domain.
    # platform_identity), which no organization role can ever hold or
    # grant. ROLES_MANAGE/GROUPS_MANAGE additionally gate every mutation
    # through the canonical grant-policy check (application.rbac.
    # grant_policy.assert_can_grant) — holding this permission lets an
    # actor administer roles/groups, but never lets them grant a
    # permission they do not themselves already hold.
    ROLES_READ = "roles:read"
    ROLES_MANAGE = "roles:manage"
    GROUPS_READ = "groups:read"
    GROUPS_MANAGE = "groups:manage"

    # Advanced DDoS Detection & Defense Center (M19).
    # READ — view incidents, detections, protected resources, policies,
    #   traffic analytics, mitigation recommendations, history.
    # MANAGE — configure protected resources and detection policies,
    #   register/update resources, manage suppression windows.
    # MITIGATION_APPROVE — explicitly approve a mitigation recommendation
    #   for execution. Separated from MANAGE so that policy administrators
    #   and mitigation approvers can be different personnel (two-person
    #   integrity). Approval NEVER bypasses tenant isolation or provider
    #   safety contracts — it is a gate, not an execution bypass.
    DDOS_READ = "ddos:read"
    DDOS_MANAGE = "ddos:manage"
    DDOS_MITIGATION_APPROVE = "ddos:mitigation_approve"
    BEHAVIOR_READ = "behavior:read"
    BEHAVIOR_MANAGE = "behavior:manage"

    # Cross-Domain Security Correlation & Unified Threat Investigation (M21).
    # READ — view investigation cases, evidence, timeline, graph, posture.
    # MANAGE — acknowledge, start-investigation, resolve cases.
    INVESTIGATIONS_READ = "investigations:read"
    INVESTIGATIONS_MANAGE = "investigations:manage"

    # Enterprise Compliance Assessment (M24 Phase 2).
    # READ — profiles, periods, control assessments.
    # MANAGE — create/activate profiles, open/close periods, confirm
    #   evidence links, advance ControlStatus. Never implies Findings or
    #   Threat Intelligence ownership.
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_MANAGE = "compliance:manage"

    # Enterprise Red Team Platform (M29).
    # Hierarchy (each tier includes lower tiers at the API layer via
    # role mapping; individual endpoints still require the minimum
    # Permission for the action):
    #   reader < analyst < operator < planner < approver < admin < ciso
    # auditor is a parallel read-only path for journal/evidence integrity.
    REDTEAM_READER = "redteam:reader"
    REDTEAM_ANALYST = "redteam:analyst"
    REDTEAM_OPERATOR = "redteam:operator"
    REDTEAM_PLANNER = "redteam:planner"
    REDTEAM_APPROVER = "redteam:approver"
    REDTEAM_ADMIN = "redteam:admin"
    REDTEAM_CISO = "redteam:ciso"
    REDTEAM_AUDITOR = "redteam:auditor"

    # Phase 3B frontend integration — nav-visibility/UI-gating permissions
    # for bounded contexts that previously had no frontend. These gate the
    # frontend nav item and page only; the underlying APIs (incident,
    # threat_hunt, analytics, playbook, ai_posture) still authenticate via
    # JWT-verified tenant context (redforge/api/security.py get_tenant_context)
    # but do not yet enforce require_permission() themselves — see the
    # residual RBAC gap noted in the Phase 3A JWT-migration commits.
    INCIDENT_READ = "incident:read"
    INCIDENT_MANAGE = "incident:manage"
    THREAT_HUNT_READ = "threat_hunt:read"
    THREAT_HUNT_MANAGE = "threat_hunt:manage"
    ANALYTICS_READ = "analytics:read"
    ANALYTICS_MANAGE = "analytics:manage"
    PLAYBOOKS_READ = "playbooks:read"
    PLAYBOOKS_MANAGE = "playbooks:manage"
    AI_POSTURE_READ = "ai_posture:read"
    AI_POSTURE_MANAGE = "ai_posture:manage"


@unique
class MembershipRole(StrEnum):
    """Predefined roles that define permission sets within an Organization.

    - OWNER: Full control. Can delete the organization, transfer ownership.
    - ADMIN: Manage members, targets, validations, and org settings.
    - SECURITY_MANAGER: Full security-data authority (run/manage
      validations, findings, evidence, targets) without org/member
      administration — the "runs the security program" role.
    - ANALYST: Executes and reads security work, cannot manage it.
    - MEMBER: Run validations, view results.
    - VIEWER: Read-only access to results and findings ("Read Only").

    Extending this enum with a new role requires adding one entry to
    ROLE_PERMISSIONS below — no other code branches on role identity
    (see Membership.has_permission). True per-organization custom roles
    (arbitrary admin-defined permission sets, not just a fixed enum) are
    a larger, deliberately deferred feature — see ADR note in
    ROLE_PERMISSIONS' docstring.
    """

    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_MANAGER = "security_manager"
    ANALYST = "analyst"
    MEMBER = "member"
    VIEWER = "viewer"


# Role → Permission mapping
#
# This is the platform's fixed-role RBAC. Every permission check in the
# system (Membership.has_permission, api/security.py's require_permission)
# goes through this single table — there is no second, competing
# authorization mechanism anywhere in the codebase.
#
# Deferred, not implemented: fully custom per-organization roles (an
# admin defining an arbitrary named role with an arbitrary permission
# set, stored per-org rather than in this fixed enum). That is a
# materially different data model (roles become organization-owned data,
# not a platform-wide enum) and is out of scope here — implementing a
# hollow "custom role" API without real per-org storage and enforcement
# would be exactly the kind of placeholder this sprint must not ship.
# The one thing this design does guarantee for that future work: every
# permission check already goes through `frozenset[Permission]`
# membership testing (Membership.has_permission →
# ROLE_PERMISSIONS[role]), not role-name string comparisons — so
# swapping "role: MembershipRole → ROLE_PERMISSIONS[role]" for
# "role: CustomRole → custom_role.permissions" is additive when that
# feature is actually built, not a rewrite of the enforcement path.
ROLE_PERMISSIONS: dict[MembershipRole, frozenset[Permission]] = {
    MembershipRole.OWNER: frozenset(Permission),
    MembershipRole.ADMIN: frozenset({
        Permission.ORG_READ,
        Permission.ORG_MANAGE,
        Permission.MEMBERS_READ,
        Permission.MEMBERS_INVITE,
        Permission.MEMBERS_MANAGE,
        Permission.TARGETS_READ,
        Permission.TARGETS_CREATE,
        Permission.TARGETS_MANAGE,
        Permission.VALIDATIONS_READ,
        Permission.VALIDATIONS_RUN,
        Permission.VALIDATIONS_MANAGE,
        Permission.EVIDENCE_READ,
        Permission.FINDINGS_READ,
        Permission.AUTHORIZATIONS_READ,
        Permission.AUTHORIZATIONS_CREATE,
        Permission.AUTHORIZATIONS_APPROVE,
        Permission.AUTHORIZATIONS_APPROVE_CREDENTIAL,
        Permission.AUTHORIZATIONS_EVALUATE,
        Permission.SECURITY_OPERATIONS_READ,
        Permission.NETWORK_SECURITY_READ,
        Permission.NETWORK_SECURITY_MANAGE,
        Permission.ROLES_READ,
        Permission.ROLES_MANAGE,
        Permission.GROUPS_READ,
        Permission.GROUPS_MANAGE,
        Permission.DDOS_READ,
        Permission.DDOS_MANAGE,
        Permission.DDOS_MITIGATION_APPROVE,
        Permission.BEHAVIOR_READ,
        Permission.BEHAVIOR_MANAGE,
        Permission.INVESTIGATIONS_READ,
        Permission.INVESTIGATIONS_MANAGE,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_MANAGE,
        Permission.REDTEAM_READER,
        Permission.REDTEAM_ANALYST,
        Permission.REDTEAM_OPERATOR,
        Permission.REDTEAM_PLANNER,
        Permission.REDTEAM_APPROVER,
        Permission.REDTEAM_ADMIN,
        Permission.REDTEAM_CISO,
        Permission.REDTEAM_AUDITOR,
        Permission.INCIDENT_READ,
        Permission.INCIDENT_MANAGE,
        Permission.THREAT_HUNT_READ,
        Permission.THREAT_HUNT_MANAGE,
        Permission.ANALYTICS_READ,
        Permission.ANALYTICS_MANAGE,
        Permission.PLAYBOOKS_READ,
        Permission.PLAYBOOKS_MANAGE,
        Permission.AI_POSTURE_READ,
        Permission.AI_POSTURE_MANAGE,
    }),
    MembershipRole.SECURITY_MANAGER: frozenset({
        Permission.ORG_READ,
        Permission.MEMBERS_READ,
        Permission.TARGETS_READ,
        Permission.TARGETS_CREATE,
        Permission.TARGETS_MANAGE,
        Permission.VALIDATIONS_READ,
        Permission.VALIDATIONS_RUN,
        Permission.VALIDATIONS_MANAGE,
        Permission.EVIDENCE_READ,
        Permission.FINDINGS_READ,
        Permission.AUTHORIZATIONS_READ,
        Permission.AUTHORIZATIONS_CREATE,
        Permission.AUTHORIZATIONS_APPROVE,
        Permission.AUTHORIZATIONS_EVALUATE,
        Permission.SECURITY_OPERATIONS_READ,
        Permission.NETWORK_SECURITY_READ,
        Permission.NETWORK_SECURITY_MANAGE,
        Permission.DDOS_READ,
        Permission.DDOS_MANAGE,
        Permission.DDOS_MITIGATION_APPROVE,
        Permission.BEHAVIOR_READ,
        Permission.BEHAVIOR_MANAGE,
        Permission.INVESTIGATIONS_READ,
        Permission.INVESTIGATIONS_MANAGE,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_MANAGE,
        Permission.REDTEAM_READER,
        Permission.REDTEAM_ANALYST,
        Permission.REDTEAM_OPERATOR,
        Permission.REDTEAM_PLANNER,
        Permission.REDTEAM_APPROVER,
        Permission.REDTEAM_ADMIN,
        Permission.REDTEAM_AUDITOR,
        Permission.INCIDENT_READ,
        Permission.INCIDENT_MANAGE,
        Permission.THREAT_HUNT_READ,
        Permission.THREAT_HUNT_MANAGE,
        Permission.ANALYTICS_READ,
        Permission.ANALYTICS_MANAGE,
        Permission.PLAYBOOKS_READ,
        Permission.PLAYBOOKS_MANAGE,
        Permission.AI_POSTURE_READ,
        Permission.AI_POSTURE_MANAGE,
    }),
    MembershipRole.ANALYST: frozenset({
        Permission.ORG_READ,
        Permission.MEMBERS_READ,
        Permission.TARGETS_READ,
        Permission.VALIDATIONS_READ,
        Permission.VALIDATIONS_RUN,
        Permission.EVIDENCE_READ,
        Permission.FINDINGS_READ,
        Permission.AUTHORIZATIONS_READ,
        Permission.AUTHORIZATIONS_CREATE,
        Permission.AUTHORIZATIONS_EVALUATE,
        Permission.SECURITY_OPERATIONS_READ,
        Permission.NETWORK_SECURITY_READ,
        Permission.DDOS_READ,
        Permission.BEHAVIOR_READ,
        Permission.INVESTIGATIONS_READ,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_MANAGE,
        Permission.REDTEAM_READER,
        Permission.REDTEAM_ANALYST,
        Permission.REDTEAM_OPERATOR,
        Permission.REDTEAM_PLANNER,
        Permission.REDTEAM_AUDITOR,
        Permission.INCIDENT_READ,
        Permission.THREAT_HUNT_READ,
        Permission.ANALYTICS_READ,
        Permission.PLAYBOOKS_READ,
        Permission.AI_POSTURE_READ,
    }),
    MembershipRole.MEMBER: frozenset({
        Permission.ORG_READ,
        Permission.MEMBERS_READ,
        Permission.TARGETS_READ,
        Permission.TARGETS_CREATE,
        Permission.VALIDATIONS_READ,
        Permission.VALIDATIONS_RUN,
        Permission.EVIDENCE_READ,
        Permission.FINDINGS_READ,
        Permission.AUTHORIZATIONS_READ,
        Permission.AUTHORIZATIONS_CREATE,
        Permission.AUTHORIZATIONS_EVALUATE,
        Permission.SECURITY_OPERATIONS_READ,
        Permission.NETWORK_SECURITY_READ,
        Permission.DDOS_READ,
        Permission.BEHAVIOR_READ,
        Permission.INVESTIGATIONS_READ,
        Permission.COMPLIANCE_READ,
        Permission.REDTEAM_READER,
        Permission.REDTEAM_ANALYST,
        Permission.REDTEAM_OPERATOR,
        Permission.REDTEAM_AUDITOR,
        Permission.INCIDENT_READ,
        Permission.THREAT_HUNT_READ,
        Permission.ANALYTICS_READ,
        Permission.PLAYBOOKS_READ,
        Permission.AI_POSTURE_READ,
    }),
    MembershipRole.VIEWER: frozenset({
        Permission.ORG_READ,
        Permission.MEMBERS_READ,
        Permission.TARGETS_READ,
        Permission.VALIDATIONS_READ,
        Permission.EVIDENCE_READ,
        Permission.FINDINGS_READ,
        Permission.AUTHORIZATIONS_READ,
        Permission.SECURITY_OPERATIONS_READ,
        Permission.NETWORK_SECURITY_READ,
        Permission.DDOS_READ,
        Permission.BEHAVIOR_READ,
        Permission.INVESTIGATIONS_READ,
        Permission.COMPLIANCE_READ,
        Permission.REDTEAM_READER,
        Permission.REDTEAM_AUDITOR,
        Permission.INCIDENT_READ,
        Permission.THREAT_HUNT_READ,
        Permission.ANALYTICS_READ,
        Permission.AI_POSTURE_READ,
    }),
}


@unique
class MembershipStatus(StrEnum):
    """Fine-grained lifecycle status of a Membership.

    - ACTIVE: Normal standing — grants permissions per role.
    - SUSPENDED: Temporarily paused (e.g., security investigation).
      Membership record and role are preserved; grants no permissions.
      Reversible via reactivate().
    - REMOVED: Permanently revoked. Terminal — a removed user must be
      re-invited to regain access (a new Membership is created).
    """

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REMOVED = "removed"


@unique
class InvitationStatus(StrEnum):
    """Lifecycle status of an organization Invitation.

    - PENDING: Sent, not yet acted on. May still be expired (see
      Invitation.is_expired) even while status is PENDING — expiry is a
      time-based fact, not a stored transition, so it can't go stale.
    - ACCEPTED: The invitee created/linked a Membership. Terminal.
    - REJECTED: The invitee explicitly declined. Terminal.
    - REVOKED: The inviting organization cancelled it before acceptance.
      Terminal.
    """

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    REVOKED = "revoked"


class Email:
    """Validated email address.

    Business rules:
    - Must contain exactly one @ symbol.
    - Must have a local part and domain part.
    - Maximum 254 characters (RFC 5321).
    - Stored in lowercase (case-insensitive matching).
    """

    __slots__ = ("_value",)

    MAX_LENGTH = 254
    _PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    def __init__(self, value: str) -> None:
        normalized = value.strip().lower()
        if len(normalized) > self.MAX_LENGTH:
            raise ValueError(
                f"Email must be at most {self.MAX_LENGTH} characters, got {len(normalized)}"
            )
        if not self._PATTERN.match(normalized):
            raise ValueError(f"Invalid email address: '{value}'")
        self._value = normalized

    @property
    def value(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Email({self._value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Email):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)


class PasswordHash:
    """Opaque password hash value object.

    This does NOT perform hashing — it holds an already-hashed value.
    The actual hashing is an infrastructure concern (bcrypt, argon2, etc.).

    Business rules:
    - Must not be empty.
    - Must not contain the raw password (enforced by convention — callers
      must hash before constructing this object).
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not value or len(value) < 20:
            raise ValueError("Password hash must be a valid hash string (min 20 chars)")
        self._value = value

    @property
    def value(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "PasswordHash(***)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PasswordHash):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)
