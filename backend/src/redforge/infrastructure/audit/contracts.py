"""Audit logging contracts.

Protocol-based abstraction for immutable audit event storage.
Implementations: in-memory (testing), structlog (stdout/file),
PostgreSQL (persistent), Kafka (streaming), CloudWatch/Datadog (SaaS).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class AuditAction(StrEnum):
    """Categorized audit actions for filtering and reporting."""

    # Authentication
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_REGISTER = "auth.register"
    AUTH_TOKEN_REFRESH = "auth.token_refresh"
    AUTH_LOGOUT = "auth.logout"

    # Organizations
    ORG_CREATED = "org.created"
    ORG_RENAMED = "org.renamed"
    ORG_DEACTIVATED = "org.deactivated"
    ORG_ACTIVATED = "org.activated"
    ORG_SUSPENDED = "org.suspended"

    # Users
    USER_ROLE_CHANGED = "user.role_changed"
    USER_DEACTIVATED = "user.deactivated"

    # Memberships
    MEMBERSHIP_CREATED = "membership.created"
    MEMBERSHIP_ROLE_CHANGED = "membership.role_changed"
    MEMBERSHIP_SUSPENDED = "membership.suspended"
    MEMBERSHIP_REACTIVATED = "membership.reactivated"
    MEMBERSHIP_REMOVED = "membership.removed"
    MEMBERSHIP_OWNERSHIP_TRANSFERRED = "membership.ownership_transferred"

    # Invitations
    INVITATION_SENT = "invitation.sent"
    INVITATION_RESENT = "invitation.resent"
    INVITATION_ACCEPTED = "invitation.accepted"
    INVITATION_REJECTED = "invitation.rejected"
    INVITATION_REVOKED = "invitation.revoked"

    # AI Targets
    TARGET_REGISTERED = "target.registered"
    TARGET_DEACTIVATED = "target.deactivated"

    # Validations
    VALIDATION_SCHEDULED = "validation.scheduled"
    VALIDATION_COMPLETED = "validation.completed"
    VALIDATION_CANCELLED = "validation.cancelled"

    # Policies
    POLICY_CREATED = "policy.created"
    POLICY_UPDATED = "policy.updated"
    POLICY_DELETED = "policy.deleted"

    # Providers
    PROVIDER_REGISTERED = "provider.registered"
    PROVIDER_DISABLED = "provider.disabled"
    PROVIDER_ENABLED = "provider.enabled"

    # Administrative
    ADMIN_CONFIG_CHANGED = "admin.config_changed"
    ADMIN_RATE_LIMIT_RESET = "admin.rate_limit_reset"

    # Platform identity (M1) — platform-wide privilege, independent of
    # organization membership. See domain.platform_identity.
    PLATFORM_BOOTSTRAP_SUCCEEDED = "platform.bootstrap_succeeded"
    PLATFORM_BOOTSTRAP_DENIED = "platform.bootstrap_denied"
    PLATFORM_ACCESS_GRANTED = "platform.access_granted"
    PLATFORM_ACCESS_REVOKED = "platform.access_revoked"
    PLATFORM_ACCESS_DENIED = "platform.access_denied"

    # MFA / privileged assurance (M2)
    MFA_ENROLLMENT_STARTED = "mfa.enrollment_started"
    MFA_FACTOR_ACTIVATED = "mfa.factor_activated"
    MFA_FACTOR_REVOKED = "mfa.factor_revoked"
    MFA_ASSURANCE_ESTABLISHED = "mfa.assurance_established"
    MFA_ASSURANCE_DENIED = "mfa.assurance_denied"

    # Platform governance (M2)
    PLATFORM_USER_SUSPENDED = "platform.user_suspended"
    PLATFORM_USER_REACTIVATED = "platform.user_reactivated"
    PLATFORM_ORG_SUSPENDED = "platform.org_suspended"
    PLATFORM_ORG_REACTIVATED = "platform.org_reactivated"

    # Security Authorization & Execution Policy (M10)
    AUTHORIZATION_CREATED = "authorization.created"
    AUTHORIZATION_SUBMITTED = "authorization.submitted"
    AUTHORIZATION_APPROVED = "authorization.approved"
    AUTHORIZATION_REJECTED = "authorization.rejected"
    AUTHORIZATION_REVOKED = "authorization.revoked"
    EXECUTION_POLICY_DECIDED = "execution_policy.decided"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """Immutable audit log entry.

    Once created, entries cannot be modified or deleted.
    This is a compliance requirement for SOC2, ISO 27001, GDPR.
    """

    action: AuditAction
    actor_id: str  # user_id or "system"
    resource_type: str  # e.g., "organization", "user", "ai_target"
    resource_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    ip_address: str = ""
    correlation_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class AuditLog(Protocol):
    """Port for audit event persistence.

    Implementations must be append-only. No update or delete operations.
    """

    async def record(self, entry: AuditEntry) -> None:
        """Append an audit entry. Must not fail silently."""
        ...

    async def query(
        self,
        *,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        action: AuditAction | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with filters. Returns newest first."""
        ...
