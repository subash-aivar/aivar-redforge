"""PlatformAssignment entity — the persisted, auditable unit of platform
privilege. A user's effective platform permissions are the union of the
permission sets of every ACTIVE assignment they hold — never inferred from
organization membership or role.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime

from redforge.domain.platform_identity.exceptions import (
    PlatformAssignmentAlreadyRevokedError,
)
from redforge.domain.platform_identity.value_objects import (
    PLATFORM_ROLE_PERMISSIONS,
    PlatformAssignmentStatus,
    PlatformPermission,
    PlatformRole,
)


@dataclass(frozen=True, slots=True)
class PlatformAssignment:
    """A single grant of one PlatformRole to one user.

    Immutable — revoke() returns a new instance rather than mutating in
    place, consistent with the rest of the domain layer's value-object
    style. Persistence (repository) is responsible for optimistic
    concurrency via `version`.
    """

    id: str
    user_id: str
    role: PlatformRole
    status: PlatformAssignmentStatus
    granted_by: str
    granted_at: datetime
    revoked_by: str | None
    revoked_at: datetime | None
    version: int

    @property
    def is_active(self) -> bool:
        return self.status == PlatformAssignmentStatus.ACTIVE

    @property
    def permissions(self) -> frozenset[PlatformPermission]:
        if not self.is_active:
            return frozenset()
        return PLATFORM_ROLE_PERMISSIONS[self.role]

    def revoke(self, revoked_by: str) -> PlatformAssignment:
        """Return a revoked copy. Raises if already revoked.

        Callers (the application service) are responsible for enforcing
        last-Super-Admin protection *before* calling this — that check
        requires querying sibling assignments, which is out of scope for
        a single-entity invariant.
        """
        if not self.is_active:
            raise PlatformAssignmentAlreadyRevokedError(self.id)
        return replace(
            self,
            status=PlatformAssignmentStatus.REVOKED,
            revoked_by=revoked_by,
            revoked_at=datetime.now(UTC),
            version=self.version + 1,
        )
