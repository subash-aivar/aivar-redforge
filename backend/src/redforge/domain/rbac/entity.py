"""OrganizationRole and OrganizationGroup aggregates — M17.

Both are simple, organization-owned aggregates. Membership rows
(user<->group, group<->role, user<->role) are deliberately NOT modeled
as rich entities — they are pure join facts with no lifecycle of their
own beyond "exists or does not," enforced by database uniqueness
constraints (see migration 0026) and mutated atomically by the
repository layer. This mirrors the existing platform_identity precedent
of keeping join-shaped data thin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.rbac.exceptions import SystemRoleImmutableError
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from redforge.domain.identity.value_objects import Permission
    from redforge.shared.identifiers import EntityId


def normalize_name(name: str) -> str:
    """Canonical normalized-name form for uniqueness checks — lowercase,
    single-spaced. Mirrors the discipline already used for OrganizationSlug
    /connector names elsewhere in the platform: uniqueness is enforced on
    a normalized projection, never on the raw display string."""
    return " ".join(name.strip().lower().split())


class OrganizationRole:
    """A custom, organization-scoped role: a named, admin-defined set of
    `Permission`s. Entirely separate from the fixed `MembershipRole` enum
    (OWNER/ADMIN/.../VIEWER) — a user can hold a MembershipRole AND any
    number of OrganizationRoles (direct or group-derived) at once; their
    effective permissions are the union (see
    application/rbac/effective_access_service.py).

    Never able to carry platform authority: `permissions` is typed
    `frozenset[Permission]`, the same closed enum every other tenant
    permission check already uses — there is no code path by which a
    `PlatformPermission` value could enter this set.
    """

    __slots__ = (
        "_description", "_events", "_id", "_is_system", "_name",
        "_organization_id", "_permissions", "_timestamps", "_version",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        name: str,
        description: str,
        permissions: frozenset[Permission],
        timestamps: AuditTimestamps,
        is_system: bool = False,
        version: int = 1,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._name = name
        self._description = description
        self._permissions = permissions
        self._timestamps = timestamps
        self._is_system = is_system
        self._version = version
        self._events: list[object] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        name: str,
        description: str,
        permissions: frozenset[Permission],
    ) -> OrganizationRole:
        from redforge.shared.identifiers import EntityId as _EntityId

        return cls(
            id=_EntityId.generate(), organization_id=organization_id, name=name,
            description=description, permissions=permissions,
            timestamps=AuditTimestamps.create(), is_system=False, version=1,
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def permissions(self) -> frozenset[Permission]:
        return self._permissions

    @property
    def is_system(self) -> bool:
        return self._is_system

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def version(self) -> int:
        return self._version

    def _guard_mutable(self) -> None:
        if self._is_system:
            raise SystemRoleImmutableError

    def rename(self, name: str, description: str) -> None:
        self._guard_mutable()
        self._name = name
        self._description = description
        self._timestamps = self._timestamps.mark_updated()
        self._version += 1

    def set_permissions(self, permissions: frozenset[Permission]) -> None:
        self._guard_mutable()
        self._permissions = permissions
        self._timestamps = self._timestamps.mark_updated()
        self._version += 1


class OrganizationGroup:
    """A tenant-scoped security group. Belongs to exactly one
    organization; a user may belong to many groups. Membership and role
    assignment are pure join rows (see module docstring), mutated only
    through the repository — this aggregate carries only the group's own
    metadata."""

    __slots__ = (
        "_description", "_events", "_id", "_name", "_organization_id", "_timestamps", "_version",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        name: str,
        description: str,
        timestamps: AuditTimestamps,
        version: int = 1,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._name = name
        self._description = description
        self._timestamps = timestamps
        self._version = version
        self._events: list[object] = []

    @classmethod
    def create(cls, organization_id: EntityId, name: str, description: str) -> OrganizationGroup:
        from redforge.shared.identifiers import EntityId as _EntityId

        return cls(
            id=_EntityId.generate(), organization_id=organization_id, name=name,
            description=description, timestamps=AuditTimestamps.create(), version=1,
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def version(self) -> int:
        return self._version

    def rename(self, name: str, description: str) -> None:
        self._name = name
        self._description = description
        self._timestamps = self._timestamps.mark_updated()
        self._version += 1
