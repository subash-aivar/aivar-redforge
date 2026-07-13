"""PlatformAccessService — the sole write/read path for platform privilege.

Every platform-authorization decision in the API layer (see
api/security.py's require_platform_permission) resolves through
`get_access_for_user`, which reads persisted PlatformAssignment rows fresh
on every call. There is no platform claim cached in any JWT — see
docs/M1_PLATFORM_IDENTITY_SUPER_ADMIN_REPORT.md, Section 7, for the
security rationale (this is the same "read live, don't cache in the
token" pattern the codebase already uses for organization-suspension
checks in require_permission).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError

from redforge.core.config import Settings
from redforge.domain.platform_identity.entity import PlatformAssignment
from redforge.domain.platform_identity.exceptions import (
    BootstrapAlreadyConsumedError,
    BootstrapDisabledError,
    BootstrapPrincipalMismatchError,
    DuplicateActivePlatformAssignmentError,
    LastSuperAdminProtectionError,
    NonGrantablePlatformRoleError,
    PlatformAssignmentAlreadyRevokedError,
    PlatformAssignmentNotFoundError,
)
from redforge.domain.platform_identity.value_objects import (
    GRANTABLE_PLATFORM_ROLES_M1,
    PLATFORM_ROLE_PERMISSIONS,
    PlatformAssignmentStatus,
    PlatformPermission,
    PlatformRole,
)
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.platform_identity_repository import (
    SqlAlchemyPlatformAssignmentRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


# ─── DTOs ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PlatformAssignmentDTO:
    id: str
    user_id: str
    role: str
    status: str
    granted_by: str
    granted_at: str
    revoked_by: str | None
    revoked_at: str | None

    @classmethod
    def from_entity(cls, a: PlatformAssignment) -> PlatformAssignmentDTO:
        return cls(
            id=a.id,
            user_id=a.user_id,
            role=a.role.value,
            status=a.status.value,
            granted_by=a.granted_by,
            granted_at=a.granted_at.isoformat(),
            revoked_by=a.revoked_by,
            revoked_at=a.revoked_at.isoformat() if a.revoked_at else None,
        )


@dataclass(frozen=True, slots=True)
class PlatformAccessDTO:
    """Effective platform authorization state for one user — the shape
    returned by GET /platform/me and consumed by require_platform_permission.
    Empty roles/permissions means "no platform privilege," not an error.
    """

    user_id: str
    roles: tuple[str, ...]
    permissions: frozenset[PlatformPermission]

    def has_permission(self, permission: PlatformPermission) -> bool:
        return permission in self.permissions

    @property
    def has_any_platform_role(self) -> bool:
        return len(self.roles) > 0


# ─── Application Service ──────────────────────────────────────────────────────


class PlatformAccessService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings

    # ── Read path (used by API authorization + /platform/me) ────────────────

    async def get_access_for_user(self, user_id: str) -> PlatformAccessDTO:
        """Read-only, live lookup — never cached, never derived from a JWT
        claim or from organization membership.
        """
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyPlatformAssignmentRepository(uow.session)
            active = await repo.list_active_by_user(user_id)

        roles = tuple(a.role.value for a in active)
        permissions: frozenset[PlatformPermission] = frozenset()
        for a in active:
            permissions = permissions | PLATFORM_ROLE_PERMISSIONS[a.role]
        return PlatformAccessDTO(user_id=user_id, roles=roles, permissions=permissions)

    async def list_assignments(
        self, limit: int = 50, offset: int = 0
    ) -> list[PlatformAssignmentDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyPlatformAssignmentRepository(uow.session)
            assignments = await repo.list_all(limit, offset)
        return [PlatformAssignmentDTO.from_entity(a) for a in assignments]

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    async def bootstrap_super_admin(
        self, authenticated_user_id: str, authenticated_email: str
    ) -> PlatformAssignmentDTO:
        """One-time initial Super Admin bootstrap.

        Fails closed: disabled by default; requires an exact
        server-configured email match against the *authenticated*
        principal (never a request-body-supplied identity); the atomic
        claim (repo.claim_bootstrap) makes concurrent attempts race-safe
        at the database level, not via an app-level count check.
        """
        if not self._settings.platform_bootstrap_enabled:
            await self._audit_denied(
                AuditAction.PLATFORM_BOOTSTRAP_DENIED,
                actor_id=authenticated_user_id,
                target_id=authenticated_user_id,
                reason="bootstrap_disabled",
            )
            raise BootstrapDisabledError

        configured_email = self._settings.platform_bootstrap_principal_email.strip().lower()
        if not configured_email or authenticated_email.strip().lower() != configured_email:
            await self._audit_denied(
                AuditAction.PLATFORM_BOOTSTRAP_DENIED,
                actor_id=authenticated_user_id,
                target_id=authenticated_user_id,
                reason="principal_mismatch",
            )
            raise BootstrapPrincipalMismatchError

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyPlatformAssignmentRepository(uow.session)
            won = await repo.claim_bootstrap(authenticated_user_id)
            if not won:
                await uow.commit()
                raise BootstrapAlreadyConsumedError

            now = datetime.now(UTC)
            assignment = PlatformAssignment(
                id=str(EntityId.generate()),
                user_id=authenticated_user_id,
                role=PlatformRole.SUPER_ADMIN,
                status=PlatformAssignmentStatus.ACTIVE,
                granted_by=authenticated_user_id,
                granted_at=now,
                revoked_by=None,
                revoked_at=None,
                version=1,
            )
            await repo.save(assignment)

            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.PLATFORM_BOOTSTRAP_SUCCEEDED,
                    actor_id=authenticated_user_id,
                    resource_type="platform_assignment",
                    resource_id=assignment.id,
                    metadata={"role": PlatformRole.SUPER_ADMIN.value, "outcome": "success"},
                )
            )
            await uow.commit()

        return PlatformAssignmentDTO.from_entity(assignment)

    async def bootstrap_is_available(self) -> bool:
        """Whether bootstrap can still be attempted (config-enabled AND
        not yet consumed). Used by the frontend to decide whether to show
        a bootstrap call-to-action — authoritative decision remains
        server-side at call time regardless of what the UI shows.
        """
        if not self._settings.platform_bootstrap_enabled:
            return False
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyPlatformAssignmentRepository(uow.session)
            consumed = await repo.bootstrap_is_consumed()
        return not consumed

    # ── Grant / Revoke ────────────────────────────────────────────────────────

    async def grant(
        self, target_user_id: str, role: PlatformRole, granted_by: str
    ) -> PlatformAssignmentDTO:
        if role not in GRANTABLE_PLATFORM_ROLES_M1:
            raise NonGrantablePlatformRoleError(role.value)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyPlatformAssignmentRepository(uow.session)

            # Defense in depth, not the race-safety mechanism: this
            # pre-check makes single-request duplicate detection work
            # identically on SQLite (used in fast API tests) and
            # PostgreSQL. The actual race-safety guarantee against two
            # *concurrent* grant requests is the partial unique index
            # from migration 0011 (ux_platform_assignments_user_role_active),
            # which only PostgreSQL enforces — hence the IntegrityError
            # handling below as the authoritative concurrent-safe path.
            existing_active = await repo.list_active_by_user(target_user_id)
            if any(a.role == role for a in existing_active):
                raise DuplicateActivePlatformAssignmentError(target_user_id, role.value)

            now = datetime.now(UTC)
            assignment = PlatformAssignment(
                id=str(EntityId.generate()),
                user_id=target_user_id,
                role=role,
                status=PlatformAssignmentStatus.ACTIVE,
                granted_by=granted_by,
                granted_at=now,
                revoked_by=None,
                revoked_at=None,
                version=1,
            )
            try:
                await repo.save(assignment)
            except IntegrityError as exc:
                await uow.rollback()
                raise DuplicateActivePlatformAssignmentError(
                    target_user_id, role.value
                ) from exc

            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.PLATFORM_ACCESS_GRANTED,
                    actor_id=granted_by,
                    resource_type="platform_assignment",
                    resource_id=assignment.id,
                    metadata={
                        "role": role.value,
                        "target_user_id": target_user_id,
                        "outcome": "success",
                    },
                )
            )
            await uow.commit()

        return PlatformAssignmentDTO.from_entity(assignment)

    async def revoke(
        self, assignment_id: str, revoked_by: str
    ) -> PlatformAssignmentDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyPlatformAssignmentRepository(uow.session)
            assignment = await repo.get_by_id(assignment_id)
            if assignment is None:
                raise PlatformAssignmentNotFoundError(assignment_id)
            if not assignment.is_active:
                raise PlatformAssignmentAlreadyRevokedError(assignment_id)

            # Last-Super-Admin protection: lock all currently-active
            # assignments of this role before deciding. Under READ
            # COMMITTED, a concurrent revoke of a different "last" active
            # assignment serializes on this row lock and re-observes the
            # post-commit state, so this is not a check-then-act race.
            if assignment.role == PlatformRole.SUPER_ADMIN:
                active_super_admins = await repo.lock_active_by_role(
                    PlatformRole.SUPER_ADMIN
                )
                if len(active_super_admins) <= 1:
                    await uow.rollback()
                    raise LastSuperAdminProtectionError(assignment_id)

            revoked = assignment.revoke(revoked_by)
            await repo.save(revoked)

            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.PLATFORM_ACCESS_REVOKED,
                    actor_id=revoked_by,
                    resource_type="platform_assignment",
                    resource_id=assignment_id,
                    metadata={
                        "role": assignment.role.value,
                        "target_user_id": assignment.user_id,
                        "outcome": "success",
                    },
                )
            )
            await uow.commit()

        return PlatformAssignmentDTO.from_entity(revoked)

    # ── Audit query ───────────────────────────────────────────────────────────

    async def query_audit(self, limit: int = 100) -> list[AuditEntry]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            audit = PostgresPlatformAuditLog(uow.session)
            return await audit.query(limit=limit)

    async def _audit_denied(
        self, action: AuditAction, *, actor_id: str, target_id: str, reason: str
    ) -> None:
        async with SessionUnitOfWork(self._session_factory) as uow:
            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=action,
                    actor_id=actor_id,
                    resource_type="platform_assignment",
                    resource_id=target_id,
                    metadata={"outcome": "denied", "reason": reason},
                )
            )
            await uow.commit()
