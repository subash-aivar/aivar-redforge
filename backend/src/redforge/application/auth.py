"""Authentication application service.

Coordinates user registration, login, token refresh, and session management.
Framework-independent — can be called from REST, CLI, MCP, or workers.

Transaction boundaries are managed by SessionUnitOfWork.
Repositories NEVER commit — only UoW does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.core.exceptions import AuthenticationError
from redforge.domain.identity.entities import User
from redforge.domain.identity.exceptions import UserAlreadyExistsError
from redforge.domain.identity.value_objects import Email, PasswordHash
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.contracts import EventPublisherPort
    from redforge.infrastructure.auth.contracts import (
        PasswordHasher,
        TokenService,
    )

__all__ = ["AuthResult", "AuthService", "AuthenticationError", "UserProfile"]


@dataclass(frozen=True, slots=True)
class AuthResult:
    """Result of successful authentication."""

    user_id: str
    email: str
    display_name: str
    access_token: str
    refresh_token: str
    expires_in: int


@dataclass(frozen=True, slots=True)
class UserProfile:
    """Current user profile from token."""

    user_id: str
    email: str
    display_name: str
    status: str


class AuthService:
    """Enterprise authentication service.

    Orchestrates: user repo → password verification → token generation.
    Stateless — no server-side sessions. Tokens carry all claims.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        password_hasher: PasswordHasher,
        token_service: TokenService,
        event_publisher: EventPublisherPort,
    ) -> None:
        self._session_factory = session_factory
        self._hasher = password_hasher
        self._tokens = token_service
        self._events = event_publisher

    async def register(
        self, email: str, display_name: str, password: str
    ) -> AuthResult:
        """Register a new user and return tokens."""
        from redforge.infrastructure.auth.contracts import TokenPayload
        from redforge.infrastructure.database.repositories.user_repository import (
            SqlAlchemyUserRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        email_vo = Email(email)
        hashed = self._hasher.hash(password)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyUserRepository(uow.session)

            if await repo.email_exists(email_vo):
                raise UserAlreadyExistsError(email)

            user = User.register(
                email=email_vo,
                display_name=display_name,
                password_hash=PasswordHash(hashed),
            )
            await repo.save(user)
            await uow.commit()

        events = user.collect_events()
        await self._events.publish(events)

        tokens = self._tokens.create_tokens(
            TokenPayload(sub=str(user.id), email=str(user.email))
        )
        return AuthResult(
            user_id=str(user.id),
            email=str(user.email),
            display_name=user.display_name,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.access_expires_in,
        )

    async def login(self, email: str, password: str) -> AuthResult:
        """Authenticate with email + password, return tokens."""
        from redforge.infrastructure.auth.contracts import TokenPayload
        from redforge.infrastructure.database.repositories.user_repository import (
            SqlAlchemyUserRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        email_vo = Email(email)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyUserRepository(uow.session)
            user = await repo.get_by_email(email_vo)

        if user is None:
            raise AuthenticationError("Invalid credentials")
        if not user.is_active:
            raise AuthenticationError("Account is not active")
        if user.password_hash is None:
            raise AuthenticationError("Account has no password set")
        if not self._hasher.verify(password, user.password_hash.value):
            raise AuthenticationError("Invalid credentials")

        tokens = self._tokens.create_tokens(
            TokenPayload(sub=str(user.id), email=str(user.email))
        )
        return AuthResult(
            user_id=str(user.id),
            email=str(user.email),
            display_name=user.display_name,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.access_expires_in,
        )

    async def refresh(self, refresh_token: str) -> AuthResult:
        """Refresh an expired access token using a valid refresh token."""
        from redforge.infrastructure.auth.contracts import TokenPayload
        from redforge.infrastructure.database.repositories.user_repository import (
            SqlAlchemyUserRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        payload = self._tokens.decode_refresh_token(refresh_token)
        if payload is None:
            raise AuthenticationError("Invalid refresh token")

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyUserRepository(uow.session)
            user = await repo.get_by_id(EntityId.from_string(payload.sub))

        if user is None or not user.is_active:
            raise AuthenticationError("User not found or inactive")

        tokens = self._tokens.create_tokens(
            TokenPayload(sub=str(user.id), email=str(user.email))
        )
        return AuthResult(
            user_id=str(user.id),
            email=str(user.email),
            display_name=user.display_name,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.access_expires_in,
        )

    async def select_organization(
        self, access_token: str, organization_id: str
    ) -> AuthResult:
        """Exchange a valid access token for one scoped to an organization.

        This is the ONLY place the platform ever mints a token carrying
        `organization_id`/`role` claims, and it does so only after
        independently verifying an active Membership row exists —
        the caller's requested organization_id is never trusted, it is
        checked. See api/security.py for how the resulting scoped token
        is consumed (TenantContext).
        """
        from redforge.domain.identity.exceptions import MembershipNotFoundError
        from redforge.infrastructure.auth.contracts import TokenPayload
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.repositories.user_repository import (
            SqlAlchemyUserRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        payload = self._tokens.decode_access_token(access_token)
        if payload is None:
            raise AuthenticationError("Invalid or expired access token")

        user_id = EntityId.from_string(payload.sub)
        try:
            org_id = EntityId.from_string(organization_id)
        except ValueError as exc:
            raise MembershipNotFoundError(organization_id) from exc

        async with SessionUnitOfWork(self._session_factory) as uow:
            user_repo = SqlAlchemyUserRepository(uow.session)
            user = await user_repo.get_by_id(user_id)
            if user is None or not user.is_active:
                raise AuthenticationError("User not found or inactive")

            membership_repo = SqlAlchemyMembershipRepository(uow.session)
            membership = await membership_repo.get_by_user_and_org(user_id, org_id)

        if membership is None or not membership.is_active:
            raise MembershipNotFoundError(organization_id)

        tokens = self._tokens.create_tokens(
            TokenPayload(
                sub=str(user.id),
                email=str(user.email),
                organization_id=str(membership.organization_id),
                role=str(membership.role),
            )
        )
        return AuthResult(
            user_id=str(user.id),
            email=str(user.email),
            display_name=user.display_name,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.access_expires_in,
        )

    async def get_current_user(self, access_token: str) -> UserProfile:
        """Validate token and return current user profile."""
        from redforge.infrastructure.database.repositories.user_repository import (
            SqlAlchemyUserRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        payload = self._tokens.decode_access_token(access_token)
        if payload is None:
            raise AuthenticationError("Invalid or expired token")

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyUserRepository(uow.session)
            user = await repo.get_by_id(EntityId.from_string(payload.sub))

        if user is None:
            raise AuthenticationError("User not found")

        # M2: live status re-check — this endpoint constructs its own
        # AuthenticatedPrincipal-equivalent independently of
        # api/security.py's get_current_principal, so it needs its own
        # copy of the same live-suspension check (a signed, unexpired
        # token proves identity at issuance time, not current standing).
        if not user.is_active:
            raise AuthenticationError("Account is not active")

        return UserProfile(
            user_id=str(user.id),
            email=str(user.email),
            display_name=user.display_name,
            status=str(user.status),
        )

    async def get_accessible_organizations(
        self, access_token: str
    ) -> list[object]:
        """Return organizations reachable through the caller's ACTIVE memberships.

        Identity comes exclusively from the validated token — callers never
        supply a user_id directly.  Only active memberships are returned
        (see SqlAlchemyMembershipRepository.list_by_user for the status filter).
        """
        from redforge.application.organizations import OrganizationDTO
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.repositories.organization_repository import (
            SqlAlchemyOrganizationRepository,
        )
        from redforge.infrastructure.database.repositories.user_repository import (
            SqlAlchemyUserRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        payload = self._tokens.decode_access_token(access_token)
        if payload is None:
            raise AuthenticationError("Invalid or expired token")

        user_id = EntityId.from_string(payload.sub)

        async with SessionUnitOfWork(self._session_factory) as uow:
            user_repo = SqlAlchemyUserRepository(uow.session)
            user = await user_repo.get_by_id(user_id)
            if user is None or not user.is_active:
                raise AuthenticationError("User not found or inactive")

            membership_repo = SqlAlchemyMembershipRepository(uow.session)
            org_repo = SqlAlchemyOrganizationRepository(uow.session)

            memberships = await membership_repo.list_by_user(user_id)
            result: list[OrganizationDTO] = []
            for m in memberships:
                org = await org_repo.get_by_id(m.organization_id)
                if org is not None:
                    result.append(OrganizationDTO.from_entity(org))

        return result


class UserStatusService:
    """Live user-account-status lookup — the M2 counterpart to
    `require_permission`'s live organization-suspension check.

    A signed, unexpired JWT proves "this user authenticated successfully
    at token-issuance time." It does NOT prove the account is still in
    good standing now. Before M2, no code path re-checked this, so
    suspending a user had no effect until their token happened to expire.
    Every authenticated request (`get_current_principal`,
    `get_tenant_context`, `get_platform_context` in api/security.py) now
    calls `get_status` and denies access if the account is not ACTIVE.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_status(self, user_id: str) -> str | None:
        from sqlalchemy import select

        from redforge.infrastructure.database.models.user import UserModel
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            result = await uow.session.execute(
                select(UserModel.status).where(UserModel.id == user_id)
            )
            row = result.first()
        return row[0] if row else None
