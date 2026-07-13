"""Application service for Invitation lifecycle use cases.

Orchestrates: duplicate-prevention → Invitation creation → notification
delivery → (later) acceptance/rejection/revocation/resend, each
producing an audit trail entry. Transaction boundaries are managed by
SessionUnitOfWork; repositories never commit.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.memberships.service import MembershipDTO
from redforge.domain.identity.entities import Invitation, Membership
from redforge.domain.identity.exceptions import (
    DuplicateInvitationError,
    InvitationNotFoundError,
    MembershipAlreadyExistsError,
)
from redforge.domain.identity.value_objects import Email, MembershipRole
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from datetime import timedelta

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.contracts import EventPublisherPort
    from redforge.domain.identity.repository import InvitationRepository
    from redforge.infrastructure.audit.contracts import AuditEntry, AuditLog
    from redforge.infrastructure.notifications.contracts import InvitationNotifier


@dataclass(frozen=True, slots=True)
class InvitationDTO:
    """Application-layer representation of an Invitation.

    Never carries the plaintext token — only a caller holding the
    original create()/resend() return value has that.
    """

    id: str
    organization_id: str
    email: str
    role: str
    invited_by_user_id: str
    status: str
    expires_at: str
    accepted_by_user_id: str | None
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, invitation: Invitation) -> InvitationDTO:
        return cls(
            id=str(invitation.id),
            organization_id=str(invitation.organization_id),
            email=str(invitation.email),
            role=str(invitation.role),
            invited_by_user_id=str(invitation.invited_by_user_id),
            status=str(invitation.status),
            expires_at=invitation.expires_at.isoformat(),
            accepted_by_user_id=(
                str(invitation.accepted_by_user_id)
                if invitation.accepted_by_user_id
                else None
            ),
            created_at=invitation.timestamps.created_at.isoformat(),
            updated_at=invitation.timestamps.updated_at.isoformat(),
        )


class InvitationService:
    """Orchestrates the full Invitation lifecycle."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: EventPublisherPort,
        audit_log: AuditLog,
        notifier: InvitationNotifier,
    ) -> None:
        self._session_factory = session_factory
        self._event_publisher = event_publisher
        self._audit_log = audit_log
        self._notifier = notifier

    async def invite(
        self,
        organization_id: str,
        organization_name: str,
        email: str,
        role: str,
        invited_by_user_id: str,
        ttl: timedelta | None = None,
    ) -> InvitationDTO:
        """Create and send a new Invitation.

        Raises:
            DuplicateInvitationError: If a PENDING invitation already
                exists for this (organization, email) — call resend()
                instead.
            MembershipAlreadyExistsError: If the email already belongs
                to an active member of this organization.
        """
        from redforge.infrastructure.database.repositories.invitation_repository import (
            SqlAlchemyInvitationRepository,
        )
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.repositories.user_repository import (
            SqlAlchemyUserRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        email_vo = Email(email)
        role_vo = MembershipRole(role)
        kwargs = {"ttl": ttl} if ttl is not None else {}

        async with SessionUnitOfWork(self._session_factory) as uow:
            invitation_repo = SqlAlchemyInvitationRepository(uow.session)
            membership_repo = SqlAlchemyMembershipRepository(uow.session)
            user_repo = SqlAlchemyUserRepository(uow.session)

            existing = await invitation_repo.get_pending_by_org_and_email(org_id, email_vo)
            if existing is not None:
                raise DuplicateInvitationError(organization_id, email)

            existing_user = await user_repo.get_by_email(email_vo)
            if existing_user is not None:
                already_member = await membership_repo.get_by_user_and_org(
                    existing_user.id, org_id
                )
                if already_member is not None and already_member.is_active:
                    raise MembershipAlreadyExistsError(str(existing_user.id), organization_id)

            invitation, token = Invitation.create(
                organization_id=org_id,
                email=email_vo,
                role=role_vo,
                invited_by_user_id=EntityId.from_string(invited_by_user_id),
                **kwargs,
            )
            await invitation_repo.save(invitation)
            await uow.commit()

        await self._notifier.send_invitation(
            email=email,
            organization_name=organization_name,
            role=role,
            token=token,
            expires_at=invitation.expires_at,
        )
        await self._event_publisher.publish(invitation.collect_events())
        await self._audit_log.record(self._entry(
            action="invitation.sent", actor_id=invited_by_user_id,
            resource_id=str(invitation.id), organization_id=organization_id,
            metadata={"email": email, "role": role},
        ))
        return InvitationDTO.from_entity(invitation)

    async def resend(
        self, organization_id: str, invitation_id: str, actor_user_id: str,
        ttl: timedelta | None = None,
    ) -> InvitationDTO:
        """Reissue a fresh token/expiry for a still-pending invitation.
        The previously issued token is invalidated (see
        Invitation.resend's docstring)."""
        from redforge.infrastructure.database.repositories.invitation_repository import (
            SqlAlchemyInvitationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        kwargs = {"ttl": ttl} if ttl is not None else {}

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyInvitationRepository(uow.session)
            invitation = await self._load_in_org(repo, invitation_id, organization_id)
            token = invitation.resend(**kwargs)
            await repo.save(invitation)
            await uow.commit()

        await self._notifier.send_invitation(
            email=str(invitation.email),
            organization_name="",  # caller-side org name lookup is a presentation concern
            role=str(invitation.role),
            token=token,
            expires_at=invitation.expires_at,
        )
        await self._event_publisher.publish(invitation.collect_events())
        await self._audit_log.record(self._entry(
            action="invitation.resent", actor_id=actor_user_id,
            resource_id=str(invitation.id), organization_id=organization_id,
            metadata={"email": str(invitation.email)},
        ))
        return InvitationDTO.from_entity(invitation)

    async def revoke(
        self, organization_id: str, invitation_id: str, actor_user_id: str,
    ) -> InvitationDTO:
        """Cancel a pending invitation before it is acted on."""
        from redforge.infrastructure.database.repositories.invitation_repository import (
            SqlAlchemyInvitationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyInvitationRepository(uow.session)
            invitation = await self._load_in_org(repo, invitation_id, organization_id)
            invitation.revoke(EntityId.from_string(actor_user_id))
            await repo.save(invitation)
            await uow.commit()

        await self._event_publisher.publish(invitation.collect_events())
        await self._audit_log.record(self._entry(
            action="invitation.revoked", actor_id=actor_user_id,
            resource_id=str(invitation.id), organization_id=organization_id,
            metadata={"email": str(invitation.email)},
        ))
        return InvitationDTO.from_entity(invitation)

    async def list_by_organization(
        self, organization_id: str, status: str | None = None,
    ) -> list[InvitationDTO]:
        from redforge.infrastructure.database.repositories.invitation_repository import (
            SqlAlchemyInvitationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyInvitationRepository(uow.session)
            invitations = await repo.list_by_organization(
                EntityId.from_string(organization_id), status,
            )
        return [InvitationDTO.from_entity(i) for i in invitations]

    # ─── Acceptance / rejection (token-authenticated, no org membership yet) ──

    async def accept(
        self, token: str, accepting_user_id: str, accepting_email: str,
    ) -> tuple[InvitationDTO, MembershipDTO]:
        """Accept an invitation using its plaintext token, creating a
        Membership for `accepting_user_id`.

        Idempotent for repeated identical acceptance, including under
        genuine concurrency: two callers racing the exact same
        (token, user) both reach the "no existing membership yet" read
        before either commits, so a naive read-then-write would insert
        two rows and let the database's UNIQUE(user_id, organization_id)
        constraint fail the second one with a raw IntegrityError. This
        method catches exactly that conflict and retries the whole
        read-mutate-write attempt from scratch in a fresh transaction —
        the retry's fresh read sees the winner's now-committed state
        (invitation already accepted by this user, membership already
        present) and the idempotent branches short-circuit into the
        same successful result the caller would have gotten by winning
        outright. No raw database error, and never two Memberships. A
        bounded retry count guards against livelock. See the
        concurrent-acceptance test in
        tests/integration/test_invitation_service.py for the regression
        this guards.

        Raises:
            InvitationNotFoundError: If the token doesn't match any invitation.
            InvitationExpiredError / InvitationAlreadyProcessedError /
            InvitationEmailMismatchError: See Invitation.accept.
            OrganizationInactiveError: If the invitation's organization
                has been suspended since the invitation was sent. This
                check cannot be covered by the shared
                api/security.py::require_permission enforcement point —
                the accepting caller has no TenantContext yet (they are
                not a member of the organization until this call
                succeeds) — so it is enforced here directly, on the one
                organization-scoped operation that is deliberately
                reachable without a scoped token.
        """
        from sqlalchemy.exc import IntegrityError

        from redforge.domain.organizations.exceptions import OrganizationInactiveError
        from redforge.infrastructure.database.repositories.invitation_repository import (
            SqlAlchemyInvitationRepository,
        )
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.repositories.organization_repository import (
            SqlAlchemyOrganizationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        accepting_id = EntityId.from_string(accepting_user_id)
        email_vo = Email(accepting_email)

        max_attempts = 5
        last_error: IntegrityError | None = None
        for _attempt in range(max_attempts):
            try:
                async with SessionUnitOfWork(self._session_factory) as uow:
                    invitation_repo = SqlAlchemyInvitationRepository(uow.session)
                    invitation = await invitation_repo.get_by_token_hash(token_hash)
                    if invitation is None:
                        raise InvitationNotFoundError("<token>")

                    org_repo = SqlAlchemyOrganizationRepository(uow.session)
                    organization = await org_repo.get_by_id(invitation.organization_id)
                    if organization is not None and organization.status.value == "suspended":
                        raise OrganizationInactiveError(str(invitation.organization_id))

                    membership_repo = SqlAlchemyMembershipRepository(uow.session)
                    already = await membership_repo.get_by_user_and_org(
                        accepting_id, invitation.organization_id,
                    )

                    was_already_accepted = invitation.status.value == "accepted"
                    invitation.accept(accepting_id, email_vo)
                    await invitation_repo.save(invitation)

                    membership: Membership
                    if already is not None:
                        # Sequential-replay path: Membership already exists
                        # from a prior successful accept() call — do not
                        # create a second one or re-emit MembershipCreated.
                        membership = already
                    else:
                        membership = Membership.create(
                            user_id=accepting_id,
                            organization_id=invitation.organization_id,
                            role=invitation.role,
                        )
                        await membership_repo.save(membership)

                    await uow.commit()
            except IntegrityError as exc:
                # Concurrent-replay path: another request for the same
                # (token, user) committed a Membership between our read
                # and our write. Retry from a fresh transaction — its
                # read will observe the winner's committed state and
                # take the idempotent branch instead of racing again.
                last_error = exc
                continue

            events: list[object] = list(invitation.collect_events())
            if not was_already_accepted:
                events.extend(membership.collect_events())
            await self._event_publisher.publish(events)
            await self._audit_log.record(self._entry(
                action="invitation.accepted", actor_id=accepting_user_id,
                resource_id=str(invitation.id),
                organization_id=str(invitation.organization_id),
                metadata={"email": accepting_email},
            ))
            return InvitationDTO.from_entity(invitation), MembershipDTO.from_entity(membership)

        # Exhausted retries under sustained contention — surface the
        # underlying database error rather than silently misreporting
        # success or failure.
        assert last_error is not None
        raise last_error
        return InvitationDTO.from_entity(invitation), MembershipDTO.from_entity(membership)

    async def reject(self, token: str) -> InvitationDTO:
        """Explicitly decline an invitation using its plaintext token."""
        from redforge.infrastructure.database.repositories.invitation_repository import (
            SqlAlchemyInvitationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyInvitationRepository(uow.session)
            invitation = await repo.get_by_token_hash(token_hash)
            if invitation is None:
                raise InvitationNotFoundError("<token>")
            invitation.reject()
            await repo.save(invitation)
            await uow.commit()

        await self._event_publisher.publish(invitation.collect_events())
        await self._audit_log.record(self._entry(
            action="invitation.rejected", actor_id=str(invitation.email),
            resource_id=str(invitation.id),
            organization_id=str(invitation.organization_id),
            metadata={"email": str(invitation.email)},
        ))
        return InvitationDTO.from_entity(invitation)

    # ─── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    async def _load_in_org(
        repo: InvitationRepository, invitation_id: str, organization_id: str
    ) -> Invitation:
        invitation = await repo.get_by_id(EntityId.from_string(invitation_id))
        if invitation is None or str(invitation.organization_id) != organization_id:
            raise InvitationNotFoundError(invitation_id)
        return invitation

    @staticmethod
    def _entry(
        *, action: str, actor_id: str, resource_id: str, organization_id: str,
        metadata: dict[str, str],
    ) -> AuditEntry:
        from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry

        return AuditEntry(
            action=AuditAction(action),
            actor_id=actor_id,
            resource_type="invitation",
            resource_id=resource_id,
            metadata={"organization_id": organization_id, **metadata},
        )
