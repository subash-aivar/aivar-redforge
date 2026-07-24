"""Integration tests for InvitationService — duplicate prevention,
accept/reject/revoke/resend, idempotent acceptance (replay protection),
and simulated concurrent acceptance.

InvitationDTO never carries the plaintext token by design (see
InvitationDTO's docstring) — tests retrieve it from the
InMemoryInvitationNotifier fixture, the same way a real email delivery
system would be the only place the token exists after invite()/resend()
return.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.invitations import InvitationService
from redforge.domain.identity.entities import Membership, User
from redforge.domain.identity.exceptions import (
    DuplicateInvitationError,
    InvitationAlreadyProcessedError,
    InvitationEmailMismatchError,
    InvitationNotFoundError,
    MembershipAlreadyExistsError,
    OwnerAssignmentNotAllowedError,
)
from redforge.domain.identity.value_objects import Email, MembershipRole, PasswordHash
from redforge.domain.organizations.exceptions import OrganizationInactiveError
from redforge.infrastructure.audit.logger import InMemoryAuditLog
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import (  # noqa: F401
    InvitationModel,
    MembershipModel,
    OrganizationModel,
    UserModel,
)
from redforge.infrastructure.database.repositories.membership_repository import (
    SqlAlchemyMembershipRepository,
)
from redforge.infrastructure.database.repositories.organization_repository import (
    SqlAlchemyOrganizationRepository,
)
from redforge.infrastructure.database.repositories.user_repository import (
    SqlAlchemyUserRepository,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.notifications.logging_notifier import (
    InMemoryInvitationNotifier,
)
from redforge.shared.identifiers import EntityId


@pytest.fixture
async def session_factory() -> async_sessionmaker[AsyncSession]:
    # A plain in-memory SQLite URL hands each new pooled connection a
    # SEPARATE, empty in-memory database — invisible to each other —
    # so the concurrent-acceptance test below (which opens two sessions
    # "at once" and needs them to see the same durable data, as any
    # real Postgres deployment would) needs a shared backing store.
    #
    # StaticPool looked like the fix but is wrong for this: it forces
    # every session onto the SAME physical DBAPI connection, and SQLite
    # only allows one transaction at a time per connection — two
    # concurrently-open AsyncSessions sharing one connection interleave
    # their BEGIN/COMMIT calls with no isolation between them, which
    # silently corrupts the very race we're trying to exercise (writes
    # go through without the UNIQUE-constraint conflict they should hit,
    # and one session's commit isn't visible to a "concurrent" session's
    # read even after it lands). A temp-file-backed database gives each
    # session its OWN connection, with SQLite's normal file-level
    # locking providing real cross-connection isolation — the same
    # shape of concurrency control a real Postgres pool provides.
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        engine = create_async_engine(
            f"sqlite+aiosqlite:///{db_path}", echo=False,
            connect_args={"timeout": 30},
        )
        async with engine.begin() as conn:
            await conn.run_sync(
            Base.metadata.create_all,
            tables=[t for t in Base.metadata.sorted_tables if t.schema is None],
        )
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        yield factory
        await engine.dispose()


@pytest.fixture
def notifier() -> InMemoryInvitationNotifier:
    return InMemoryInvitationNotifier()


@pytest.fixture
def audit() -> InMemoryAuditLog:
    return InMemoryAuditLog()


@pytest.fixture
def service(
    session_factory: async_sessionmaker[AsyncSession],
    notifier: InMemoryInvitationNotifier,
    audit: InMemoryAuditLog,
) -> InvitationService:
    return InvitationService(session_factory, InMemoryEventPublisher(), audit, notifier)


async def _seed_user(
    session_factory: async_sessionmaker[AsyncSession], email: str,
) -> User:
    user = User.register(
        email=Email(email), display_name="Test User",
        password_hash=PasswordHash("x" * 20),
    )
    async with session_factory() as session:
        repo = SqlAlchemyUserRepository(session)
        await repo.save(user)
        await session.commit()
    return user


async def _seed_suspended_organization(
    session_factory: async_sessionmaker[AsyncSession], org_id: EntityId,
) -> None:
    from redforge.domain.organizations.entity import Organization
    from redforge.domain.organizations.value_objects import OrganizationName, OrganizationSlug

    org = Organization.create(
        name=OrganizationName("Suspended Org"), slug=OrganizationSlug("suspended-org"),
    )
    # Organization.create() always generates its own id; rebuild with the
    # id the invitation already points at.
    org = Organization(
        id=org_id, name=org.name, slug=org.slug,
        status=org.status, plan=org.plan, timestamps=org.timestamps,
    )
    org.suspend("test")
    async with session_factory() as session:
        repo = SqlAlchemyOrganizationRepository(session)
        await repo.save(org)
        await session.commit()


class TestInvite:
    async def test_invite_creates_pending_invitation(
        self, service: InvitationService,
    ) -> None:
        dto = await service.invite(
            organization_id=str(EntityId.generate()),
            organization_name="Acme",
            email="new@test.com",
            role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        assert dto.status == "pending"
        assert dto.email == "new@test.com"

    async def test_invite_sends_notification_with_token(
        self, service: InvitationService, notifier: InMemoryInvitationNotifier,
    ) -> None:
        await service.invite(
            organization_id=str(EntityId.generate()),
            organization_name="Acme",
            email="notify@test.com",
            role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        assert len(notifier.sent) == 1
        assert notifier.sent[0].email == "notify@test.com"
        assert len(notifier.sent[0].token) > 20

    async def test_invite_with_owner_role_raises(
        self, service: InvitationService,
    ) -> None:
        """The application layer's invite() reaches the same domain
        guard as the direct entity test — verifying the block survives
        the full service call path (duplicate/existing-user checks,
        repository construction), not just a unit-level construction."""
        with pytest.raises(OwnerAssignmentNotAllowedError):
            await service.invite(
                organization_id=str(EntityId.generate()),
                organization_name="Acme",
                email="wouldbeowner@test.com",
                role="owner",
                invited_by_user_id=str(EntityId.generate()),
            )

    async def test_duplicate_pending_invitation_raises(
        self, service: InvitationService,
    ) -> None:
        org_id = str(EntityId.generate())
        await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="dup@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        with pytest.raises(DuplicateInvitationError):
            await service.invite(
                organization_id=org_id, organization_name="Acme",
                email="dup@test.com", role="admin",
                invited_by_user_id=str(EntityId.generate()),
            )

    async def test_invite_existing_active_member_raises(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        user = await _seed_user(session_factory, "member@test.com")
        org_id = EntityId.generate()
        membership = Membership.create(
            user_id=user.id, organization_id=org_id, role=MembershipRole.MEMBER,
        )
        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            await repo.save(membership)
            await session.commit()

        with pytest.raises(MembershipAlreadyExistsError):
            await service.invite(
                organization_id=str(org_id), organization_name="Acme",
                email="member@test.com", role="admin",
                invited_by_user_id=str(EntityId.generate()),
            )

    async def test_different_orgs_can_both_invite_same_email(
        self, service: InvitationService,
    ) -> None:
        """Duplicate prevention is scoped per-organization, not global."""
        await service.invite(
            organization_id=str(EntityId.generate()), organization_name="Org A",
            email="shared@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        await service.invite(
            organization_id=str(EntityId.generate()), organization_name="Org B",
            email="shared@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )  # must not raise


class TestAccept:
    async def test_accept_creates_membership(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
        notifier: InMemoryInvitationNotifier,
    ) -> None:
        user = await _seed_user(session_factory, "acceptor@test.com")
        org_id = str(EntityId.generate())
        await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="acceptor@test.com", role="analyst",
            invited_by_user_id=str(EntityId.generate()),
        )
        token = notifier.sent[-1].token

        invitation_dto, membership_dto = await service.accept(
            token=token, accepting_user_id=str(user.id),
            accepting_email="acceptor@test.com",
        )
        assert invitation_dto.status == "accepted"
        assert membership_dto.role == "analyst"
        assert membership_dto.organization_id == org_id

        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            found = await repo.get_by_user_and_org(user.id, EntityId.from_string(org_id))
        assert found is not None
        assert found.is_active is True

    async def test_accept_blocked_when_organization_suspended(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
        notifier: InMemoryInvitationNotifier,
    ) -> None:
        """Acceptance is reachable without a TenantContext (the invitee
        isn't a member yet), so it cannot rely on the shared
        require_permission suspension check — accept() must enforce this
        itself. The invitation is created while active, then the org is
        suspended before the invitee acts."""
        user = await _seed_user(session_factory, "suspended-accept@test.com")
        org_id = EntityId.generate()
        await service.invite(
            organization_id=str(org_id), organization_name="Acme",
            email="suspended-accept@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        token = notifier.sent[-1].token

        await _seed_suspended_organization(session_factory, org_id)

        with pytest.raises(OrganizationInactiveError):
            await service.accept(
                token=token, accepting_user_id=str(user.id),
                accepting_email="suspended-accept@test.com",
            )

        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            found = await repo.get_by_user_and_org(user.id, org_id)
        assert found is None

    async def test_accept_wrong_token_raises(
        self, service: InvitationService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        user = await _seed_user(session_factory, "x@test.com")
        with pytest.raises(InvitationNotFoundError):
            await service.accept(
                token="totally-invalid-token",
                accepting_user_id=str(user.id), accepting_email="x@test.com",
            )

    async def test_accept_email_mismatch_raises(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
        notifier: InMemoryInvitationNotifier,
    ) -> None:
        attacker = await _seed_user(session_factory, "attacker@test.com")
        org_id = str(EntityId.generate())
        await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="victim@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        token = notifier.sent[-1].token

        with pytest.raises(InvitationEmailMismatchError):
            await service.accept(
                token=token, accepting_user_id=str(attacker.id),
                accepting_email="attacker@test.com",
            )

    async def test_idempotent_accept_replay(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
        notifier: InMemoryInvitationNotifier,
    ) -> None:
        """A network retry of a successful accept() call must return the
        same result, not raise, and must not create a second Membership."""
        user = await _seed_user(session_factory, "replay@test.com")
        org_id = str(EntityId.generate())
        await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="replay@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        token = notifier.sent[-1].token

        first_invitation, first_membership = await service.accept(
            token=token, accepting_user_id=str(user.id), accepting_email="replay@test.com",
        )
        second_invitation, second_membership = await service.accept(
            token=token, accepting_user_id=str(user.id), accepting_email="replay@test.com",
        )

        assert first_membership.id == second_membership.id
        assert first_invitation.status == second_invitation.status == "accepted"

        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            memberships = await repo.list_by_user(user.id)
        assert len(memberships) == 1  # never duplicated

    async def test_concurrent_accept_does_not_duplicate_membership(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
        notifier: InMemoryInvitationNotifier,
    ) -> None:
        """Simulates two near-simultaneous accept() calls for the same
        (token, user) — e.g. a double-click or a client retry racing the
        original request. Exactly one Membership must exist afterward."""
        user = await _seed_user(session_factory, "racer@test.com")
        org_id = str(EntityId.generate())
        await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="racer@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        token = notifier.sent[-1].token

        results = await asyncio.gather(
            service.accept(
                token=token, accepting_user_id=str(user.id),
                accepting_email="racer@test.com",
            ),
            service.accept(
                token=token, accepting_user_id=str(user.id),
                accepting_email="racer@test.com",
            ),
            return_exceptions=True,
        )
        # Both racers must resolve cleanly to the SAME membership — no
        # raw database IntegrityError should ever reach the caller (see
        # InvitationService.accept's conflict-resolution path), and no
        # InvitationAlreadyProcessedError either, since both calls are
        # for the same user/token, not a competing different outcome.
        for result in results:
            assert not isinstance(result, BaseException), result
        membership_ids = {m.id for _invitation, m in results}  # type: ignore[union-attr]
        assert len(membership_ids) == 1

        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            memberships = await repo.list_by_user(user.id)
        assert len(memberships) == 1


class TestReject:
    async def test_reject_marks_rejected(
        self, service: InvitationService, notifier: InMemoryInvitationNotifier,
    ) -> None:
        await service.invite(
            organization_id=str(EntityId.generate()), organization_name="Acme",
            email="decliner@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        token = notifier.sent[-1].token

        dto = await service.reject(token)
        assert dto.status == "rejected"

    async def test_reject_wrong_token_raises(self, service: InvitationService) -> None:
        with pytest.raises(InvitationNotFoundError):
            await service.reject("invalid-token")


class TestRevoke:
    async def test_revoke_marks_revoked(self, service: InvitationService) -> None:
        org_id = str(EntityId.generate())
        actor_id = str(EntityId.generate())
        invited = await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="revokee@test.com", role="member",
            invited_by_user_id=actor_id,
        )
        dto = await service.revoke(org_id, invited.id, actor_id)
        assert dto.status == "revoked"

    async def test_revoked_invitation_cannot_be_accepted(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
        notifier: InMemoryInvitationNotifier,
    ) -> None:
        user = await _seed_user(session_factory, "toolate@test.com")
        org_id = str(EntityId.generate())
        invited = await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="toolate@test.com", role="member",
            invited_by_user_id=str(EntityId.generate()),
        )
        token = notifier.sent[-1].token
        await service.revoke(org_id, invited.id, str(EntityId.generate()))

        with pytest.raises(InvitationAlreadyProcessedError):
            await service.accept(
                token=token, accepting_user_id=str(user.id),
                accepting_email="toolate@test.com",
            )


class TestResend:
    async def test_resend_issues_new_token(
        self, service: InvitationService, notifier: InMemoryInvitationNotifier,
    ) -> None:
        org_id = str(EntityId.generate())
        actor_id = str(EntityId.generate())
        invited = await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="resend@test.com", role="member",
            invited_by_user_id=actor_id,
        )
        original_token = notifier.sent[-1].token

        await service.resend(org_id, invited.id, actor_id)
        new_token = notifier.sent[-1].token

        assert new_token != original_token
        assert len(notifier.sent) == 2

    async def test_old_token_invalidated_after_resend(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
        notifier: InMemoryInvitationNotifier,
    ) -> None:
        user = await _seed_user(session_factory, "oldtoken@test.com")
        org_id = str(EntityId.generate())
        actor_id = str(EntityId.generate())
        invited = await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="oldtoken@test.com", role="member",
            invited_by_user_id=actor_id,
        )
        original_token = notifier.sent[-1].token
        await service.resend(org_id, invited.id, actor_id)

        with pytest.raises(InvitationNotFoundError):
            await service.accept(
                token=original_token, accepting_user_id=str(user.id),
                accepting_email="oldtoken@test.com",
            )

    async def test_new_token_after_resend_works(
        self,
        service: InvitationService,
        session_factory: async_sessionmaker[AsyncSession],
        notifier: InMemoryInvitationNotifier,
    ) -> None:
        user = await _seed_user(session_factory, "newtoken@test.com")
        org_id = str(EntityId.generate())
        actor_id = str(EntityId.generate())
        invited = await service.invite(
            organization_id=org_id, organization_name="Acme",
            email="newtoken@test.com", role="member",
            invited_by_user_id=actor_id,
        )
        await service.resend(org_id, invited.id, actor_id)
        new_token = notifier.sent[-1].token

        invitation_dto, _membership = await service.accept(
            token=new_token, accepting_user_id=str(user.id),
            accepting_email="newtoken@test.com",
        )
        assert invitation_dto.status == "accepted"
