"""Integration tests for SqlAlchemyInvitationRepository."""

from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.domain.identity.entities import Invitation
from redforge.domain.identity.value_objects import Email, MembershipRole
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import InvitationModel  # noqa: F401
from redforge.infrastructure.database.repositories.invitation_repository import (
    SqlAlchemyInvitationRepository,
)
from redforge.shared.identifiers import EntityId


@pytest.fixture
async def session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[t for t in Base.metadata.sorted_tables if t.schema is None],
        )
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def repository(session: AsyncSession) -> SqlAlchemyInvitationRepository:
    return SqlAlchemyInvitationRepository(session)


def _create_invitation(
    email: str = "invitee@test.com", org_id: EntityId | None = None,
) -> tuple[Invitation, str]:
    return Invitation.create(
        organization_id=org_id or EntityId.generate(),
        email=Email(email),
        role=MembershipRole.MEMBER,
        invited_by_user_id=EntityId.generate(),
        ttl=timedelta(days=7),
    )


class TestSaveAndGetById:
    async def test_saves_and_loads(
        self, repository: SqlAlchemyInvitationRepository, session: AsyncSession
    ) -> None:
        invitation, _token = _create_invitation("a@test.com")
        await repository.save(invitation)
        await session.commit()

        loaded = await repository.get_by_id(invitation.id)
        assert loaded is not None
        assert str(loaded.email) == "a@test.com"
        assert loaded.status.value == "pending"

    async def test_get_by_id_missing_returns_none(
        self, repository: SqlAlchemyInvitationRepository
    ) -> None:
        assert await repository.get_by_id(EntityId.generate()) is None


class TestGetByTokenHash:
    async def test_finds_by_hash(
        self, repository: SqlAlchemyInvitationRepository, session: AsyncSession
    ) -> None:
        invitation, _token = _create_invitation()
        await repository.save(invitation)
        await session.commit()

        found = await repository.get_by_token_hash(invitation.token_hash)
        assert found is not None
        assert found.id == invitation.id

    async def test_wrong_hash_returns_none(
        self, repository: SqlAlchemyInvitationRepository
    ) -> None:
        assert await repository.get_by_token_hash("0" * 64) is None

    async def test_plaintext_token_never_matches_directly(
        self, repository: SqlAlchemyInvitationRepository, session: AsyncSession
    ) -> None:
        """The stored value is a hash — looking up by the raw plaintext
        token (as if an attacker read the DB and tried to use a row
        value directly as a bearer token) must fail."""
        invitation, token = _create_invitation()
        await repository.save(invitation)
        await session.commit()

        assert await repository.get_by_token_hash(token) is None


class TestGetPendingByOrgAndEmail:
    async def test_finds_pending(
        self, repository: SqlAlchemyInvitationRepository, session: AsyncSession
    ) -> None:
        org_id = EntityId.generate()
        invitation, _token = _create_invitation("dup@test.com", org_id)
        await repository.save(invitation)
        await session.commit()

        found = await repository.get_pending_by_org_and_email(org_id, Email("dup@test.com"))
        assert found is not None
        assert found.id == invitation.id

    async def test_accepted_invitation_not_returned(
        self, repository: SqlAlchemyInvitationRepository, session: AsyncSession
    ) -> None:
        org_id = EntityId.generate()
        invitation, _token = _create_invitation("done@test.com", org_id)
        invitation.accept(EntityId.generate(), Email("done@test.com"))
        await repository.save(invitation)
        await session.commit()

        found = await repository.get_pending_by_org_and_email(org_id, Email("done@test.com"))
        assert found is None

    async def test_different_org_not_returned(
        self, repository: SqlAlchemyInvitationRepository, session: AsyncSession
    ) -> None:
        invitation, _token = _create_invitation("x@test.com", EntityId.generate())
        await repository.save(invitation)
        await session.commit()

        found = await repository.get_pending_by_org_and_email(
            EntityId.generate(), Email("x@test.com"),
        )
        assert found is None


class TestListByOrganization:
    async def test_lists_all_for_org(
        self, repository: SqlAlchemyInvitationRepository, session: AsyncSession
    ) -> None:
        org_id = EntityId.generate()
        i1, _ = _create_invitation("one@test.com", org_id)
        i2, _ = _create_invitation("two@test.com", org_id)
        i3, _ = _create_invitation("three@test.com", EntityId.generate())
        await repository.save(i1)
        await repository.save(i2)
        await repository.save(i3)
        await session.commit()

        results = await repository.list_by_organization(org_id)
        assert len(results) == 2

    async def test_filters_by_status(
        self, repository: SqlAlchemyInvitationRepository, session: AsyncSession
    ) -> None:
        org_id = EntityId.generate()
        pending, _ = _create_invitation("p@test.com", org_id)
        revoked, _ = _create_invitation("r@test.com", org_id)
        revoked.revoke(EntityId.generate())
        await repository.save(pending)
        await repository.save(revoked)
        await session.commit()

        results = await repository.list_by_organization(org_id, status="pending")
        assert len(results) == 1
        assert results[0].id == pending.id
