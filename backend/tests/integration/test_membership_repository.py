"""Integration tests for SqlAlchemyMembershipRepository.

This repository backs the platform's tenant-isolation security boundary
(see api/security.py) — every organization-scoped API request resolves
its authorization through a Membership lookup.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.domain.identity.entities import Membership
from redforge.domain.identity.value_objects import MembershipRole
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import MembershipModel  # noqa: F401
from redforge.infrastructure.database.repositories.membership_repository import (
    SqlAlchemyMembershipRepository,
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
def repository(session: AsyncSession) -> SqlAlchemyMembershipRepository:
    return SqlAlchemyMembershipRepository(session)


def _membership(
    user_id: EntityId | None = None,
    org_id: EntityId | None = None,
    role: MembershipRole = MembershipRole.MEMBER,
) -> Membership:
    return Membership.create(
        user_id=user_id or EntityId.generate(),
        organization_id=org_id or EntityId.generate(),
        role=role,
    )


class TestSaveAndGetById:
    async def test_saves_and_loads(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        membership = _membership(role=MembershipRole.ADMIN)
        await repository.save(membership)
        await session.commit()

        loaded = await repository.get_by_id(membership.id)
        assert loaded is not None
        assert loaded.role == MembershipRole.ADMIN
        assert loaded.is_active is True

    async def test_get_by_id_missing_returns_none(
        self, repository: SqlAlchemyMembershipRepository
    ) -> None:
        assert await repository.get_by_id(EntityId.generate()) is None


class TestGetByUserAndOrg:
    """This is THE tenant-isolation query — every organization-scoped
    request resolves through this lookup."""

    async def test_finds_matching_membership(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        user_id = EntityId.generate()
        org_id = EntityId.generate()
        membership = _membership(user_id, org_id, MembershipRole.OWNER)
        await repository.save(membership)
        await session.commit()

        found = await repository.get_by_user_and_org(user_id, org_id)
        assert found is not None
        assert found.role == MembershipRole.OWNER

    async def test_wrong_organization_returns_none(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        """A user with a membership in Org A must not resolve a
        membership when queried against Org B — this is the query that
        api/security.py's select-organization flow depends on to reject
        cross-tenant token minting."""
        user_id = EntityId.generate()
        org_a = EntityId.generate()
        org_b = EntityId.generate()
        await repository.save(_membership(user_id, org_a))
        await session.commit()

        assert await repository.get_by_user_and_org(user_id, org_b) is None

    async def test_wrong_user_returns_none(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        user_a = EntityId.generate()
        user_b = EntityId.generate()
        org_id = EntityId.generate()
        await repository.save(_membership(user_a, org_id))
        await session.commit()

        assert await repository.get_by_user_and_org(user_b, org_id) is None

    async def test_revoked_membership_still_returned_but_marked_inactive(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        """Callers (e.g. the org-select flow) are responsible for
        checking `.is_active` — get_by_user_and_org itself does not
        filter it out, so revoked-but-visible auditing remains possible."""
        user_id = EntityId.generate()
        org_id = EntityId.generate()
        membership = _membership(user_id, org_id)
        membership.revoke()
        await repository.save(membership)
        await session.commit()

        found = await repository.get_by_user_and_org(user_id, org_id)
        assert found is not None
        assert found.is_active is False


class TestListByUserAndOrganization:
    async def test_list_by_user_excludes_inactive(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        user_id = EntityId.generate()
        active = _membership(user_id)
        revoked = _membership(user_id)
        revoked.revoke()
        await repository.save(active)
        await repository.save(revoked)
        await session.commit()

        results = await repository.list_by_user(user_id)
        assert len(results) == 1
        assert results[0].id == active.id

    async def test_list_by_organization_excludes_inactive(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        org_id = EntityId.generate()
        active = _membership(org_id=org_id)
        revoked = _membership(org_id=org_id)
        revoked.revoke()
        await repository.save(active)
        await repository.save(revoked)
        await session.commit()

        results = await repository.list_by_organization(org_id)
        assert len(results) == 1
        assert results[0].id == active.id


class TestExists:
    async def test_exists_true_after_save(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        user_id = EntityId.generate()
        org_id = EntityId.generate()
        await repository.save(_membership(user_id, org_id))
        await session.commit()

        assert await repository.exists(user_id, org_id) is True

    async def test_exists_false_for_unrelated_pair(
        self, repository: SqlAlchemyMembershipRepository
    ) -> None:
        assert await repository.exists(EntityId.generate(), EntityId.generate()) is False


class TestUniqueConstraint:
    async def test_second_membership_for_same_user_org_updates_not_duplicates(
        self, repository: SqlAlchemyMembershipRepository, session: AsyncSession
    ) -> None:
        """Saving via merge() with the same primary key updates in place.
        The (user_id, organization_id) unique constraint additionally
        guards against two DIFFERENT membership rows ever existing for
        the same pair (enforced at the DB level, not exercised by this
        ORM-level test but documented here for maintainers)."""
        membership = _membership(role=MembershipRole.MEMBER)
        await repository.save(membership)
        await session.commit()

        membership.change_role(MembershipRole.ADMIN)
        await repository.save(membership)
        await session.commit()

        loaded = await repository.get_by_id(membership.id)
        assert loaded is not None
        assert loaded.role == MembershipRole.ADMIN
