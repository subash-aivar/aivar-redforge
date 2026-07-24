"""Integration tests for MembershipService — the enterprise invariants:
last-owner protection, self-privilege-escalation prevention, atomic
ownership transfer, suspend/reactivate/remove/leave.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.memberships import MembershipService
from redforge.domain.identity.entities import Membership
from redforge.domain.identity.exceptions import (
    LastOwnerError,
    MembershipNotFoundError,
    OwnerAssignmentNotAllowedError,
    SelfPrivilegeEscalationError,
)
from redforge.domain.identity.value_objects import MembershipRole
from redforge.infrastructure.audit.logger import InMemoryAuditLog
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import MembershipModel  # noqa: F401
from redforge.infrastructure.database.repositories.membership_repository import (
    SqlAlchemyMembershipRepository,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.shared.identifiers import EntityId


@pytest.fixture
async def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[t for t in Base.metadata.sorted_tables if t.schema is None],
        )
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
def events() -> InMemoryEventPublisher:
    return InMemoryEventPublisher()


@pytest.fixture
def audit() -> InMemoryAuditLog:
    return InMemoryAuditLog()


@pytest.fixture
def service(
    session_factory: async_sessionmaker[AsyncSession],
    events: InMemoryEventPublisher,
    audit: InMemoryAuditLog,
) -> MembershipService:
    return MembershipService(session_factory, events, audit)


async def _seed_membership(
    session_factory: async_sessionmaker[AsyncSession],
    org_id: EntityId,
    role: MembershipRole = MembershipRole.MEMBER,
    user_id: EntityId | None = None,
) -> Membership:
    membership = Membership.create(
        user_id=user_id or EntityId.generate(), organization_id=org_id, role=role,
    )
    async with session_factory() as session:
        repo = SqlAlchemyMembershipRepository(session)
        await repo.save(membership)
        await session.commit()
    return membership


class TestChangeRole:
    async def test_changes_role(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        target = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)

        dto = await service.change_role(
            str(owner.user_id), str(org_id), str(target.id), "admin",
        )
        assert dto.role == "admin"

    async def test_self_change_raises(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        actor = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)

        with pytest.raises(SelfPrivilegeEscalationError):
            await service.change_role(
                str(actor.user_id), str(org_id), str(actor.id), "member",
            )

    async def test_change_role_to_owner_raises(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """OWNER can only ever be granted via transfer_ownership() —
        change_role must reject it outright, even for a non-self target,
        even before any self-escalation or last-owner checks run."""
        org_id = EntityId.generate()
        actor = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)
        target = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)

        with pytest.raises(OwnerAssignmentNotAllowedError):
            await service.change_role(
                str(actor.user_id), str(org_id), str(target.id), "owner",
            )

    async def test_change_own_role_to_owner_raises_owner_not_self_escalation(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """When both violations apply (self-target AND owner-assignment),
        the OWNER-assignment block fires first — it is unconditional and
        does not depend on who the target is."""
        org_id = EntityId.generate()
        actor = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)

        with pytest.raises(OwnerAssignmentNotAllowedError):
            await service.change_role(
                str(actor.user_id), str(org_id), str(actor.id), "owner",
            )

    async def test_demoting_sole_owner_raises(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        acting_owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        sole_owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        # Give the sole_owner a distinct identity so acting_owner != sole_owner
        # (both are OWNER here — demoting either one when 2 owners exist is fine;
        # this test demotes down to 1 owner remaining, which must still succeed,
        # then demoting THAT one must fail).
        await service.change_role(
            str(acting_owner.user_id), str(org_id), str(sole_owner.id), "admin",
        )
        # Now only acting_owner is OWNER. Demoting them (by a different actor)
        # must fail — simulate a second admin attempting it.
        other_admin = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)
        with pytest.raises(LastOwnerError):
            await service.change_role(
                str(other_admin.user_id), str(org_id), str(acting_owner.id), "admin",
            )

    async def test_demoting_owner_with_other_owner_present_succeeds(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner_a = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        owner_b = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)

        dto = await service.change_role(
            str(owner_a.user_id), str(org_id), str(owner_b.id), "admin",
        )
        assert dto.role == "admin"

    async def test_target_in_different_org_not_found(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_a = EntityId.generate()
        org_b = EntityId.generate()
        actor = await _seed_membership(session_factory, org_a, MembershipRole.OWNER)
        foreign_target = await _seed_membership(session_factory, org_b, MembershipRole.MEMBER)

        with pytest.raises(MembershipNotFoundError):
            await service.change_role(
                str(actor.user_id), str(org_a), str(foreign_target.id), "admin",
            )


class TestSuspendReactivateRemove:
    async def test_suspend_member(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        target = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)

        dto = await service.suspend_member(str(owner.user_id), str(org_id), str(target.id))
        assert dto.status == "suspended"

    async def test_self_suspend_raises(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        actor = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)
        with pytest.raises(SelfPrivilegeEscalationError):
            await service.suspend_member(str(actor.user_id), str(org_id), str(actor.id))

    async def test_suspending_sole_owner_raises(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        admin = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)

        with pytest.raises(LastOwnerError):
            await service.suspend_member(str(admin.user_id), str(org_id), str(owner.id))

    async def test_reactivate_restores_access(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        target = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)
        await service.suspend_member(str(owner.user_id), str(org_id), str(target.id))

        dto = await service.reactivate_member(str(owner.user_id), str(org_id), str(target.id))
        assert dto.status == "active"

    async def test_remove_member(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        target = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)

        await service.remove_member(str(owner.user_id), str(org_id), str(target.id))

        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            reloaded = await repo.get_by_id(target.id)
        assert reloaded is not None
        assert reloaded.status.value == "removed"

    async def test_self_remove_raises(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        actor = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)
        with pytest.raises(SelfPrivilegeEscalationError):
            await service.remove_member(str(actor.user_id), str(org_id), str(actor.id))

    async def test_removing_sole_owner_raises(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        admin = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)

        with pytest.raises(LastOwnerError):
            await service.remove_member(str(admin.user_id), str(org_id), str(owner.id))


class TestLeaveOrganization:
    async def test_member_can_leave(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        member = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)
        await service.leave_organization(str(member.user_id), str(org_id))

        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            reloaded = await repo.get_by_id(member.id)
        assert reloaded is not None
        assert reloaded.status.value == "removed"

    async def test_sole_owner_cannot_leave(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        with pytest.raises(LastOwnerError):
            await service.leave_organization(str(owner.user_id), str(org_id))

    async def test_one_of_two_owners_can_leave(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner_a = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        await service.leave_organization(str(owner_a.user_id), str(org_id))  # must not raise


class TestTransferOwnership:
    async def test_transfers_ownership(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        current_owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        new_owner = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)

        dto = await service.transfer_ownership(
            str(current_owner.user_id), str(org_id), str(new_owner.user_id),
        )
        assert dto.role == "owner"
        assert dto.id == str(new_owner.id)

        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            reloaded_old = await repo.get_by_id(current_owner.id)
        assert reloaded_old is not None
        assert reloaded_old.role == MembershipRole.ADMIN
        assert reloaded_old.is_active is True  # demoted, not removed

    async def test_transfer_to_self_raises(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        org_id = EntityId.generate()
        owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        with pytest.raises(SelfPrivilegeEscalationError):
            await service.transfer_ownership(
                str(owner.user_id), str(org_id), str(owner.user_id),
            )

    async def test_non_owner_actor_cannot_transfer(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """An ADMIN holds ORG_MANAGE (same as OWNER) but must not be able
        to transfer ownership they don't have — this is the domain-level
        check beyond the route's permission gate."""
        org_id = EntityId.generate()
        admin = await _seed_membership(session_factory, org_id, MembershipRole.ADMIN)
        target = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)

        with pytest.raises(SelfPrivilegeEscalationError):
            await service.transfer_ownership(
                str(admin.user_id), str(org_id), str(target.user_id),
            )

    async def test_transfer_never_leaves_zero_owners(
        self, service: MembershipService, session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """After a successful transfer, exactly one OWNER exists (the
        new one) — the old owner is demoted, never simply removed."""
        org_id = EntityId.generate()
        current_owner = await _seed_membership(session_factory, org_id, MembershipRole.OWNER)
        new_owner = await _seed_membership(session_factory, org_id, MembershipRole.MEMBER)

        await service.transfer_ownership(
            str(current_owner.user_id), str(org_id), str(new_owner.user_id),
        )

        async with session_factory() as session:
            repo = SqlAlchemyMembershipRepository(session)
            owner_count = await repo.count_active_owners(org_id)
        assert owner_count == 1
