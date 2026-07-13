"""Application service for Membership lifecycle use cases.

Owns the invariants a single Membership aggregate cannot enforce on its
own (last-owner protection, self-privilege-escalation prevention,
ownership transfer) because they require cross-membership context —
counting other owners, comparing the acting user to the target.

Transaction boundaries are managed by SessionUnitOfWork. Repositories
never commit — only UoW does. Every mutation is audit-logged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.identity.exceptions import (
    LastOwnerError,
    MembershipNotFoundError,
    OwnerAssignmentNotAllowedError,
    SelfPrivilegeEscalationError,
)
from redforge.domain.identity.value_objects import MembershipRole
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.contracts import EventPublisherPort
    from redforge.domain.identity.entities import Membership
    from redforge.domain.identity.repository import MembershipRepository
    from redforge.infrastructure.audit.contracts import AuditEntry, AuditLog


@dataclass(frozen=True, slots=True)
class MembershipDTO:
    """Application-layer representation of a Membership."""

    id: str
    user_id: str
    organization_id: str
    role: str
    status: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, membership: Membership) -> MembershipDTO:
        return cls(
            id=str(membership.id),
            user_id=str(membership.user_id),
            organization_id=str(membership.organization_id),
            role=str(membership.role),
            status=str(membership.status),
            created_at=membership.timestamps.created_at.isoformat(),
            updated_at=membership.timestamps.updated_at.isoformat(),
        )


class MembershipService:
    """Orchestrates Membership lifecycle use cases with full enterprise
    invariant enforcement: last-owner protection, self-escalation
    prevention, atomic ownership transfer.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: EventPublisherPort,
        audit_log: AuditLog,
    ) -> None:
        self._session_factory = session_factory
        self._event_publisher = event_publisher
        self._audit_log = audit_log

    # ─── Queries ────────────────────────────────────────────────────────

    async def list_by_organization(self, organization_id: str) -> list[MembershipDTO]:
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMembershipRepository(uow.session)
            memberships = await repo.list_by_organization(
                EntityId.from_string(organization_id)
            )
        return [MembershipDTO.from_entity(m) for m in memberships]

    # ─── Role management ────────────────────────────────────────────────

    async def change_role(
        self,
        actor_user_id: str,
        organization_id: str,
        target_membership_id: str,
        new_role: str,
    ) -> MembershipDTO:
        """Change a member's role.

        Raises:
            OwnerAssignmentNotAllowedError: If new_role is OWNER — the
                only valid path to OWNER is transfer_ownership().
            SelfPrivilegeEscalationError: If the actor targets their own membership.
            LastOwnerError: If demoting the sole remaining OWNER.
            MembershipNotFoundError: If the target isn't in this organization.
        """
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        target_id = EntityId.from_string(target_membership_id)
        role = MembershipRole(new_role)

        if role == MembershipRole.OWNER:
            raise OwnerAssignmentNotAllowedError(target_membership_id)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMembershipRepository(uow.session)
            target = await self._load_in_org(repo, target_id, org_id)

            if str(target.user_id) == actor_user_id:
                raise SelfPrivilegeEscalationError(actor_user_id, "change role of")

            # `role` is never OWNER here — ruled out above — so any
            # change to a currently-OWNER target is necessarily a
            # demotion, and must preserve at least one other owner.
            if target.role == MembershipRole.OWNER:
                await self._require_other_owner_exists(repo, org_id, target_id)

            target.change_role(role)
            await repo.save(target)
            await uow.commit()

        await self._audit_and_publish(
            target,
            action="membership.role_changed",
            actor_user_id=actor_user_id,
            metadata={"new_role": new_role},
        )
        return MembershipDTO.from_entity(target)

    # ─── Suspend / reactivate / remove ─────────────────────────────────────

    async def suspend_member(
        self, actor_user_id: str, organization_id: str, target_membership_id: str,
    ) -> MembershipDTO:
        """Temporarily pause a member's access.

        Raises:
            SelfPrivilegeEscalationError: If the actor targets themselves.
            LastOwnerError: If suspending the sole remaining OWNER.
        """
        return await self._mutate_membership(
            actor_user_id, organization_id, target_membership_id,
            mutate=lambda m: m.suspend(),
            action="membership.suspended",
            block_self=True,
            enforce_last_owner=True,
        )

    async def reactivate_member(
        self, actor_user_id: str, organization_id: str, target_membership_id: str,
    ) -> MembershipDTO:
        """Restore a suspended member's access. No self-restriction — an
        OWNER reactivating themselves (e.g. after an admin error) is not
        a privilege escalation, since no privilege is gained beyond what
        the membership already had before suspension."""
        return await self._mutate_membership(
            actor_user_id, organization_id, target_membership_id,
            mutate=lambda m: m.reactivate(),
            action="membership.reactivated",
            block_self=False,
            enforce_last_owner=False,
        )

    async def remove_member(
        self, actor_user_id: str, organization_id: str, target_membership_id: str,
    ) -> None:
        """Permanently remove a member from the organization.

        Raises:
            SelfPrivilegeEscalationError: If the actor targets themselves
                (use leave_organization() for self-removal instead).
            LastOwnerError: If removing the sole remaining OWNER.
        """
        await self._mutate_membership(
            actor_user_id, organization_id, target_membership_id,
            mutate=lambda m: m.revoke(),
            action="membership.removed",
            block_self=True,
            enforce_last_owner=True,
        )

    async def leave_organization(self, actor_user_id: str, organization_id: str) -> None:
        """A member voluntarily removes their own membership.

        Raises:
            LastOwnerError: If the actor is the sole remaining OWNER —
                ownership must be transferred first.
            MembershipNotFoundError: If the actor has no membership here.
        """
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        user_id = EntityId.from_string(actor_user_id)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMembershipRepository(uow.session)
            membership = await repo.get_by_user_and_org(user_id, org_id)
            if membership is None:
                raise MembershipNotFoundError(f"user={actor_user_id} org={organization_id}")

            if membership.role == MembershipRole.OWNER:
                await self._require_other_owner_exists(repo, org_id, membership.id)

            membership.revoke()
            await repo.save(membership)
            await uow.commit()

        await self._audit_and_publish(
            membership, action="membership.removed", actor_user_id=actor_user_id,
            metadata={"self_initiated": "true"},
        )

    # ─── Ownership transfer ─────────────────────────────────────────────

    async def transfer_ownership(
        self, actor_user_id: str, organization_id: str, new_owner_user_id: str,
    ) -> MembershipDTO:
        """Atomically move OWNER role from the acting user to another
        active member of the same organization. The previous owner is
        demoted to ADMIN (not removed) — ownership transfer is a role
        change, not an exit.

        Raises:
            MembershipNotFoundError: If either party has no membership
                in this organization.
            SelfPrivilegeEscalationError: If new_owner_user_id equals
                actor_user_id (nothing to transfer).
        """
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        if actor_user_id == new_owner_user_id:
            raise SelfPrivilegeEscalationError(actor_user_id, "transfer ownership to yourself")

        org_id = EntityId.from_string(organization_id)
        current_owner_id = EntityId.from_string(actor_user_id)
        new_owner_id = EntityId.from_string(new_owner_user_id)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMembershipRepository(uow.session)

            current_owner = await repo.get_by_user_and_org(current_owner_id, org_id)
            if current_owner is None or not current_owner.is_active:
                raise MembershipNotFoundError(
                    f"user={actor_user_id} org={organization_id}"
                )
            if current_owner.role != MembershipRole.OWNER:
                raise SelfPrivilegeEscalationError(
                    actor_user_id, "transfer ownership without being an owner"
                )

            new_owner = await repo.get_by_user_and_org(new_owner_id, org_id)
            if new_owner is None or not new_owner.is_active:
                raise MembershipNotFoundError(
                    f"user={new_owner_user_id} org={organization_id}"
                )

            # Promote first, then demote — if the promote step fails, the
            # organization never transiently has zero owners.
            new_owner.change_role(MembershipRole.OWNER)
            current_owner.change_role(MembershipRole.ADMIN)
            await repo.save(new_owner)
            await repo.save(current_owner)
            await uow.commit()

        from redforge.domain.identity.events import OwnershipTransferred
        from redforge.shared.timestamps import utc_now

        transfer_events: list[object] = [
            OwnershipTransferred(
                occurred_at=utc_now(),
                organization_id=organization_id,
                previous_owner_membership_id=str(current_owner.id),
                previous_owner_user_id=actor_user_id,
                new_owner_membership_id=str(new_owner.id),
                new_owner_user_id=new_owner_user_id,
            ),
            *current_owner.collect_events(),
            *new_owner.collect_events(),
        ]
        await self._event_publisher.publish(transfer_events)
        await self._audit_log.record(self._entry(
            action="membership.ownership_transferred",
            actor_id=actor_user_id,
            resource_id=str(new_owner.id),
            organization_id=organization_id,
            metadata={
                "previous_owner_user_id": actor_user_id,
                "new_owner_user_id": new_owner_user_id,
            },
        ))
        return MembershipDTO.from_entity(new_owner)

    # ─── Shared helpers ─────────────────────────────────────────────────

    async def _mutate_membership(
        self,
        actor_user_id: str,
        organization_id: str,
        target_membership_id: str,
        *,
        mutate: Callable[[Membership], None],
        action: str,
        block_self: bool,
        enforce_last_owner: bool,
    ) -> MembershipDTO:
        from redforge.infrastructure.database.repositories.membership_repository import (
            SqlAlchemyMembershipRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        org_id = EntityId.from_string(organization_id)
        target_id = EntityId.from_string(target_membership_id)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMembershipRepository(uow.session)
            target = await self._load_in_org(repo, target_id, org_id)

            if block_self and str(target.user_id) == actor_user_id:
                raise SelfPrivilegeEscalationError(actor_user_id, action.split(".")[-1])

            if enforce_last_owner and target.role == MembershipRole.OWNER:
                await self._require_other_owner_exists(repo, org_id, target_id)

            mutate(target)
            await repo.save(target)
            await uow.commit()

        await self._audit_and_publish(target, action=action, actor_user_id=actor_user_id)
        return MembershipDTO.from_entity(target)

    @staticmethod
    async def _load_in_org(
        repo: MembershipRepository, target_id: EntityId, org_id: EntityId
    ) -> Membership:
        target = await repo.get_by_id(target_id)
        if target is None or target.organization_id != org_id:
            raise MembershipNotFoundError(str(target_id))
        return target

    @staticmethod
    async def _require_other_owner_exists(
        repo: MembershipRepository, org_id: EntityId, excluding_membership_id: EntityId
    ) -> None:
        """Raise LastOwnerError unless at least one ACTIVE OWNER other
        than `excluding_membership_id` exists. Counts, rather than
        fetching the excluded membership's own current state, so this
        is correct whether the excluded membership is still ACTIVE
        (about to be mutated) or already mutated in-session."""
        owner_count = await repo.count_active_owners(org_id)
        # The excluded membership is still ACTIVE/OWNER in the DB at
        # this point (mutation hasn't been saved yet), so a count of 1
        # means "only the membership about to change" — i.e. no other
        # owner exists.
        if owner_count <= 1:
            raise LastOwnerError(str(org_id), "modify the sole owner")

    async def _audit_and_publish(
        self, membership: Membership, *, action: str, actor_user_id: str,
        metadata: dict[str, str] | None = None,
    ) -> None:
        await self._event_publisher.publish(membership.collect_events())
        await self._audit_log.record(self._entry(
            action=action,
            actor_id=actor_user_id,
            resource_id=str(membership.id),
            organization_id=str(membership.organization_id),
            metadata=metadata or {},
        ))

    @staticmethod
    def _entry(
        *, action: str, actor_id: str, resource_id: str, organization_id: str,
        metadata: dict[str, str],
    ) -> AuditEntry:
        from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry

        return AuditEntry(
            action=AuditAction(action),
            actor_id=actor_id,
            resource_type="membership",
            resource_id=resource_id,
            metadata={"organization_id": organization_id, **metadata},
        )
