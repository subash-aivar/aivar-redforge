"""SqlAlchemy repository for the ContinuousValidationPolicy aggregate (M14).

Receives an active AsyncSession. NEVER commits or rolls back — matches
every other repository in this codebase (the application service/unit
of work owns the transaction boundary).
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, or_, select, update

from redforge.domain.continuous_validation.value_objects import (
    CLAIM_LEASE_SECONDS,
    PolicyLifecycle,
)
from redforge.infrastructure.database.mappings.continuous_validation_mapper import (
    policy_to_entity,
    policy_to_model,
)
from redforge.infrastructure.database.models.continuous_validation import (
    ContinuousValidationPolicyModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.continuous_validation.entity import ContinuousValidationPolicy
    from redforge.shared.identifiers import EntityId


class SqlAlchemyContinuousValidationPolicyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id_for_organization(
        self, policy_id: EntityId, organization_id: EntityId,
    ) -> ContinuousValidationPolicy | None:
        model = await self._get_model(str(policy_id), str(organization_id))
        return policy_to_entity(model) if model is not None else None

    async def get_by_id_for_organization_for_update(
        self, policy_id: EntityId, organization_id: EntityId,
    ) -> ContinuousValidationPolicy | None:
        """Row-locked read for a read-modify-write transition (operator
        lifecycle actions and the scheduler's post-run
        advance/release). Two concurrent callers targeting the same
        policy (e.g. an operator's disable() racing the scheduler's own
        post-run save()) serialize on this lock rather than one
        blindly overwriting the other's committed change — save()
        itself has no optimistic-concurrency check, so the lock here is
        what makes the read-modify-write atomic."""
        model = await self._get_model(
            str(policy_id), str(organization_id), for_update=True,
        )
        return policy_to_entity(model) if model is not None else None

    async def list_for_organization(
        self,
        organization_id: EntityId,
        lifecycle: PolicyLifecycle | None,
        limit: int,
        offset: int,
    ) -> list[ContinuousValidationPolicy]:
        stmt = select(ContinuousValidationPolicyModel).where(
            ContinuousValidationPolicyModel.organization_id == str(organization_id)
        )
        if lifecycle is not None:
            stmt = stmt.where(ContinuousValidationPolicyModel.lifecycle == str(lifecycle))
        stmt = (
            stmt.order_by(ContinuousValidationPolicyModel.created_at.desc())
            .limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        return [policy_to_entity(m) for m in result.scalars().all()]

    async def count_for_organization(
        self, organization_id: EntityId, lifecycle: PolicyLifecycle | None,
    ) -> int:
        """Real COUNT(*) for the M15 Security Operations summary — never
        a client-side tally over one paginated page."""
        stmt = select(func.count(ContinuousValidationPolicyModel.id)).where(
            ContinuousValidationPolicyModel.organization_id == str(organization_id)
        )
        if lifecycle is not None:
            stmt = stmt.where(ContinuousValidationPolicyModel.lifecycle == str(lifecycle))
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)

    async def save(self, policy: ContinuousValidationPolicy) -> None:
        existing = await self._get_model(str(policy.id), str(policy.organization_id))
        model = policy_to_model(policy)
        if existing is None:
            self._session.add(model)
        else:
            existing.lifecycle = model.lifecycle
            existing.next_due_at = model.next_due_at
            existing.last_scheduled_at = model.last_scheduled_at
            existing.claimed_at = model.claimed_at
            existing.claim_owner = model.claim_owner
            existing.updated_at = model.updated_at
        await self._session.flush()

    async def claim_one_due_policy(
        self, now: datetime, worker_id: str, lease_seconds: int = CLAIM_LEASE_SECONDS,
    ) -> ContinuousValidationPolicy | None:
        """Atomically claim exactly one due, unclaimed-or-lease-expired
        ACTIVE policy. A single `UPDATE ... WHERE id = (SELECT ... FOR
        UPDATE SKIP LOCKED) RETURNING *` statement — the standard
        Postgres job-queue claim idiom. Two concurrent callers never
        block each other on the same candidate row: SKIP LOCKED makes
        the loser simply see a different row (or none), rather than
        waiting and re-evaluating a stale WHERE clause. The row lock is
        held only for this single statement's own transaction, never
        for the (much longer) validation run that follows — that run
        happens in a separate, later transaction after this one commits.
        Postgres-only (FOR UPDATE SKIP LOCKED) — exercised by the M14
        PostgreSQL concurrency proof, not by SQLite-backed API isolation
        tests.
        """
        lease_cutoff = now - timedelta(seconds=lease_seconds)
        candidate = (
            select(ContinuousValidationPolicyModel.id)
            .where(
                ContinuousValidationPolicyModel.lifecycle == str(PolicyLifecycle.ACTIVE),
                ContinuousValidationPolicyModel.next_due_at <= now,
                or_(
                    ContinuousValidationPolicyModel.claimed_at.is_(None),
                    ContinuousValidationPolicyModel.claimed_at < lease_cutoff,
                ),
            )
            .order_by(ContinuousValidationPolicyModel.next_due_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        stmt = (
            update(ContinuousValidationPolicyModel)
            .where(ContinuousValidationPolicyModel.id == candidate)
            .values(claimed_at=now, claim_owner=worker_id)
            .returning(ContinuousValidationPolicyModel)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        await self._session.flush()
        return policy_to_entity(model) if model is not None else None

    async def _get_model(
        self, policy_id: str, organization_id: str, *, for_update: bool = False,
    ) -> ContinuousValidationPolicyModel | None:
        stmt = select(ContinuousValidationPolicyModel).where(
            ContinuousValidationPolicyModel.id == policy_id,
            ContinuousValidationPolicyModel.organization_id == organization_id,
        )
        if for_update:
            stmt = stmt.with_for_update()
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
