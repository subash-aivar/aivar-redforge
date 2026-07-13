"""ContinuousValidationPolicyService — M14.

Tenant-scoped CRUD + lifecycle transitions for ContinuousValidationPolicy.
Deliberately thin: this service never executes anything and never
touches ValidationExecution — see
`application/continuous_validation/processor.py` for the actual
claim -> authorize -> execute -> reconcile -> drift orchestration. This
mirrors how `TenantAssetService` (M3) stays a pure persistence/identity
layer while execution logic lives in `execution_service.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.continuous_validation.entity import ContinuousValidationPolicy
from redforge.domain.continuous_validation.exceptions import (
    ContinuousValidationPolicyNotFoundError,
)
from redforge.domain.continuous_validation.value_objects import PolicyLifecycle, ValidationCadence
from redforge.domain.validation_execution.value_objects import ValidationProfile
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.ai_targets import AITargetService


def _safe_entity_id(value: str) -> EntityId | None:
    """A client-supplied id that is not a syntactically valid EntityId
    can never resolve to a real row — treated the same as "not found"
    rather than propagating EntityId.from_string()'s raw ValueError
    into an unhandled 500."""
    try:
        return EntityId.from_string(value)
    except ValueError:
        return None


# ─── DTOs ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ContinuousValidationPolicyDTO:
    id: str
    organization_id: str
    target_id: str
    requester_user_id: str
    profile: str
    cadence: str
    lifecycle: str
    next_due_at: str | None
    last_scheduled_at: str | None
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, policy: ContinuousValidationPolicy) -> ContinuousValidationPolicyDTO:
        return cls(
            id=str(policy.id),
            organization_id=str(policy.organization_id),
            target_id=str(policy.target_id),
            requester_user_id=str(policy.requester_user_id),
            profile=str(policy.profile),
            cadence=str(policy.cadence),
            lifecycle=str(policy.lifecycle),
            next_due_at=policy.next_due_at.isoformat() if policy.next_due_at else None,
            last_scheduled_at=(
                policy.last_scheduled_at.isoformat() if policy.last_scheduled_at else None
            ),
            created_at=policy.timestamps.created_at.isoformat(),
            updated_at=policy.timestamps.updated_at.isoformat(),
        )


class ContinuousValidationPolicyService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        ai_target_service: AITargetService,
    ) -> None:
        self._session_factory = session_factory
        self._ai_target_service = ai_target_service

    async def create(
        self,
        organization_id: str,
        target_id: str,
        requester_user_id: str,
        profile: str,
        cadence: str,
    ) -> ContinuousValidationPolicyDTO:
        """Create a new ContinuousValidationPolicy in DRAFT.

        Raises:
            ValidationError: unknown profile or cadence string.
            TargetNotFoundError: `target_id` does not resolve to a real,
                same-tenant canonical AITarget.
        """
        from redforge.core.exceptions import ValidationError
        from redforge.infrastructure.database.repositories.continuous_validation.repository import (
            SqlAlchemyContinuousValidationPolicyRepository,
        )
        from redforge.infrastructure.database.repositories.policy_lifecycle_repository import (
            SqlAlchemyPolicyLifecycleEventRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        try:
            parsed_profile = ValidationProfile(profile)
        except ValueError as exc:
            raise ValidationError(f"Unknown validation profile: {profile!r}") from exc
        try:
            parsed_cadence = ValidationCadence(cadence)
        except ValueError as exc:
            raise ValidationError(f"Unknown validation cadence: {cadence!r}") from exc

        # Ownership check — never create a policy against a target the
        # caller's organization does not own (raises TargetNotFoundError
        # otherwise, exactly like create_and_run()'s own target
        # normalization step).
        await self._ai_target_service.get_by_id(target_id, organization_id)

        policy = ContinuousValidationPolicy.create(
            organization_id=EntityId.from_string(organization_id),
            target_id=EntityId.from_string(target_id),
            requester_user_id=EntityId.from_string(requester_user_id),
            profile=parsed_profile,
            cadence=parsed_cadence,
        )

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyContinuousValidationPolicyRepository(uow.session)
            await repo.save(policy)
            lifecycle_repo = SqlAlchemyPolicyLifecycleEventRepository(uow.session)
            await lifecycle_repo.append(
                event_id=str(EntityId.generate()), organization_id=organization_id,
                policy_id=str(policy.id), event_type="created",
                detail={"cadence": cadence, "profile": profile},
                occurred_at=policy.timestamps.created_at,
            )
            await uow.commit()

        return ContinuousValidationPolicyDTO.from_entity(policy)

    async def get(
        self, organization_id: str, policy_id: str,
    ) -> ContinuousValidationPolicyDTO:
        policy = await self._load_readonly(organization_id, policy_id)
        return ContinuousValidationPolicyDTO.from_entity(policy)

    async def list_for_org(
        self,
        organization_id: str,
        lifecycle: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ContinuousValidationPolicyDTO]:
        from redforge.core.exceptions import ValidationError
        from redforge.infrastructure.database.repositories.continuous_validation.repository import (
            SqlAlchemyContinuousValidationPolicyRepository,
        )

        parsed_lifecycle: PolicyLifecycle | None = None
        if lifecycle is not None:
            try:
                parsed_lifecycle = PolicyLifecycle(lifecycle)
            except ValueError as exc:
                raise ValidationError(f"Unknown policy lifecycle: {lifecycle!r}") from exc

        async with self._session_factory() as session:
            repo = SqlAlchemyContinuousValidationPolicyRepository(session)
            policies = await repo.list_for_organization(
                EntityId.from_string(organization_id), parsed_lifecycle, limit, offset,
            )
        return [ContinuousValidationPolicyDTO.from_entity(p) for p in policies]

    async def activate(
        self, organization_id: str, policy_id: str,
    ) -> ContinuousValidationPolicyDTO:
        return await self._transition(organization_id, policy_id, "activate")

    async def pause(
        self, organization_id: str, policy_id: str,
    ) -> ContinuousValidationPolicyDTO:
        return await self._transition(organization_id, policy_id, "pause")

    async def resume(
        self, organization_id: str, policy_id: str,
    ) -> ContinuousValidationPolicyDTO:
        return await self._transition(organization_id, policy_id, "resume")

    async def disable(
        self, organization_id: str, policy_id: str,
    ) -> ContinuousValidationPolicyDTO:
        return await self._transition(organization_id, policy_id, "disable")

    # ─── Private ──────────────────────────────────────────────────────────

    async def _transition(
        self, organization_id: str, policy_id: str, verb: str,
    ) -> ContinuousValidationPolicyDTO:
        from redforge.infrastructure.database.repositories.continuous_validation.repository import (
            SqlAlchemyContinuousValidationPolicyRepository,
        )
        from redforge.infrastructure.database.repositories.policy_lifecycle_repository import (
            SqlAlchemyPolicyLifecycleEventRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        now = utc_now()
        safe_policy_id = _safe_entity_id(policy_id)
        safe_org_id = _safe_entity_id(organization_id)
        if safe_policy_id is None or safe_org_id is None:
            raise ContinuousValidationPolicyNotFoundError(policy_id)
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyContinuousValidationPolicyRepository(uow.session)
            # Row-locked read: serializes against a concurrent scheduler
            # post-run save() (see ContinuousValidationProcessor.
            # _release_and_advance()'s own docstring) so neither side
            # blindly overwrites the other's committed change.
            policy = await repo.get_by_id_for_organization_for_update(safe_policy_id, safe_org_id)
            if policy is None:
                raise ContinuousValidationPolicyNotFoundError(policy_id)
            if verb == "activate":
                policy.activate(now)
            elif verb == "pause":
                policy.pause(now)
            elif verb == "resume":
                policy.resume(now)
            else:
                policy.disable(now)
            await repo.save(policy)
            lifecycle_repo = SqlAlchemyPolicyLifecycleEventRepository(uow.session)
            await lifecycle_repo.append(
                event_id=str(EntityId.generate()), organization_id=organization_id,
                policy_id=str(policy.id), event_type=f"{verb}d",
                detail={}, occurred_at=now,
            )
            await uow.commit()
        return ContinuousValidationPolicyDTO.from_entity(policy)

    async def _load_readonly(
        self, organization_id: str, policy_id: str,
    ) -> ContinuousValidationPolicy:
        from redforge.infrastructure.database.repositories.continuous_validation.repository import (
            SqlAlchemyContinuousValidationPolicyRepository,
        )

        safe_policy_id = _safe_entity_id(policy_id)
        safe_org_id = _safe_entity_id(organization_id)
        if safe_policy_id is None or safe_org_id is None:
            raise ContinuousValidationPolicyNotFoundError(policy_id)
        async with self._session_factory() as session:
            repo = SqlAlchemyContinuousValidationPolicyRepository(session)
            policy = await repo.get_by_id_for_organization(safe_policy_id, safe_org_id)
        if policy is None:
            raise ContinuousValidationPolicyNotFoundError(policy_id)
        return policy


__all__ = [
    "ContinuousValidationPolicyDTO",
    "ContinuousValidationPolicyService",
]
