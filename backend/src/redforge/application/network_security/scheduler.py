"""NetworkMonitoringProcessor — M16. Claim -> orchestrate -> advance ->
release, mirroring application/continuous_validation/processor.py's own
claim/lock discipline. Reuses NetworkValidationOrchestrator.create_and_run()
unchanged for the actual run — M10's fresh-per-address authorization gate
is inherited automatically (see orchestrator.py's own docstring on why
nothing is cached).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.network_security.value_objects import PolicyLifecycle
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.network_security.orchestrator import (
        NetworkValidationOrchestrator,
        NetworkValidationRunDTO,
    )
    from redforge.domain.network_security.entity import NetworkMonitoringPolicy


class NetworkMonitoringProcessor:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        orchestrator: NetworkValidationOrchestrator,
    ) -> None:
        self._session_factory = session_factory
        self._orchestrator = orchestrator

    async def process_one_due_policy(self, worker_id: str) -> NetworkValidationRunDTO | None:
        """Claim and process exactly one due policy. Returns None when
        nothing is currently due — the normal steady state, never an
        error."""
        from redforge.infrastructure.database.repositories.network_security.policy_repository import (  # noqa: E501
            SqlAlchemyNetworkMonitoringPolicyRepository,
        )

        now = utc_now()
        async with self._session_factory() as session:
            policy_repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            policy = await policy_repo.claim_one_due_policy(now, worker_id)
            await session.commit()

        if policy is None:
            return None

        try:
            run = await self._orchestrator.create_and_run(
                organization_id=str(policy.organization_id),
                target_asset_id=str(policy.target_asset_id),
                requester_user_id=str(policy.requester_user_id),
                profile=policy.profile, trigger="scheduled",
                continuous_policy_id=str(policy.id), scheduled_due_at=policy.next_due_at,
            )
        except Exception:
            await self._release_claim_only(policy)
            raise

        await self._release_and_advance(policy, now)
        return run

    async def run_now(self, organization_id: str, policy_id: str) -> NetworkValidationRunDTO:
        """Operator-triggered ON_DEMAND run — same execute pipeline,
        not tied to a due boundary."""
        from redforge.domain.network_security.exceptions import (
            NetworkMonitoringPolicyNotFoundError,
            NetworkPolicyDisabledForRunError,
        )
        from redforge.infrastructure.database.repositories.network_security.policy_repository import (  # noqa: E501
            SqlAlchemyNetworkMonitoringPolicyRepository,
        )
        from redforge.shared.identifiers import EntityId

        try:
            safe_policy_id = EntityId.from_string(policy_id)
            safe_org_id = EntityId.from_string(organization_id)
        except ValueError as exc:
            raise NetworkMonitoringPolicyNotFoundError(policy_id) from exc

        async with self._session_factory() as session:
            policy_repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            policy = await policy_repo.get_by_id_for_organization(safe_policy_id, safe_org_id)
        if policy is None:
            raise NetworkMonitoringPolicyNotFoundError(policy_id)
        if policy.lifecycle == PolicyLifecycle.DISABLED:
            raise NetworkPolicyDisabledForRunError(policy_id)

        return await self._orchestrator.create_and_run(
            organization_id=str(policy.organization_id),
            target_asset_id=str(policy.target_asset_id),
            requester_user_id=str(policy.requester_user_id),
            profile=policy.profile, trigger="on_demand",
            continuous_policy_id=str(policy.id), scheduled_due_at=None,
        )

    async def _release_and_advance(
        self, policy: NetworkMonitoringPolicy, now: datetime,
    ) -> None:
        def _advance_and_release(fresh: NetworkMonitoringPolicy) -> None:
            fresh.advance_schedule(now)
            fresh.release_claim()

        await self._mutate_under_lock(policy, _advance_and_release)

    async def _release_claim_only(self, policy: NetworkMonitoringPolicy) -> None:
        await self._mutate_under_lock(policy, lambda fresh: fresh.release_claim())

    async def _mutate_under_lock(
        self, policy: NetworkMonitoringPolicy, mutate: Callable[[NetworkMonitoringPolicy], None],
    ) -> None:
        from redforge.infrastructure.database.repositories.network_security.policy_repository import (  # noqa: E501
            SqlAlchemyNetworkMonitoringPolicyRepository,
        )

        async with self._session_factory() as session:
            policy_repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            fresh = await policy_repo.get_by_id_for_organization_for_update(
                policy.id, policy.organization_id,
            )
            if fresh is None or fresh.lifecycle == PolicyLifecycle.DISABLED:
                await session.commit()
                return
            mutate(fresh)
            await policy_repo.save(fresh)
            await session.commit()
