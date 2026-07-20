"""RateLimitEvaluationService — delegates atomic consume to rate limit store."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.domain.aggregates.rate_limit_bucket import RateLimitBucket
from execution.domain.value_objects.enums import ImpactCeiling
from execution.domain.value_objects.execution_vos import RateLimitPolicy

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.ports.i_rate_limit_store import IRateLimitStore
    from execution.domain.value_objects.enums import RateLimitDecision
    from execution.domain.value_objects.execution_vos import TechniqueRef
    from execution.domain.value_objects.identifiers import TargetId, TenantId


class RateLimitEvaluationService:
    def __init__(self, store: IRateLimitStore) -> None:
        self._store = store

    async def evaluate(
        self,
        tenant_id: TenantId,
        target_id: TargetId,
        technique_ref: TechniqueRef,
        policy: RateLimitPolicy,
        engagement_id: UUID,
    ) -> RateLimitDecision:
        is_destruct = technique_ref.impact_ceiling == ImpactCeiling.DESTRUCT
        effective_policy = policy
        if is_destruct:
            # Hard-coded Destruct ceiling: max 1 per engagement per target.
            effective_policy = RateLimitPolicy(
                max_executions=RateLimitBucket.destruct_hard_limit(),
                window_duration_seconds=policy.window_duration_seconds,
                technique_category=technique_ref.technique_category,
            )
        return await self._store.evaluate_and_consume(
            tenant_id,
            target_id,
            technique_ref.technique_category,
            effective_policy,
            engagement_id=engagement_id,
            is_destruct=is_destruct,
        )
