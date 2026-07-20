"""In-memory rate limit store for unit tests."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from execution.domain.aggregates.rate_limit_bucket import RateLimitBucket
from execution.domain.ports.i_rate_limit_store import IRateLimitStore
from execution.domain.value_objects.enums import RateLimitDecision

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.value_objects.execution_vos import RateLimitPolicy
    from execution.domain.value_objects.identifiers import TargetId, TenantId


class InMemoryRateLimitStore(IRateLimitStore):
    def __init__(self) -> None:
        self._counts: dict[tuple[str, str, str], tuple[int, float]] = {}
        self._destruct_keys: set[str] = set()

    async def evaluate_and_consume(
        self,
        tenant_id: TenantId,
        target_id: TargetId,
        technique_category: str,
        policy: RateLimitPolicy,
        *,
        engagement_id: UUID,
        is_destruct: bool,
    ) -> RateLimitDecision:
        now = time.time()
        if is_destruct:
            nx_key = RateLimitBucket.destruct_nx_key(engagement_id, target_id)
            if nx_key in self._destruct_keys:
                return RateLimitDecision.FORBIDDEN
            self._destruct_keys.add(nx_key)
            return RateLimitDecision.PERMITTED

        key = (str(tenant_id), str(target_id), technique_category)
        count, window_start = self._counts.get(key, (0, now))
        if now - window_start >= policy.window_duration_seconds:
            count = 0
            window_start = now
        count += 1
        self._counts[key] = (count, window_start)
        return RateLimitBucket.decide_from_count(
            count,
            policy.max_executions,
            is_destruct=False,
            destruct_already_used=False,
        )
