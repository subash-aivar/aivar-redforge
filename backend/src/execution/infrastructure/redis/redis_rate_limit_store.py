"""Redis rate limit store — Redis TIME + INCR/EXPIRE; Destruct via SET NX."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.domain.aggregates.rate_limit_bucket import RateLimitBucket
from execution.domain.ports.i_rate_limit_store import IRateLimitStore
from execution.domain.value_objects.enums import RateLimitDecision

if TYPE_CHECKING:
    from uuid import UUID

    from redis.asyncio import Redis

    from execution.domain.value_objects.execution_vos import RateLimitPolicy
    from execution.domain.value_objects.identifiers import TargetId, TenantId


class RedisRateLimitStore(IRateLimitStore):
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    @staticmethod
    def _bucket_key(
        tenant_id: TenantId, target_id: TargetId, technique_category: str
    ) -> str:
        return f"{tenant_id}:ratelimit:{target_id}:{technique_category}"

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
        if is_destruct:
            nx_key = (
                f"{tenant_id}:destruct:{engagement_id}:{target_id}"
            )
            # SET NX with engagement-lifetime TTL (30 days default).
            was_set = await self._redis.set(nx_key, "1", nx=True, ex=30 * 24 * 3600)
            if not was_set:
                return RateLimitDecision.FORBIDDEN
            return RateLimitDecision.PERMITTED

        # Use Redis TIME for server-side timestamps (Hardening §4).
        server_time = await self._redis.time()
        _ = server_time  # establishes clock authority; window via EXPIRE
        key = self._bucket_key(tenant_id, target_id, technique_category)
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, policy.window_duration_seconds, nx=True)
        results = await pipe.execute()
        count = int(results[0])
        return RateLimitBucket.decide_from_count(
            count,
            policy.max_executions,
            is_destruct=False,
            destruct_already_used=False,
        )
