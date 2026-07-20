"""Infrastructure tests: in-memory Redis fail simulation."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid7

import pytest

from execution.domain.aggregates.kill_switch_state import KillSwitchState
from execution.domain.aggregates.rate_limit_bucket import RateLimitBucket
from execution.domain.ports.i_kill_switch_store import KillSwitchStoreUnavailable
from execution.domain.services.kill_switch_evaluation_service import (
    KillSwitchEvaluationService,
)
from execution.domain.value_objects.enums import (
    KillSwitchArmedState,
    KillSwitchScope,
    RateLimitDecision,
)
from execution.domain.value_objects.execution_vos import (
    RateLimitPolicy,
)
from execution.domain.value_objects.identifiers import EngagementId, TargetId, TenantId
from execution.infrastructure.redis.in_memory_kill_switch_store import InMemoryKillSwitchStore
from execution.infrastructure.redis.in_memory_rate_limit_store import InMemoryRateLimitStore


@pytest.mark.asyncio
async def test_in_memory_kill_switch_store_unavailability() -> None:
    store = InMemoryKillSwitchStore()
    tenant = TenantId(uuid7())
    now = datetime.now(UTC)
    ks = KillSwitchState.create_armed(
        tenant, KillSwitchScope.ENGAGEMENT, uuid7(), now
    )
    await store.set_state(ks)
    store.simulate_unavailability(True)
    with pytest.raises(KillSwitchStoreUnavailable):
        await store.get_state(tenant, KillSwitchScope.ENGAGEMENT, ks.scope_ref)

    svc = KillSwitchEvaluationService(store)
    state = await svc.evaluate(tenant, EngagementId(ks.scope_ref))
    assert state == KillSwitchArmedState.TRIGGERED


@pytest.mark.asyncio
async def test_in_memory_rate_limit_sliding_window() -> None:
    store = InMemoryRateLimitStore()
    tenant = TenantId(uuid7())
    target = TargetId(uuid7())
    policy = RateLimitPolicy(2, 60, "execution")
    d1 = await store.evaluate_and_consume(
        tenant, target, "execution", policy, engagement_id=uuid7(), is_destruct=False
    )
    d2 = await store.evaluate_and_consume(
        tenant, target, "execution", policy, engagement_id=uuid7(), is_destruct=False
    )
    d3 = await store.evaluate_and_consume(
        tenant, target, "execution", policy, engagement_id=uuid7(), is_destruct=False
    )
    assert d1 == RateLimitDecision.PERMITTED
    assert d2 == RateLimitDecision.PERMITTED
    assert d3 == RateLimitDecision.THROTTLED
    assert RateLimitBucket.destruct_hard_limit() == 1
