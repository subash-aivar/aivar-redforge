"""Domain tests: kill switch state machine and fail-safe evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid7

import pytest

from execution.domain.aggregates.kill_switch_state import KillSwitchState
from execution.domain.exceptions.domain_exceptions import (
    PlatformWideReleaseAuthorizationInsufficient,
    SameOperatorReleaseForbidden,
)
from execution.domain.services.kill_switch_evaluation_service import (
    KillSwitchEvaluationService,
)
from execution.domain.value_objects.enums import (
    CISO_ROLE,
    KillSwitchArmedState,
    KillSwitchScope,
)
from execution.domain.value_objects.execution_vos import (
    ReleaseAuthority,
    TriggerAuthority,
    TriggerReason,
)
from execution.domain.value_objects.identifiers import EngagementId, OperatorId, TenantId
from execution.infrastructure.redis.in_memory_kill_switch_store import InMemoryKillSwitchStore


def test_kill_switch_armed_to_triggered_to_released_to_armed() -> None:
    now = datetime.now(UTC)
    tenant = TenantId(uuid7())
    eng = uuid7()
    ks = KillSwitchState.create_armed(tenant, KillSwitchScope.ENGAGEMENT, eng, now)
    op1 = OperatorId(uuid7())
    op2 = OperatorId(uuid7())
    ks.trigger(tenant, TriggerAuthority(op1, "redteam:admin"), TriggerReason("incident"), now)
    assert ks.armed_state == KillSwitchArmedState.TRIGGERED
    assert ks.trigger_hash is not None
    ks.release(tenant, ReleaseAuthority(op2, "redteam:admin"), now)
    assert ks.armed_state == KillSwitchArmedState.RELEASED
    ks.re_arm(tenant, TriggerAuthority(op2, "redteam:admin"), now)
    assert ks.armed_state == KillSwitchArmedState.ARMED


def test_same_operator_cannot_release() -> None:
    now = datetime.now(UTC)
    tenant = TenantId(uuid7())
    ks = KillSwitchState.create_armed(
        tenant, KillSwitchScope.ENGAGEMENT, uuid7(), now
    )
    op = OperatorId(uuid7())
    ks.trigger(tenant, TriggerAuthority(op, "redteam:admin"), TriggerReason("stop"), now)
    with pytest.raises(SameOperatorReleaseForbidden):
        ks.release(tenant, ReleaseAuthority(op, "redteam:admin"), now)


def test_platform_wide_requires_ciso_and_oversight() -> None:
    now = datetime.now(UTC)
    tenant = TenantId(uuid7())
    ks = KillSwitchState.create_armed(
        tenant, KillSwitchScope.PLATFORM_WIDE, tenant.value, now
    )
    trigger_op = OperatorId(uuid7())
    ciso = OperatorId(uuid7())
    legal = OperatorId(uuid7())
    ks.trigger(
        tenant, TriggerAuthority(trigger_op, "redteam:admin"), TriggerReason("global"), now
    )
    with pytest.raises(PlatformWideReleaseAuthorizationInsufficient):
        ks.release(tenant, ReleaseAuthority(ciso, CISO_ROLE), now)
    with pytest.raises(PlatformWideReleaseAuthorizationInsufficient):
        ks.release(
            tenant,
            ReleaseAuthority(ciso, CISO_ROLE),
            now,
            countersigning=ReleaseAuthority(legal, CISO_ROLE),
        )
    ks.release(
        tenant,
        ReleaseAuthority(ciso, CISO_ROLE),
        now,
        countersigning=ReleaseAuthority(legal, "legal:oversight"),
    )
    assert ks.armed_state == KillSwitchArmedState.RELEASED


@pytest.mark.asyncio
async def test_kill_switch_evaluation_fail_safe_on_unavailable() -> None:
    store = InMemoryKillSwitchStore(unavailable=True)
    svc = KillSwitchEvaluationService(store)
    tenant = TenantId(uuid7())
    state = await svc.evaluate(tenant, EngagementId(uuid7()))
    assert state == KillSwitchArmedState.TRIGGERED


@pytest.mark.asyncio
async def test_kill_switch_evaluation_platform_first() -> None:
    store = InMemoryKillSwitchStore()
    tenant = TenantId(uuid7())
    engagement = EngagementId(uuid7())
    now = datetime.now(UTC)
    platform = KillSwitchState.create_armed(
        tenant, KillSwitchScope.PLATFORM_WIDE, tenant.value, now
    )
    platform.trigger(
        tenant,
        TriggerAuthority(OperatorId(uuid7()), "redteam:admin"),
        TriggerReason("platform stop"),
        now,
    )
    await store.set_state(platform)
    svc = KillSwitchEvaluationService(store)
    assert await svc.evaluate(tenant, engagement) == KillSwitchArmedState.TRIGGERED
