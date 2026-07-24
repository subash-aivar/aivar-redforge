"""Shared fixtures for execution tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest

from execution.domain.value_objects.enums import ImpactCeiling
from execution.domain.value_objects.execution_vos import (
    RateLimitPolicy,
    ScopeSnapshot,
    TechniqueRef,
)
from execution.domain.value_objects.identifiers import (
    EngagementId,
    OperatorId,
    TargetId,
    TenantId,
)
from execution.infrastructure.redis.in_memory_kill_switch_store import InMemoryKillSwitchStore
from execution.infrastructure.redis.in_memory_rate_limit_store import InMemoryRateLimitStore


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.from_uuid(uuid7())


@pytest.fixture
def engagement_id() -> EngagementId:
    return EngagementId(uuid7())


@pytest.fixture
def operator_id() -> OperatorId:
    return OperatorId(uuid7())


@pytest.fixture
def target_id() -> TargetId:
    return TargetId(uuid7())


@pytest.fixture
def technique() -> TechniqueRef:
    return TechniqueRef("T1059", "execution", ImpactCeiling.PROBE)


@pytest.fixture
def rate_policy() -> RateLimitPolicy:
    return RateLimitPolicy(10, 60, "execution")


@pytest.fixture
def scope_snapshot(
    tenant_id: TenantId, engagement_id: EngagementId, target_id: TargetId, now: datetime
) -> ScopeSnapshot:
    return ScopeSnapshot(
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        authorized_target_ids=frozenset({target_id.value}),
        scope_hash="a" * 64,
        engagement_version=1,
        state="Active",
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=8),
        allowed_techniques=frozenset({"T1059", "T1003", "T1499"}),
        kill_switch_field_hint=None,
        degraded=False,
    )


@pytest.fixture
def kill_switch_store() -> InMemoryKillSwitchStore:
    return InMemoryKillSwitchStore()


@pytest.fixture
def rate_limit_store() -> InMemoryRateLimitStore:
    return InMemoryRateLimitStore()
