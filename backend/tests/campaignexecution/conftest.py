"""Shared fixtures for campaignexecution tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from campaignexecution.domain.value_objects.execution_vos import (
    CampaignInstanceRef,
    EngagementRef,
    PolicySnapshot,
    TaskGraphVersionRef,
)
from campaignexecution.domain.value_objects.identifiers import (
    CampaignTaskId,
    SafetyMonitorId,
    TaskGraphExecutionId,
    TenantId,
)


@pytest.fixture()
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture()
def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture()
def policy_snapshot() -> PolicySnapshot:
    return PolicySnapshot(
        max_concurrent_actions=5,
        auto_abort_on_detection=False,
        auto_abort_on_objective_failure=False,
        blast_radius_ceiling="Medium",
    )


@pytest.fixture()
def campaign_instance_ref(tenant_id: TenantId) -> CampaignInstanceRef:
    return CampaignInstanceRef(
        instance_id=uuid4(),
        campaign_id=uuid4(),
        tenant_id=tenant_id.value,
    )


@pytest.fixture()
def graph_version_ref() -> TaskGraphVersionRef:
    return TaskGraphVersionRef(graph_id=uuid4(), version_str="1.0.0")


@pytest.fixture()
def engagement_ref(tenant_id: TenantId) -> EngagementRef:
    return EngagementRef(engagement_id=uuid4(), tenant_id=tenant_id.value)


@pytest.fixture()
def task_ids() -> list[CampaignTaskId]:
    return [CampaignTaskId(uuid4()) for _ in range(3)]


@pytest.fixture()
def execution_id() -> TaskGraphExecutionId:
    return TaskGraphExecutionId.generate()


@pytest.fixture()
def monitor_id() -> SafetyMonitorId:
    return SafetyMonitorId.generate()
