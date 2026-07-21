"""Tests for CampaignSafetyMonitor aggregate."""

from __future__ import annotations

import pytest

from campaignexecution.domain.aggregates.campaign_safety_monitor import CampaignSafetyMonitor
from campaignexecution.domain.exceptions.domain_exceptions import (
    MonitorAutoAbortAlreadyTriggered,
    SafetyPolicyViolation,
)
from campaignexecution.domain.value_objects.enums import MonitorState
from campaignexecution.domain.value_objects.execution_vos import (
    CampaignInstanceRef,
    PolicySnapshot,
)
from campaignexecution.domain.value_objects.identifiers import (
    SafetyMonitorId,
    TenantId,
)


def make_monitor(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> CampaignSafetyMonitor:
    from datetime import UTC, datetime

    now_dt = now if isinstance(now, datetime) else datetime.now(UTC)
    return CampaignSafetyMonitor.create(
        monitor_id=SafetyMonitorId.generate(),
        tenant_id=tenant_id,
        campaign_instance_ref=campaign_instance_ref,
        policy_snapshot=policy_snapshot,
        now=now_dt,
    )


def test_create_monitor_starts_active(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    monitor = make_monitor(tenant_id, campaign_instance_ref, policy_snapshot, now)
    assert monitor.monitor_state == MonitorState.ACTIVE
    assert monitor.concurrent_action_count == 0
    assert not monitor.auto_abort_triggered


def test_register_action_increments_count(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    monitor = make_monitor(tenant_id, campaign_instance_ref, policy_snapshot, now)
    monitor.register_action(tenant_id, "op-1", datetime.now(UTC))
    assert monitor.concurrent_action_count == 1


def test_ceiling_enforced_raises_on_breach(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    now: object,
) -> None:
    from datetime import UTC, datetime

    policy = PolicySnapshot(
        max_concurrent_actions=2,
        auto_abort_on_detection=False,
        auto_abort_on_objective_failure=False,
        blast_radius_ceiling="Low",
    )
    monitor = make_monitor(tenant_id, campaign_instance_ref, policy, now)
    monitor.register_action(tenant_id, "op-1", datetime.now(UTC))
    monitor.register_action(tenant_id, "op-2", datetime.now(UTC))

    with pytest.raises(SafetyPolicyViolation, match="max_concurrent_actions"):
        monitor.register_action(tenant_id, "op-3", datetime.now(UTC))


def test_concurrent_action_count_never_exceeds_ceiling(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    now: object,
) -> None:
    from datetime import UTC, datetime

    # Test with 100 concurrent tasks (load test scenario)
    policy = PolicySnapshot(
        max_concurrent_actions=100,
        auto_abort_on_detection=False,
        auto_abort_on_objective_failure=False,
        blast_radius_ceiling="High",
    )
    monitor = make_monitor(tenant_id, campaign_instance_ref, policy, now)
    for i in range(100):
        monitor.register_action(tenant_id, f"op-{i}", datetime.now(UTC))

    assert monitor.concurrent_action_count == 100

    with pytest.raises(SafetyPolicyViolation):
        monitor.register_action(tenant_id, "op-100", datetime.now(UTC))


def test_release_action_decrements_count(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    monitor = make_monitor(tenant_id, campaign_instance_ref, policy_snapshot, now)
    monitor.register_action(tenant_id, "op-1", datetime.now(UTC))
    monitor.release_action(tenant_id, "op-1", datetime.now(UTC))
    assert monitor.concurrent_action_count == 0


def test_release_is_idempotent(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    monitor = make_monitor(tenant_id, campaign_instance_ref, policy_snapshot, now)
    monitor.register_action(tenant_id, "op-1", datetime.now(UTC))
    monitor.release_action(tenant_id, "op-1", datetime.now(UTC))
    # Second release should not raise
    monitor.release_action(tenant_id, "op-1", datetime.now(UTC))
    assert monitor.concurrent_action_count == 0


def test_auto_abort_on_detection_triggers(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    now: object,
) -> None:
    from datetime import UTC, datetime

    policy = PolicySnapshot(
        max_concurrent_actions=5,
        auto_abort_on_detection=True,
        auto_abort_on_objective_failure=False,
        blast_radius_ceiling="Medium",
    )
    monitor = make_monitor(tenant_id, campaign_instance_ref, policy, now)
    monitor.trigger_auto_abort_on_detection(tenant_id, "DetectionFinding-123", datetime.now(UTC))
    assert monitor.auto_abort_triggered
    assert monitor.monitor_state == MonitorState.ABORTED


def test_auto_abort_is_irreversible(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    now: object,
) -> None:
    from datetime import UTC, datetime

    policy = PolicySnapshot(
        max_concurrent_actions=5,
        auto_abort_on_detection=True,
        auto_abort_on_objective_failure=False,
        blast_radius_ceiling="Medium",
    )
    monitor = make_monitor(tenant_id, campaign_instance_ref, policy, now)
    monitor.trigger_auto_abort_on_detection(tenant_id, "detection-1", datetime.now(UTC))

    with pytest.raises(MonitorAutoAbortAlreadyTriggered):
        monitor.register_action(tenant_id, "new-op", datetime.now(UTC))


def test_auto_abort_noop_when_disabled(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    # policy_snapshot has auto_abort_on_detection=False
    monitor = make_monitor(tenant_id, campaign_instance_ref, policy_snapshot, now)
    monitor.trigger_auto_abort_on_detection(tenant_id, "detection-1", datetime.now(UTC))
    # Should not trigger because policy is disabled
    assert not monitor.auto_abort_triggered
    assert monitor.monitor_state == MonitorState.ACTIVE


def test_release_monitor_clears_active_ops(
    tenant_id: TenantId,
    campaign_instance_ref: CampaignInstanceRef,
    policy_snapshot: PolicySnapshot,
    now: object,
) -> None:
    from datetime import UTC, datetime

    monitor = make_monitor(tenant_id, campaign_instance_ref, policy_snapshot, now)
    monitor.register_action(tenant_id, "op-1", datetime.now(UTC))
    monitor.register_action(tenant_id, "op-2", datetime.now(UTC))
    monitor.release(tenant_id, datetime.now(UTC))
    assert monitor.monitor_state == MonitorState.RELEASED
    assert monitor.concurrent_action_count == 0
