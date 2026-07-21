"""CampaignSafetyMonitor aggregate root — enforces safety policy during execution."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from campaignexecution.domain.events.execution_events import (
    ConcurrentActionRegistered,
    ConcurrentActionReleased,
    SafetyMonitorAborted,
    SafetyMonitorInitialized,
    SafetyMonitorReleased,
)
from campaignexecution.domain.exceptions.domain_exceptions import (
    MonitorAutoAbortAlreadyTriggered,
    SafetyPolicyViolation,
    TenantMismatch,
)
from campaignexecution.domain.value_objects.enums import MonitorState

if TYPE_CHECKING:
    from datetime import datetime

    from campaignexecution.domain.events.base import BaseDomainEvent
    from campaignexecution.domain.value_objects.execution_vos import (
        CampaignInstanceRef,
        PolicySnapshot,
    )
    from campaignexecution.domain.value_objects.identifiers import (
        SafetyMonitorId,
        TenantId,
    )


class CampaignSafetyMonitor:
    """Enforces campaign-level safety policy during execution.

    Tracks concurrent action count. Enforces max_concurrent_actions ceiling.
    Triggers auto-abort when detection event received (if configured).
    Auto-abort is irreversible for the lifetime of this monitor instance.
    """

    __slots__ = (
        "_pending_events",
        "_version",
        "active_operation_ids",
        "auto_abort_triggered",
        "campaign_instance_ref",
        "monitor_id",
        "monitor_state",
        "policy_snapshot",
        "tenant_id",
    )

    def __init__(
        self,
        monitor_id: SafetyMonitorId,
        tenant_id: TenantId,
        campaign_instance_ref: CampaignInstanceRef,
        policy_snapshot: PolicySnapshot,
        monitor_state: MonitorState,
        auto_abort_triggered: bool,
        active_operation_ids: list[str],
        version: int,
    ) -> None:
        self.monitor_id = monitor_id
        self.tenant_id = tenant_id
        self.campaign_instance_ref = campaign_instance_ref
        self.policy_snapshot = policy_snapshot
        self.monitor_state = monitor_state
        self.auto_abort_triggered = auto_abort_triggered
        self.active_operation_ids = list(active_operation_ids)
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def concurrent_action_count(self) -> int:
        return len(self.active_operation_ids)

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self) -> None:
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def create(
        cls,
        monitor_id: SafetyMonitorId,
        tenant_id: TenantId,
        campaign_instance_ref: CampaignInstanceRef,
        policy_snapshot: PolicySnapshot,
        now: datetime,
    ) -> CampaignSafetyMonitor:
        monitor = cls(
            monitor_id=monitor_id,
            tenant_id=tenant_id,
            campaign_instance_ref=campaign_instance_ref,
            policy_snapshot=policy_snapshot,
            monitor_state=MonitorState.ACTIVE,
            auto_abort_triggered=False,
            active_operation_ids=[],
            version=1,
        )
        monitor._emit(
            SafetyMonitorInitialized(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(monitor_id),
                aggregate_type="CampaignSafetyMonitor",
                campaign_instance_id=str(campaign_instance_ref.instance_id),
                max_concurrent_actions=policy_snapshot.max_concurrent_actions,
                auto_abort_on_detection=policy_snapshot.auto_abort_on_detection,
            )
        )
        return monitor

    def register_action(
        self,
        tenant_id: TenantId,
        operation_id: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.auto_abort_triggered:
            raise MonitorAutoAbortAlreadyTriggered(str(self.monitor_id))
        if self.monitor_state != MonitorState.ACTIVE:
            raise SafetyPolicyViolation("monitor_state", "Safety monitor is not active")

        if operation_id in self.active_operation_ids:
            return  # Idempotent

        ceiling = self.policy_snapshot.max_concurrent_actions
        if len(self.active_operation_ids) >= ceiling:
            raise SafetyPolicyViolation(
                "max_concurrent_actions",
                f"Would exceed ceiling of {ceiling} concurrent actions",
            )

        self.active_operation_ids.append(operation_id)
        self._mutate()
        self._emit(
            ConcurrentActionRegistered(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.monitor_id),
                aggregate_type="CampaignSafetyMonitor",
                operation_id=operation_id,
                current_count=len(self.active_operation_ids),
                ceiling=ceiling,
            )
        )

    def release_action(
        self,
        tenant_id: TenantId,
        operation_id: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if operation_id not in self.active_operation_ids:
            return  # Idempotent: already released
        self.active_operation_ids.remove(operation_id)
        self._mutate()
        self._emit(
            ConcurrentActionReleased(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.monitor_id),
                aggregate_type="CampaignSafetyMonitor",
                operation_id=operation_id,
                current_count=len(self.active_operation_ids),
            )
        )

    def trigger_auto_abort_on_detection(
        self,
        tenant_id: TenantId,
        detection_detail: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not self.policy_snapshot.auto_abort_on_detection:
            return  # Policy does not require auto-abort on detection
        if self.auto_abort_triggered:
            return  # Idempotent: already triggered

        self.auto_abort_triggered = True
        self.monitor_state = MonitorState.ABORTED
        self._mutate()
        self._emit(
            SafetyMonitorAborted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.monitor_id),
                aggregate_type="CampaignSafetyMonitor",
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
                reason=f"auto_abort_on_detection: {detection_detail}",
            )
        )

    def release(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self.monitor_state = MonitorState.RELEASED
        self.active_operation_ids.clear()
        self._mutate()
        self._emit(
            SafetyMonitorReleased(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(self.monitor_id),
                aggregate_type="CampaignSafetyMonitor",
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
            )
        )
