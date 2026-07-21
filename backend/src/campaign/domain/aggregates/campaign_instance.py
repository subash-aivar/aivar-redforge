"""CampaignInstance aggregate root — single execution run of a Campaign."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from campaign.domain.events.campaign_events import (
    CampaignInstanceAborted,
    CampaignInstanceCompleted,
    CampaignInstanceFailed,
    CampaignInstanceStarted,
)
from campaign.domain.exceptions.domain_exceptions import (
    InvalidStateTransition,
    TenantMismatch,
)
from campaign.domain.value_objects.enums import InstanceState
from campaign.domain.value_objects.identifiers import (
    CampaignId,
    CampaignInstanceId,
)

if TYPE_CHECKING:
    from datetime import datetime

    from campaign.domain.events.base import BaseDomainEvent
    from campaign.domain.value_objects.campaign_vos import SelectedTargetSet, TargetRef
    from campaign.domain.value_objects.identifiers import TenantId

_ALLOWED_TRANSITIONS: dict[InstanceState, frozenset[InstanceState]] = {
    InstanceState.STARTING: frozenset({InstanceState.RUNNING, InstanceState.FAILED}),
    InstanceState.RUNNING: frozenset(
        {InstanceState.PAUSED, InstanceState.COMPLETED, InstanceState.FAILED, InstanceState.ABORTED}
    ),
    InstanceState.PAUSED: frozenset({InstanceState.RUNNING, InstanceState.ABORTED}),
    InstanceState.COMPLETED: frozenset(),
    InstanceState.FAILED: frozenset(),
    InstanceState.ABORTED: frozenset(),
}


class CampaignInstance:
    """A single execution run of a Campaign against resolved targets.

    Instances are immutable snapshots — the resolved target set is fixed at
    instance start time and never changes during execution.
    """

    __slots__ = (
        "_pending_events",
        "_version",
        "campaign_id",
        "completed_at",
        "failure_reason",
        "instance_id",
        "resolved_targets",
        "run_number",
        "started_at",
        "state",
        "tenant_id",
    )

    def __init__(
        self,
        instance_id: CampaignInstanceId,
        campaign_id: CampaignId,
        tenant_id: TenantId,
        run_number: int,
        state: InstanceState,
        resolved_targets: list[TargetRef],
        started_at: datetime,
        completed_at: datetime | None,
        failure_reason: str | None,
        version: int,
    ) -> None:
        self.instance_id = instance_id
        self.campaign_id = campaign_id
        self.tenant_id = tenant_id
        self.run_number = run_number
        self.state = state
        self.resolved_targets = list(resolved_targets)
        self.started_at = started_at
        self.completed_at = completed_at
        self.failure_reason = failure_reason
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _mutate(self, now: datetime) -> None:
        self._version += 1

    def _transition(self, to_state: InstanceState) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                to_state.value,
                str(self.instance_id),
            )
        self.state = to_state

    @classmethod
    def start(
        cls,
        instance_id: CampaignInstanceId,
        campaign_id: CampaignId,
        tenant_id: TenantId,
        run_number: int,
        resolved_targets: SelectedTargetSet,
        now: datetime,
    ) -> CampaignInstance:
        instance = cls(
            instance_id=instance_id,
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            run_number=run_number,
            state=InstanceState.RUNNING,
            resolved_targets=list(resolved_targets.targets),
            started_at=now,
            completed_at=None,
            failure_reason=None,
            version=1,
        )
        instance._emit(
            CampaignInstanceStarted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(instance_id),
                aggregate_type="CampaignInstance",
                instance_id=str(instance_id),
                run_number=run_number,
            )
        )
        return instance

    def complete(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(InstanceState.COMPLETED)
        self.completed_at = now
        self._mutate(now)
        self._emit(
            CampaignInstanceCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.instance_id),
                aggregate_type="CampaignInstance",
                instance_id=str(self.instance_id),
                run_number=self.run_number,
            )
        )

    def fail(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(InstanceState.FAILED)
        self.completed_at = now
        self.failure_reason = reason
        self._mutate(now)
        self._emit(
            CampaignInstanceFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.instance_id),
                aggregate_type="CampaignInstance",
                instance_id=str(self.instance_id),
                run_number=self.run_number,
                reason=reason,
            )
        )

    def abort(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(InstanceState.ABORTED)
        self.completed_at = now
        self.failure_reason = reason
        self._mutate(now)
        self._emit(
            CampaignInstanceAborted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.instance_id),
                aggregate_type="CampaignInstance",
                instance_id=str(self.instance_id),
                run_number=self.run_number,
                reason=reason,
            )
        )
