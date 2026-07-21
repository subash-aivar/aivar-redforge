"""ExposureReductionPlan aggregate — Finalization Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from remediation_impact.domain.events.plan_events import (
    ExposureReductionPlanCommitted,
    ExposureReductionPlanGenerated,
)
from remediation_impact.domain.exceptions.domain_exceptions import (
    InvalidPlanTransition,
    TenantMismatch,
)
from remediation_impact.domain.value_objects.enums import PlanStatus

if TYPE_CHECKING:
    from remediation_impact.domain.events.base import BaseDomainEvent
    from remediation_impact.domain.value_objects.identifiers import (
        ExposureReductionPlanId,
        TenantId,
    )
    from remediation_impact.domain.value_objects.simulation_vos import SimulationResult

STALE_AFTER = timedelta(days=30)


class ExposureReductionPlan:
    __slots__ = (
        "_pending_events",
        "committed_at",
        "committed_by",
        "generated_at",
        "plan_id",
        "simulation",
        "status",
        "tenant_id",
    )

    def __init__(
        self,
        plan_id: ExposureReductionPlanId,
        tenant_id: TenantId,
        simulation: SimulationResult,
        status: PlanStatus,
        generated_at: datetime,
        committed_at: datetime | None = None,
        committed_by: str | None = None,
    ) -> None:
        self.plan_id = plan_id
        self.tenant_id = tenant_id
        self.simulation = simulation
        self.status = status
        self.generated_at = generated_at
        self.committed_at = committed_at
        self.committed_by = committed_by
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def create(
        cls,
        plan_id: ExposureReductionPlanId,
        tenant_id: TenantId,
        simulation: SimulationResult,
        generated_at: datetime | None = None,
    ) -> ExposureReductionPlan:
        at = generated_at or datetime.now(UTC)
        plan = cls(plan_id, tenant_id, simulation, PlanStatus.GENERATED, at)
        plan._emit(
            ExposureReductionPlanGenerated(
                tenant_id=str(tenant_id),
                aggregate_id=str(plan_id),
                projected_exposure_reduction=simulation.projected_exposure_reduction,
                algorithm=simulation.algorithm,
                step_count=len(simulation.plan_steps),
            )
        )
        return plan

    def commit(self, tenant_id: TenantId, committed_by: str, at: datetime | None = None) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on commit")
        if self.status != PlanStatus.GENERATED:
            raise InvalidPlanTransition("only Generated plans can be committed")
        if not committed_by.strip():
            raise InvalidPlanTransition("committed_by required")
        when = at or datetime.now(UTC)
        self.status = PlanStatus.COMMITTED
        self.committed_at = when
        self.committed_by = committed_by
        self._emit(
            ExposureReductionPlanCommitted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.plan_id),
                committed_by=committed_by,
            )
        )

    def is_stale(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return (now - self.generated_at) > STALE_AFTER
