"""Operation aggregate root — planning, DAG, and authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from operation.domain.entities.operation_entities import (
    ExecutionStep,
    OperationApproval,
    OperationObjective,
    StepDependency,
)
from operation.domain.events.operation_events import (
    ExecutionStepAdded,
    ExecutionStepRemoved,
    OperationAborted,
    OperationApproved,
    OperationCompleted,
    OperationCreated,
    OperationFailed,
    OperationPaused,
    OperationQueued,
    OperationResumed,
    OperationStarted,
    OperationSubmittedForApproval,
)
from operation.domain.exceptions.domain_exceptions import (
    ApprovalAuthorityInsufficient,
    CyclicDependencyError,
    EngagementNotActive,
    InvalidArgument,
    InvalidStateTransition,
    TenantMismatch,
)
from operation.domain.services.operation_risk_assessor import OperationRiskAssessor
from operation.domain.value_objects.enums import (
    OperationRisk,
    OperationState,
    StepState,
)
from operation.domain.value_objects.identifiers import (
    ExecutionStepId,
    OperationApprovalId,
    OperationId,
    OperationObjectiveId,
    StepDependencyId,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from operation.domain.events.base import BaseDomainEvent
    from operation.domain.value_objects.enums import (
        ImpactCeiling,
        OperationClassification,
        StepType,
    )
    from operation.domain.value_objects.identifiers import EngagementId, TenantId
    from operation.domain.value_objects.plan_vos import (
        ExecutionWindowConstraint,
        MitreAttackRef,
        RateLimit,
        StepConstraints,
        StepTargetRef,
        StepTechniqueRef,
    )

_CISO_AUTHORITY = "CISO"
_CRITICAL_CISO_APPROVALS_REQUIRED = 2

_ALLOWED: dict[OperationState, frozenset[OperationState]] = {
    OperationState.PLANNING: frozenset(
        {
            OperationState.PENDING_OPERATION_APPROVAL,
            OperationState.ABORTED,
        }
    ),
    OperationState.PENDING_OPERATION_APPROVAL: frozenset(
        {
            OperationState.APPROVED,
            OperationState.PLANNING,
            OperationState.ABORTED,
        }
    ),
    OperationState.APPROVED: frozenset(
        {
            OperationState.QUEUED,
            OperationState.ABORTED,
        }
    ),
    OperationState.QUEUED: frozenset(
        {
            OperationState.RUNNING,
            OperationState.ABORTED,
            OperationState.FAILED,
        }
    ),
    OperationState.RUNNING: frozenset(
        {
            OperationState.PAUSED,
            OperationState.COMPLETED,
            OperationState.ABORTED,
            OperationState.FAILED,
        }
    ),
    OperationState.PAUSED: frozenset(
        {
            OperationState.RUNNING,
            OperationState.ABORTED,
            OperationState.FAILED,
        }
    ),
    OperationState.COMPLETED: frozenset(),
    OperationState.ABORTED: frozenset(),
    OperationState.FAILED: frozenset(),
}


class Operation:
    """Planned offensive operation within an engagement."""

    __slots__ = (
        "_pending_events",
        "_version",
        "abort_reason",
        "approvals",
        "classification",
        "created_at",
        "dependencies",
        "engagement_id",
        "name",
        "objectives",
        "operation_id",
        "risk",
        "state",
        "steps",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        operation_id: OperationId,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        name: str,
        classification: OperationClassification,
        state: OperationState,
        risk: OperationRisk,
        steps: dict[str, ExecutionStep],
        dependencies: list[StepDependency],
        approvals: list[OperationApproval],
        objectives: list[OperationObjective],
        abort_reason: str | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.operation_id = operation_id
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id
        self.name = name
        self.classification = classification
        self.state = state
        self.risk = risk
        self.steps = dict(steps)
        self.dependencies = list(dependencies)
        self.approvals = list(approvals)
        self.objectives = list(objectives)
        self.abort_reason = abort_reason
        self.created_at = created_at
        self.updated_at = updated_at
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

    def record_plan_drafted(self, *, tenant_id: TenantId, now: datetime) -> None:
        """Record that an execution plan snapshot was drafted for signing."""
        self._assert_tenant(tenant_id)
        from uuid import uuid7

        from operation.domain.events.operation_events import ExecutionPlanDrafted

        self._emit(
            ExecutionPlanDrafted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                step_count=len(self.steps),
            )
        )

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_planning(self) -> None:
        if self.state != OperationState.PLANNING:
            raise InvalidStateTransition(
                self.state.value,
                "modify_plan",
                str(self.operation_id),
            )

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: OperationState) -> None:
        allowed = _ALLOWED.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(self.state.value, to_state.value, str(self.operation_id))
        self.state = to_state

    def refresh_risk(self) -> None:
        self.risk = OperationRiskAssessor.assess(list(self.steps.values()))

    @classmethod
    def create(
        cls,
        *,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        name: str,
        classification: OperationClassification,
        now: datetime,
        operation_id: OperationId | None = None,
    ) -> Operation:
        if not name.strip():
            raise InvalidArgument("name", "must not be empty")
        oid = operation_id or OperationId.generate()
        aggregate = cls(
            operation_id=oid,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            name=name.strip(),
            classification=classification,
            state=OperationState.PLANNING,
            risk=OperationRisk.LOW,
            steps={},
            dependencies=[],
            approvals=[],
            objectives=[],
            abort_reason=None,
            created_at=now,
            updated_at=now,
            version=0,
        )
        aggregate._emit(
            OperationCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(oid),
                aggregate_type="Operation",
                engagement_id=str(engagement_id),
                classification=classification.value,
                name=name.strip(),
            )
        )
        return aggregate

    def add_execution_step(
        self,
        *,
        tenant_id: TenantId,
        name: str,
        step_type: StepType,
        constraints: StepConstraints,
        now: datetime,
        technique_ref: StepTechniqueRef | None = None,
        target_ref: StepTargetRef | None = None,
        impact_ceiling: ImpactCeiling | None = None,
        modifies_persistent_state: bool = False,
        mitre_ref: MitreAttackRef | None = None,
        rate_limit: RateLimit | None = None,
        window: ExecutionWindowConstraint | None = None,
        description: str = "",
        step_id: ExecutionStepId | None = None,
    ) -> ExecutionStepId:
        self._assert_tenant(tenant_id)
        self._assert_planning()
        if not name.strip():
            raise InvalidArgument("name", "must not be empty")
        sid = step_id or ExecutionStepId.generate()
        step = ExecutionStep(
            step_id=sid,
            name=name.strip(),
            step_type=step_type,
            state=StepState.PENDING,
            constraints=constraints,
            technique_ref=technique_ref,
            target_ref=target_ref,
            impact_ceiling=impact_ceiling,
            modifies_persistent_state=modifies_persistent_state,
            mitre_ref=mitre_ref,
            rate_limit=rate_limit,
            window=window,
            output_ref=None,
            description=description,
        )
        self.steps[str(sid)] = step
        self.refresh_risk()
        self._mutate(now)
        self._emit(
            ExecutionStepAdded(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                step_id=str(sid),
                step_type=step_type.value,
            )
        )
        return sid

    def remove_execution_step(
        self,
        *,
        tenant_id: TenantId,
        step_id: ExecutionStepId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_planning()
        key = str(step_id)
        if key not in self.steps:
            raise InvalidArgument("step_id", f"step {step_id} not found")
        del self.steps[key]
        self.dependencies = [
            d
            for d in self.dependencies
            if str(d.from_step_id) != key and str(d.to_step_id) != key
        ]
        self.refresh_risk()
        self._mutate(now)
        self._emit(
            ExecutionStepRemoved(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                step_id=key,
            )
        )

    def _would_create_cycle(self, from_step_id: str, to_step_id: str) -> bool:
        """Return True if edge from→to introduces a cycle (to can reach from)."""
        adjacency: dict[str, list[str]] = {}
        for dep in self.dependencies:
            adjacency.setdefault(str(dep.from_step_id), []).append(str(dep.to_step_id))
        adjacency.setdefault(from_step_id, []).append(to_step_id)

        visited: set[str] = set()
        stack = [to_step_id]
        while stack:
            current = stack.pop()
            if current == from_step_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            stack.extend(adjacency.get(current, []))
        return False

    def add_dependency(
        self,
        *,
        tenant_id: TenantId,
        from_step_id: ExecutionStepId,
        to_step_id: ExecutionStepId,
        now: datetime,
        dependency_id: StepDependencyId | None = None,
    ) -> StepDependencyId:
        self._assert_tenant(tenant_id)
        self._assert_planning()
        from_key = str(from_step_id)
        to_key = str(to_step_id)
        if from_key == to_key:
            raise InvalidArgument("dependency", "step cannot depend on itself")
        if from_key not in self.steps or to_key not in self.steps:
            raise InvalidArgument("dependency", "both steps must exist in the plan")
        if self._would_create_cycle(from_key, to_key):
            raise CyclicDependencyError(from_key, to_key)
        did = dependency_id or StepDependencyId.generate()
        self.dependencies.append(
            StepDependency(
                dependency_id=did,
                from_step_id=from_step_id,
                to_step_id=to_step_id,
            )
        )
        self._mutate(now)
        return did

    def set_objectives(
        self,
        *,
        tenant_id: TenantId,
        objectives: list[tuple[str, str, bool]],
        now: datetime,
    ) -> None:
        """Replace objectives with (description, success_criteria, is_primary) tuples."""
        self._assert_tenant(tenant_id)
        self._assert_planning()
        if not objectives:
            raise InvalidArgument("objectives", "must not be empty")
        primary_count = sum(1 for _, _, is_primary in objectives if is_primary)
        if primary_count != 1:
            raise InvalidArgument("objectives", "exactly one primary objective required")
        self.objectives = [
            OperationObjective(
                objective_id=OperationObjectiveId.generate(),
                description=desc.strip(),
                success_criteria=criteria.strip(),
                is_primary=is_primary,
            )
            for desc, criteria, is_primary in objectives
        ]
        self._mutate(now)

    def submit_for_approval(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not self.steps:
            raise InvalidArgument("steps", "plan must contain at least one step")
        self.refresh_risk()
        self._transition(OperationState.PENDING_OPERATION_APPROVAL)
        self.approvals = []
        self._mutate(now)
        self._emit(
            OperationSubmittedForApproval(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                risk=self.risk.value,
            )
        )

    def approve(
        self,
        *,
        tenant_id: TenantId,
        operator_id: UUID,
        authority: str,
        signature: str,
        now: datetime,
    ) -> OperationApprovalId:
        self._assert_tenant(tenant_id)
        if self.state != OperationState.PENDING_OPERATION_APPROVAL:
            raise InvalidStateTransition(
                self.state.value,
                OperationState.APPROVED.value,
                str(self.operation_id),
            )
        if not authority.strip():
            raise InvalidArgument("authority", "must not be empty")
        if not signature.strip():
            raise InvalidArgument("signature", "must not be empty")
        if operator_id.int == 0:
            raise InvalidArgument("operator_id", "must not be nil UUID")

        if self.risk == OperationRisk.CRITICAL and authority.upper() != _CISO_AUTHORITY:
            raise ApprovalAuthorityInsufficient(_CISO_AUTHORITY, authority)

        if any(a.operator_id == operator_id for a in self.approvals):
            raise InvalidArgument("operator_id", "operator has already approved this operation")

        aid = OperationApprovalId.generate()
        self.approvals.append(
            OperationApproval(
                approval_id=aid,
                operator_id=operator_id,
                authority=authority.strip(),
                signature=signature.strip(),
                approved_at=now,
            )
        )

        fully_approved = True
        if self.risk == OperationRisk.CRITICAL:
            ciso_operators = {
                a.operator_id
                for a in self.approvals
                if a.authority.upper() == _CISO_AUTHORITY
            }
            fully_approved = len(ciso_operators) >= _CRITICAL_CISO_APPROVALS_REQUIRED

        if fully_approved:
            self._transition(OperationState.APPROVED)

        self._mutate(now)
        self._emit(
            OperationApproved(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                approval_id=str(aid),
                authority=authority.strip(),
                operator_id=str(operator_id),
                approval_count=len(self.approvals),
            )
        )
        return aid

    def queue(
        self,
        *,
        tenant_id: TenantId,
        engagement_is_active: bool,
        engagement_state: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not engagement_is_active:
            raise EngagementNotActive(str(self.engagement_id), engagement_state)
        self._transition(OperationState.QUEUED)
        self._mutate(now)
        self._emit(
            OperationQueued(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                engagement_id=str(self.engagement_id),
            )
        )

    def start(
        self,
        *,
        tenant_id: TenantId,
        engagement_is_active: bool,
        engagement_state: str,
        now: datetime,
    ) -> None:
        """Transition Queued → Running. No worker dispatch in Phase 2."""
        self._assert_tenant(tenant_id)
        if not engagement_is_active:
            raise EngagementNotActive(str(self.engagement_id), engagement_state)
        self._transition(OperationState.RUNNING)
        self._mutate(now)
        self._emit(
            OperationStarted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                engagement_id=str(self.engagement_id),
            )
        )

    def pause(self, *, tenant_id: TenantId, now: datetime, reason: str | None = None) -> None:
        self._assert_tenant(tenant_id)
        self._transition(OperationState.PAUSED)
        self._mutate(now)
        self._emit(
            OperationPaused(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                reason=reason,
            )
        )

    def resume(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(OperationState.RUNNING)
        self._mutate(now)
        self._emit(
            OperationResumed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
            )
        )

    def complete(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(OperationState.COMPLETED)
        self._mutate(now)
        self._emit(
            OperationCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
            )
        )

    def abort(
        self,
        *,
        tenant_id: TenantId,
        reason: str,
        aborting_authority: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("reason", "must not be empty")
        self._transition(OperationState.ABORTED)
        self.abort_reason = reason.strip()
        self._mutate(now)
        self._emit(
            OperationAborted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                reason=reason.strip(),
                aborting_authority=aborting_authority.strip(),
            )
        )

    def fail(self, *, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("reason", "must not be empty")
        self._transition(OperationState.FAILED)
        self.abort_reason = reason.strip()
        self._mutate(now)
        self._emit(
            OperationFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.operation_id),
                aggregate_type="Operation",
                reason=reason.strip(),
            )
        )
