"""Aggregates for the Gated Safe Active Validation bounded context (M11).

`ValidationExecution` is the aggregate root. `ValidationStep` is a child
entity owned by it (embedded in its `steps` list — steps never exist
independently of their execution). `ExecutionEvent` is a separate,
append-only, immutable log record: unlike `ValidationExecution`'s
in-memory domain events (collected via `collect_events()` and published
best-effort after commit, matching every other bounded context's
convention), `ExecutionEvent` rows are written to the database
IMMEDIATELY as each step of the process happens — that is the entire
point of "live progress": a concurrent poller must see them before the
whole execution finishes, not after. The application service
(`application/validation_execution/execution_service.py`) is the one
that constructs and persists `ExecutionEvent` rows directly; this
aggregate never buffers them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from redforge.domain.validation_execution.events import (
    ExecutionAuthorized,
    ExecutionCancelled,
    ExecutionCreated,
    ExecutionDenied,
    ExecutionFinished,
    ExecutionStarted,
    ValidationExecutionEvent,
    _now,
)
from redforge.domain.validation_execution.exceptions import (
    InvalidExecutionTransitionError,
    InvalidStepTransitionError,
)
from redforge.domain.validation_execution.value_objects import (
    TERMINAL_EXECUTION_STATUSES,
    ErrorCategory,
    ExecutionLimits,
    ExecutionStatus,
    ExecutionTrigger,
    StepSource,
    StepStatus,
    StepType,
    ValidationProfile,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from datetime import datetime


class ValidationStep:
    """One bounded validation step owned by a ValidationExecution.

    Steps are created PENDING, in a fixed order, as part of the
    execution's immutable plan snapshot (built once, at AUTHORIZED ->
    RUNNING). Their status only ever moves forward
    (PENDING -> RUNNING -> {COMPLETED, FAILED, TIMED_OUT, SKIPPED,
    CANCELLED}) — never backward, never re-run in place.
    """

    __slots__ = (
        "_adaptive_rule_id",
        "_adaptive_rule_version",
        "_completed_at",
        "_error_category",
        "_evidence",
        "_id",
        "_order",
        "_protocol_validation_state",
        "_source",
        "_source_fact_ref",
        "_started_at",
        "_status",
        "_step_type",
        "_validator_id",
        "_validator_version",
    )

    def __init__(
        self,
        id: EntityId,
        step_type: StepType,
        order: int,
        status: StepStatus,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        evidence: tuple[dict[str, str], ...] = (),
        error_category: ErrorCategory | None = None,
        source: StepSource = StepSource.INITIAL,
        adaptive_rule_id: str | None = None,
        adaptive_rule_version: int | None = None,
        source_fact_ref: str | None = None,
        validator_id: str | None = None,
        validator_version: int | None = None,
        protocol_validation_state: str | None = None,
    ) -> None:
        self._id = id
        self._step_type = step_type
        self._order = order
        self._status = status
        self._started_at = started_at
        self._completed_at = completed_at
        self._evidence = evidence
        self._error_category = error_category
        self._source = source
        self._adaptive_rule_id = adaptive_rule_id
        self._adaptive_rule_version = adaptive_rule_version
        self._source_fact_ref = source_fact_ref
        # M13 — which ProtocolValidator (if any) produced this step's
        # outcome, and what state it reached. Set at complete()/fail()
        # time (when the outcome is actually known), unlike
        # adaptive_rule_id/version which are set at creation time (why
        # the step was scheduled) — this is what happened when it ran.
        self._validator_id = validator_id
        self._validator_version = validator_version
        self._protocol_validation_state = protocol_validation_state

    @classmethod
    def create(cls, step_type: StepType, order: int) -> Self:
        return cls(
            id=EntityId.generate(), step_type=step_type, order=order, status=StepStatus.PENDING,
        )

    @classmethod
    def create_adaptive(
        cls,
        step_type: StepType,
        order: int,
        rule_id: str,
        rule_version: int,
        fact_ref: str,
    ) -> Self:
        """An adaptive step appended mid-execution by the deterministic
        adaptive rule registry (M12) — never client-submitted, never
        LLM-planned. Provenance (which rule, which version, which
        observed fact) is persisted so an operator can audit exactly
        why this step exists."""
        return cls(
            id=EntityId.generate(), step_type=step_type, order=order, status=StepStatus.PENDING,
            source=StepSource.ADAPTIVE, adaptive_rule_id=rule_id,
            adaptive_rule_version=rule_version, source_fact_ref=fact_ref,
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def step_type(self) -> StepType:
        return self._step_type

    @property
    def order(self) -> int:
        return self._order

    @property
    def status(self) -> StepStatus:
        return self._status

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def completed_at(self) -> datetime | None:
        return self._completed_at

    @property
    def evidence(self) -> tuple[dict[str, str], ...]:
        return self._evidence

    @property
    def error_category(self) -> ErrorCategory | None:
        return self._error_category

    @property
    def source(self) -> StepSource:
        return self._source

    @property
    def adaptive_rule_id(self) -> str | None:
        return self._adaptive_rule_id

    @property
    def adaptive_rule_version(self) -> int | None:
        return self._adaptive_rule_version

    @property
    def source_fact_ref(self) -> str | None:
        return self._source_fact_ref

    @property
    def validator_id(self) -> str | None:
        return self._validator_id

    @property
    def validator_version(self) -> int | None:
        return self._validator_version

    @property
    def protocol_validation_state(self) -> str | None:
        return self._protocol_validation_state

    def start(self, now: datetime) -> None:
        if self._status != StepStatus.PENDING:
            raise InvalidStepTransitionError(str(self._status), "running")
        self._status = StepStatus.RUNNING
        self._started_at = now

    def complete(
        self,
        now: datetime,
        evidence: tuple[dict[str, str], ...],
        validator_id: str | None = None,
        validator_version: int | None = None,
        protocol_validation_state: str | None = None,
    ) -> None:
        if self._status != StepStatus.RUNNING:
            raise InvalidStepTransitionError(str(self._status), "completed")
        self._status = StepStatus.COMPLETED
        self._completed_at = now
        self._evidence = evidence
        if validator_id is not None:
            self._validator_id = validator_id
            self._validator_version = validator_version
            self._protocol_validation_state = protocol_validation_state

    def fail(
        self,
        now: datetime,
        error_category: ErrorCategory,
        evidence: tuple[dict[str, str], ...] = (),
        validator_id: str | None = None,
        validator_version: int | None = None,
        protocol_validation_state: str | None = None,
    ) -> None:
        if self._status != StepStatus.RUNNING:
            raise InvalidStepTransitionError(str(self._status), "failed")
        self._status = StepStatus.FAILED
        self._completed_at = now
        self._error_category = error_category
        self._evidence = evidence
        if validator_id is not None:
            self._validator_id = validator_id
            self._validator_version = validator_version
            self._protocol_validation_state = protocol_validation_state

    def timeout(self, now: datetime) -> None:
        if self._status != StepStatus.RUNNING:
            raise InvalidStepTransitionError(str(self._status), "timed_out")
        self._status = StepStatus.TIMED_OUT
        self._completed_at = now
        self._error_category = ErrorCategory.TIMEOUT

    def skip(self) -> None:
        if self._status != StepStatus.PENDING:
            raise InvalidStepTransitionError(str(self._status), "skipped")
        self._status = StepStatus.SKIPPED

    def cancel(self) -> None:
        if self._status != StepStatus.PENDING:
            raise InvalidStepTransitionError(str(self._status), "cancelled")
        self._status = StepStatus.CANCELLED

    def __repr__(self) -> str:
        return f"ValidationStep(id={self._id}, type={self._step_type}, status={self._status})"


class ValidationExecution:
    """ValidationExecution aggregate root.

    Invariants:
    - Always tenant-owned (organization_id never changes).
    - A DENIED execution never has any step leave PENDING — no network
      activity is ever scheduled for it (enforced structurally: only
      `authorize()` -> `start()` can build/run steps; `deny()` is
      reachable only from POLICY_CHECKING and is terminal).
    - A CANCELLED execution's `cancellation_requested` flag, once set,
      prevents any further PENDING step from starting — already-RUNNING
      steps are allowed to finish and their true result recorded.
    - Completion status is computed from the real step statuses, never
      asserted independently of them.
    """

    __slots__ = (
        "_cancellation_requested",
        "_completed_at",
        "_continuous_policy_id",
        "_events",
        "_failure_reason",
        "_id",
        "_limits",
        "_organization_id",
        "_policy_decision_id",
        "_policy_reason_code",
        "_profile",
        "_requester_user_id",
        "_scheduled_due_at",
        "_started_at",
        "_status",
        "_steps",
        "_target_id",
        "_timestamps",
        "_trigger",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_id: EntityId,
        requester_user_id: EntityId,
        profile: ValidationProfile,
        status: ExecutionStatus,
        limits: ExecutionLimits,
        timestamps: AuditTimestamps,
        steps: list[ValidationStep] | None = None,
        policy_decision_id: str | None = None,
        policy_reason_code: str | None = None,
        cancellation_requested: bool = False,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        failure_reason: str = "",
        trigger: ExecutionTrigger = ExecutionTrigger.MANUAL,
        continuous_policy_id: EntityId | None = None,
        scheduled_due_at: datetime | None = None,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._target_id = target_id
        self._requester_user_id = requester_user_id
        self._profile = profile
        self._status = status
        self._limits = limits
        self._timestamps = timestamps
        self._steps = steps or []
        self._policy_decision_id = policy_decision_id
        self._policy_reason_code = policy_reason_code
        self._cancellation_requested = cancellation_requested
        self._started_at = started_at
        self._completed_at = completed_at
        self._failure_reason = failure_reason
        # M14 — closed, server-assigned provenance. Never mutated after
        # creation; a client can never set or forge any of these three.
        self._trigger = trigger
        self._continuous_policy_id = continuous_policy_id
        self._scheduled_due_at = scheduled_due_at
        self._events: list[ValidationExecutionEvent] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        target_id: EntityId,
        requester_user_id: EntityId,
        profile: ValidationProfile = ValidationProfile.SAFE_ACTIVE_BASELINE_V1,
        trigger: ExecutionTrigger = ExecutionTrigger.MANUAL,
        continuous_policy_id: EntityId | None = None,
        scheduled_due_at: datetime | None = None,
    ) -> Self:
        execution = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            target_id=target_id,
            requester_user_id=requester_user_id,
            profile=profile,
            status=ExecutionStatus.PENDING,
            limits=ExecutionLimits.default_for(profile),
            timestamps=AuditTimestamps.create(),
            trigger=trigger,
            continuous_policy_id=continuous_policy_id,
            scheduled_due_at=scheduled_due_at,
        )
        execution._record_event(
            ExecutionCreated(
                occurred_at=_now(),
                execution_id=str(execution._id),
                organization_id=str(organization_id),
                target_id=str(target_id),
            )
        )
        return execution

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def requester_user_id(self) -> EntityId:
        return self._requester_user_id

    @property
    def profile(self) -> ValidationProfile:
        return self._profile

    @property
    def status(self) -> ExecutionStatus:
        return self._status

    @property
    def limits(self) -> ExecutionLimits:
        return self._limits

    @property
    def steps(self) -> tuple[ValidationStep, ...]:
        return tuple(self._steps)

    @property
    def policy_decision_id(self) -> str | None:
        return self._policy_decision_id

    @property
    def policy_reason_code(self) -> str | None:
        return self._policy_reason_code

    @property
    def cancellation_requested(self) -> bool:
        return self._cancellation_requested

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def completed_at(self) -> datetime | None:
        return self._completed_at

    @property
    def failure_reason(self) -> str:
        return self._failure_reason

    @property
    def trigger(self) -> ExecutionTrigger:
        return self._trigger

    @property
    def continuous_policy_id(self) -> EntityId | None:
        return self._continuous_policy_id

    @property
    def scheduled_due_at(self) -> datetime | None:
        return self._scheduled_due_at

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_terminal(self) -> bool:
        return self._status in TERMINAL_EXECUTION_STATUSES

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def begin_policy_check(self) -> None:
        if self._status != ExecutionStatus.PENDING:
            raise InvalidExecutionTransitionError(str(self._status), "policy_checking")
        self._status = ExecutionStatus.POLICY_CHECKING
        self._touch()

    def authorize(self, policy_decision_id: str) -> None:
        if self._status != ExecutionStatus.POLICY_CHECKING:
            raise InvalidExecutionTransitionError(str(self._status), "authorized")
        self._status = ExecutionStatus.AUTHORIZED
        self._policy_decision_id = policy_decision_id
        self._touch()
        self._record_event(
            ExecutionAuthorized(
                occurred_at=_now(), execution_id=str(self._id),
                organization_id=str(self._organization_id), policy_decision_id=policy_decision_id,
            )
        )

    def deny(self, policy_decision_id: str, reason_code: str) -> None:
        """{PENDING, POLICY_CHECKING, AUTHORIZED} -> DENIED. Terminal.

        AUTHORIZED is a legal source status specifically for the
        mandatory SECOND time-of-use policy check performed immediately
        before step dispatch (see
        application/validation_execution/execution_service.py): an
        authorization can be revoked or expire in the window between
        the initial ALLOW and actual dispatch, and that must still
        block all network activity — no step is ever created for an
        execution denied from any of these three statuses.
        """
        if self._status not in (
            ExecutionStatus.PENDING, ExecutionStatus.POLICY_CHECKING, ExecutionStatus.AUTHORIZED,
        ):
            raise InvalidExecutionTransitionError(str(self._status), "denied")
        self._status = ExecutionStatus.DENIED
        self._policy_decision_id = policy_decision_id
        self._policy_reason_code = reason_code
        self._completed_at = _now()
        self._touch()
        self._record_event(
            ExecutionDenied(
                occurred_at=_now(), execution_id=str(self._id),
                organization_id=str(self._organization_id), reason_code=reason_code,
            )
        )

    def fail_preflight(self, reason: str) -> None:
        """AUTHORIZED -> FAILED, directly, with zero steps. Used only
        when the plan itself cannot even be built (e.g. the canonical
        target's endpoint fails normalization) — distinct from
        `finish()`'s post-run, step-status-driven computation."""
        if self._status != ExecutionStatus.AUTHORIZED:
            raise InvalidExecutionTransitionError(str(self._status), "failed")
        self._status = ExecutionStatus.FAILED
        self._failure_reason = reason
        self._completed_at = _now()
        self._touch()
        self._record_event(
            ExecutionFinished(
                occurred_at=_now(), execution_id=str(self._id),
                organization_id=str(self._organization_id), status=str(ExecutionStatus.FAILED),
            )
        )

    def build_plan(self, step_types: list[StepType]) -> None:
        """Build the immutable step-plan snapshot. Only legal from
        AUTHORIZED, before RUNNING starts. `step_types` is server-built
        (see application/validation_execution/step_planner.py) — never
        client-supplied."""
        if self._status != ExecutionStatus.AUTHORIZED:
            raise InvalidExecutionTransitionError(str(self._status), "plan_created")
        if len(step_types) > self._limits.max_steps:
            step_types = step_types[: self._limits.max_steps]
        self._steps = [ValidationStep.create(st, i) for i, st in enumerate(step_types)]
        self._touch()

    def append_adaptive_step(
        self, step_type: StepType, rule_id: str, rule_version: int, fact_ref: str,
    ) -> ValidationStep | None:
        """Append one adaptively-planned step while RUNNING. Returns
        None (a documented no-op, never an error) when:
          - a step of this exact (step_type, rule_id) already exists —
            duplicate-fact-resistant, so re-observing the same port
            reachability twice never appends the step twice;
          - the hard `max_steps` or `max_adaptive_steps` bound would be
            exceeded — plan expansion always has a hard ceiling.
        Only legal while RUNNING: adaptive expansion is a mid-execution
        concern, never part of the initial plan snapshot."""
        if self._status != ExecutionStatus.RUNNING:
            raise InvalidExecutionTransitionError(str(self._status), "adaptive_step_added")

        already_present = any(
            s.step_type == step_type and s.adaptive_rule_id == rule_id for s in self._steps
        )
        if already_present:
            return None

        adaptive_count = sum(1 for s in self._steps if s.source == StepSource.ADAPTIVE)
        if (
            len(self._steps) >= self._limits.max_steps
            or adaptive_count >= self._limits.max_adaptive_steps
        ):
            return None

        step = ValidationStep.create_adaptive(
            step_type=step_type, order=len(self._steps), rule_id=rule_id,
            rule_version=rule_version, fact_ref=fact_ref,
        )
        self._steps.append(step)
        self._touch()
        return step

    def start(self) -> None:
        if self._status != ExecutionStatus.AUTHORIZED:
            raise InvalidExecutionTransitionError(str(self._status), "running")
        self._status = ExecutionStatus.RUNNING
        self._started_at = _now()
        self._touch()
        self._record_event(
            ExecutionStarted(
                occurred_at=_now(), execution_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def request_cancellation(self) -> None:
        """Idempotent. Legal for any non-terminal status. Does not
        itself transition status — the running loop observes this flag
        between steps and is the one that calls `cancel()`."""
        if self.is_terminal:
            raise InvalidExecutionTransitionError(str(self._status), "cancellation_requested")
        self._cancellation_requested = True
        self._touch()

    def cancel(self) -> None:
        if self.is_terminal:
            raise InvalidExecutionTransitionError(str(self._status), "cancelled")
        for step in self._steps:
            if step.status == StepStatus.PENDING:
                step.cancel()
        self._status = ExecutionStatus.CANCELLED
        self._completed_at = _now()
        self._touch()
        self._record_event(
            ExecutionCancelled(
                occurred_at=_now(), execution_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def finish(self) -> ExecutionStatus:
        """RUNNING -> {COMPLETED, PARTIALLY_COMPLETED, FAILED}, computed
        truthfully from the real step statuses — never asserted
        independently. Returns the resulting status."""
        if self._status != ExecutionStatus.RUNNING:
            raise InvalidExecutionTransitionError(str(self._status), "completed")

        completed = [s for s in self._steps if s.status == StepStatus.COMPLETED]
        failed = [
            s for s in self._steps
            if s.status in (StepStatus.FAILED, StepStatus.TIMED_OUT)
        ]

        if failed and not completed:
            final = ExecutionStatus.FAILED
            categories = sorted({str(s.error_category) for s in failed if s.error_category})
            self._failure_reason = (
                f"All {len(failed)} step(s) failed ({', '.join(categories) or 'unknown'})"
            )
        elif failed:
            final = ExecutionStatus.PARTIALLY_COMPLETED
        else:
            final = ExecutionStatus.COMPLETED

        self._status = final
        self._completed_at = _now()
        self._touch()
        self._record_event(
            ExecutionFinished(
                occurred_at=_now(), execution_id=str(self._id),
                organization_id=str(self._organization_id), status=str(final),
            )
        )
        return final

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[ValidationExecutionEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: ValidationExecutionEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ValidationExecution):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"ValidationExecution(id={self._id}, org={self._organization_id}, "
            f"status={self._status}, steps={len(self._steps)})"
        )
