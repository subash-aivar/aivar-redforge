"""ConversationSession aggregate root.

A ConversationSession represents one adaptive multi-turn attack dialogue
against an AI target. It is NOT a ValidationRun — it spans N turns with
adaptive decision-making between them.

Invariants:
- Always belongs to an Organization and targets an AI Target.
- Status transitions: PENDING → RUNNING → {COMPLETED, FAILED, CANCELLED, EXHAUSTED}
- turns is append-only; each ConversationTurn is immutable.
- Budget accounting is checked externally (ConversationEngine) and enforced
  here by exhaust_budget() — the session never exceeds its budget silently.
- Terminal states (COMPLETED, FAILED, CANCELLED, EXHAUSTED) are immutable.
- metrics is only set at completion (complete() or exhaust_budget()).
- outcome is only set at completion.

Sibling relationship to ValidationRun:
- ValidationRun: single-target, single-step execution aggregate.
- ConversationSession: single-target, multi-turn, adaptive aggregate.
- A CampaignRun may spawn both types depending on its strategy.

Domain layer — imports only redforge.domain.*, redforge.shared.*,
redforge.core.exceptions (ADR-0001).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.conversations.events import (
    ConversationBudgetExhausted,
    ConversationEvent,
    ConversationSessionCancelled,
    ConversationSessionCompleted,
    ConversationSessionCreated,
    ConversationSessionFailed,
    ConversationSessionStarted,
    ConversationTurnRecorded,
)
from redforge.domain.conversations.exceptions import (
    ConversationAlreadyTerminalError,
    ConversationNotRunningError,
    EmptyConversationError,
    InvalidConversationTransitionError,
)
from redforge.domain.conversations.value_objects import (
    ConversationBudget,
    ConversationMetrics,
    ConversationOutcome,
    ConversationStatus,
    ConversationStrategyType,
    ConversationTurn,
    DecisionAction,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps, utc_now

if TYPE_CHECKING:
    from datetime import datetime

_TERMINAL = frozenset({
    ConversationStatus.COMPLETED,
    ConversationStatus.FAILED,
    ConversationStatus.CANCELLED,
    ConversationStatus.EXHAUSTED,
})


class ConversationSession:
    """ConversationSession aggregate root.

    The domain layer records what happened (turns, decisions, outcomes).
    The application layer (ConversationEngine) drives the adaptive loop.
    """

    __slots__ = (
        "_attack_category",
        "_budget",
        "_campaign_id",
        "_completed_at",
        "_events",
        "_failure_reason",
        "_id",
        "_metadata",
        "_metrics",
        "_organization_id",
        "_outcome",
        "_policy_id",
        "_started_at",
        "_status",
        "_strategy_type",
        "_target_id",
        "_timestamps",
        "_turns",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_id: EntityId,
        strategy_type: ConversationStrategyType,
        attack_category: str,
        budget: ConversationBudget,
        status: ConversationStatus,
        turns: tuple[ConversationTurn, ...],
        outcome: ConversationOutcome | None,
        metrics: ConversationMetrics | None,
        policy_id: EntityId | None,
        campaign_id: EntityId | None,
        started_at: datetime | None,
        completed_at: datetime | None,
        failure_reason: str | None,
        metadata: dict[str, str],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._target_id = target_id
        self._strategy_type = strategy_type
        self._attack_category = attack_category
        self._budget = budget
        self._status = status
        self._turns = turns
        self._outcome = outcome
        self._metrics = metrics
        self._policy_id = policy_id
        self._campaign_id = campaign_id
        self._started_at = started_at
        self._completed_at = completed_at
        self._failure_reason = failure_reason
        self._metadata = metadata
        self._timestamps = timestamps
        self._events: list[ConversationEvent] = []

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        target_id: EntityId,
        strategy_type: ConversationStrategyType,
        attack_category: str,
        budget: ConversationBudget | None = None,
        policy_id: EntityId | None = None,
        campaign_id: EntityId | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ConversationSession:
        if not attack_category:
            from redforge.core.exceptions import ValidationError
            raise ValidationError("attack_category must not be empty")

        session_id = EntityId.generate()
        effective_budget = budget or ConversationBudget()

        session = cls(
            id=session_id,
            organization_id=organization_id,
            target_id=target_id,
            strategy_type=strategy_type,
            attack_category=attack_category,
            budget=effective_budget,
            status=ConversationStatus.PENDING,
            turns=(),
            outcome=None,
            metrics=None,
            policy_id=policy_id,
            campaign_id=campaign_id,
            started_at=None,
            completed_at=None,
            failure_reason=None,
            metadata=metadata or {},
            timestamps=AuditTimestamps.create(),
        )
        session._events.append(ConversationSessionCreated(
            session_id=str(session_id),
            organization_id=str(organization_id),
            strategy_type=strategy_type.value,
            attack_category=attack_category,
            max_turns=effective_budget.max_turns,
        ))
        return session

    # ── Properties ────────────────────────────────────────────────────────────

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
    def strategy_type(self) -> ConversationStrategyType:
        return self._strategy_type

    @property
    def attack_category(self) -> str:
        return self._attack_category

    @property
    def budget(self) -> ConversationBudget:
        return self._budget

    @property
    def status(self) -> ConversationStatus:
        return self._status

    @property
    def turns(self) -> tuple[ConversationTurn, ...]:
        return self._turns

    @property
    def turn_count(self) -> int:
        return len(self._turns)

    @property
    def outcome(self) -> ConversationOutcome | None:
        return self._outcome

    @property
    def metrics(self) -> ConversationMetrics | None:
        return self._metrics

    @property
    def policy_id(self) -> EntityId | None:
        return self._policy_id

    @property
    def campaign_id(self) -> EntityId | None:
        return self._campaign_id

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def completed_at(self) -> datetime | None:
        return self._completed_at

    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_terminal(self) -> bool:
        return self._status in _TERMINAL

    @property
    def is_running(self) -> bool:
        return self._status == ConversationStatus.RUNNING

    @property
    def budget_remaining_turns(self) -> int:
        return max(0, self._budget.max_turns - len(self._turns))

    @property
    def total_estimated_tokens(self) -> int:
        return sum(t.estimated_tokens for t in self._turns)

    # ── Lifecycle transitions ─────────────────────────────────────────────────

    def start(self) -> None:
        """PENDING → RUNNING."""
        if self._status != ConversationStatus.PENDING:
            raise InvalidConversationTransitionError(self._status.value, "running")
        self._status = ConversationStatus.RUNNING
        self._started_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(ConversationSessionStarted(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
        ))

    def record_turn(self, turn: ConversationTurn) -> None:
        """Append a completed turn. Only valid when RUNNING."""
        if self._status != ConversationStatus.RUNNING:
            raise ConversationNotRunningError(str(self._id), self._status.value)
        if turn.turn_number != len(self._turns) + 1:
            from redforge.core.exceptions import ValidationError
            raise ValidationError(
                f"Expected turn_number {len(self._turns) + 1}, got {turn.turn_number}"
            )
        self._turns = (*self._turns, turn)
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(ConversationTurnRecorded(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            turn_number=turn.turn_number,
            decision=turn.decision,
            evaluation_outcome=turn.evaluation_outcome,
        ))

    def complete(self, outcome: ConversationOutcome) -> None:
        """RUNNING → COMPLETED. Requires at least one turn."""
        if self.is_terminal:
            raise ConversationAlreadyTerminalError(str(self._id), self._status.value)
        if self._status != ConversationStatus.RUNNING:
            raise InvalidConversationTransitionError(self._status.value, "completed")
        if not self._turns:
            raise EmptyConversationError(str(self._id))
        self._status = ConversationStatus.COMPLETED
        self._outcome = outcome
        self._metrics = _compute_metrics(self._turns)
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(ConversationSessionCompleted(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            outcome=outcome.value,
            total_turns=len(self._turns),
            success_rate=self._metrics.success_rate,
        ))

    def exhaust_budget(self, exhaustion_reason: str) -> None:
        """RUNNING → EXHAUSTED when budget is hit."""
        if self.is_terminal:
            raise ConversationAlreadyTerminalError(str(self._id), self._status.value)
        if self._status != ConversationStatus.RUNNING:
            raise InvalidConversationTransitionError(self._status.value, "exhausted")
        self._status = ConversationStatus.EXHAUSTED
        self._outcome = ConversationOutcome.EXHAUSTED
        self._metrics = _compute_metrics(self._turns) if self._turns else None
        self._completed_at = utc_now()
        self._failure_reason = exhaustion_reason
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(ConversationBudgetExhausted(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            exhaustion_reason=exhaustion_reason,
            turns_completed=len(self._turns),
        ))

    def fail(self, reason: str) -> None:
        """RUNNING | PENDING → FAILED on unhandled error."""
        if self.is_terminal:
            raise ConversationAlreadyTerminalError(str(self._id), self._status.value)
        self._status = ConversationStatus.FAILED
        self._failure_reason = reason
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(ConversationSessionFailed(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            reason=reason,
        ))

    def cancel(self, reason: str = "") -> None:
        """Any non-terminal → CANCELLED."""
        if self.is_terminal:
            raise ConversationAlreadyTerminalError(str(self._id), self._status.value)
        self._status = ConversationStatus.CANCELLED
        self._failure_reason = reason or "cancelled"
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(ConversationSessionCancelled(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            reason=self._failure_reason,
        ))

    # ── Event collection ──────────────────────────────────────────────────────

    def collect_events(self) -> list[ConversationEvent]:
        events, self._events = self._events, []
        return events

    # ── Equality ──────────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConversationSession):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"ConversationSession(id={self._id!s}, "
            f"strategy={self._strategy_type.value}, "
            f"status={self._status.value}, "
            f"turns={len(self._turns)}/{self._budget.max_turns})"
        )


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _compute_metrics(turns: tuple[ConversationTurn, ...]) -> ConversationMetrics:
    """Compute ConversationMetrics from a completed turns tuple."""
    successful = sum(
        1 for t in turns
        if t.evaluation_outcome in {
            ConversationOutcome.SUCCESS.value,
            "success",
            DecisionAction.TERMINATE_SUCCESS.value,
        }
    )
    failed = sum(
        1 for t in turns
        if t.evaluation_outcome in {
            ConversationOutcome.FAILURE.value,
            "failure",
            DecisionAction.TERMINATE_FAILURE.value,
        }
    )
    errors = sum(1 for t in turns if t.is_error)
    escalations = sum(1 for t in turns if t.decision == DecisionAction.ESCALATE.value)
    pivots = sum(1 for t in turns if t.decision == DecisionAction.PIVOT.value)
    retries = sum(1 for t in turns if t.decision == DecisionAction.RETRY.value)
    total_tokens = sum(t.estimated_tokens for t in turns)
    total_ms = sum(t.duration_ms for t in turns)

    return ConversationMetrics(
        total_turns=len(turns),
        successful_turns=successful,
        failed_turns=failed,
        error_turns=errors,
        escalation_count=escalations,
        pivot_count=pivots,
        retry_count=retries,
        total_estimated_tokens=total_tokens,
        total_duration_ms=total_ms,
    )
