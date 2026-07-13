"""Unit tests for ConversationSession aggregate root (Sprint 18)."""

from __future__ import annotations

import pytest

from redforge.domain.conversations.entity import ConversationSession
from redforge.domain.conversations.events import (
    ConversationBudgetExhausted,
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
    ConversationOutcome,
    ConversationStatus,
    ConversationStrategyType,
    ConversationTurn,
    DecisionAction,
)
from redforge.shared.identifiers import EntityId

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _org() -> EntityId:
    return EntityId.generate()


def _target() -> EntityId:
    return EntityId.generate()


def _make_session(
    strategy: ConversationStrategyType = ConversationStrategyType.PROGRESSIVE_ESCALATION,
    budget: ConversationBudget | None = None,
) -> ConversationSession:
    return ConversationSession.create(
        organization_id=_org(),
        target_id=_target(),
        strategy_type=strategy,
        attack_category="prompt_injection",
        budget=budget,
    )


def _make_turn(
    turn_number: int = 1,
    decision: str = DecisionAction.CONTINUE.value,
    evaluation_outcome: str = "inconclusive",
    error: str | None = None,
) -> ConversationTurn:
    return ConversationTurn(
        turn_number=turn_number,
        attack_payload=f"attack payload {turn_number}",
        assistant_response=None if error else f"assistant response {turn_number}",
        evaluation_outcome=evaluation_outcome,
        decision=decision,
        turn_started_at=None,
        turn_completed_at=None,
        estimated_tokens=100,
        error=error,
    )


# ─── Factory ──────────────────────────────────────────────────────────────────


class TestConversationSessionCreate:
    def test_creates_with_pending_status(self) -> None:
        s = _make_session()
        assert s.status == ConversationStatus.PENDING

    def test_uses_default_budget_when_none_provided(self) -> None:
        s = _make_session()
        default = ConversationBudget()
        assert s.budget.max_turns == default.max_turns

    def test_uses_custom_budget(self) -> None:
        budget = ConversationBudget(max_turns=3)
        s = _make_session(budget=budget)
        assert s.budget.max_turns == 3

    def test_has_no_turns_at_creation(self) -> None:
        s = _make_session()
        assert s.turns == ()
        assert s.turn_count == 0

    def test_emits_created_event(self) -> None:
        s = _make_session()
        events = s.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], ConversationSessionCreated)

    def test_rejects_empty_attack_category(self) -> None:
        from redforge.core.exceptions import ValidationError
        with pytest.raises(ValidationError):
            ConversationSession.create(
                organization_id=_org(),
                target_id=_target(),
                strategy_type=ConversationStrategyType.SINGLE_TURN,
                attack_category="",
            )

    def test_collect_events_drains(self) -> None:
        s = _make_session()
        s.collect_events()
        assert s.collect_events() == []


# ─── Lifecycle ────────────────────────────────────────────────────────────────


class TestConversationSessionLifecycle:
    def test_start_transitions_to_running(self) -> None:
        s = _make_session()
        s.start()
        assert s.status == ConversationStatus.RUNNING
        assert s.started_at is not None

    def test_start_emits_started_event(self) -> None:
        s = _make_session()
        s.collect_events()
        s.start()
        events = s.collect_events()
        assert any(isinstance(e, ConversationSessionStarted) for e in events)

    def test_cannot_start_non_pending(self) -> None:
        s = _make_session()
        s.start()
        with pytest.raises(InvalidConversationTransitionError):
            s.start()

    def test_complete_transitions_to_completed(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn())
        s.complete(ConversationOutcome.SUCCESS)
        assert s.status == ConversationStatus.COMPLETED
        assert s.outcome == ConversationOutcome.SUCCESS

    def test_complete_without_turns_raises(self) -> None:
        s = _make_session()
        s.start()
        with pytest.raises(EmptyConversationError):
            s.complete(ConversationOutcome.FAILURE)

    def test_exhaust_budget_transitions_to_exhausted(self) -> None:
        s = _make_session()
        s.start()
        s.exhaust_budget("max_turns reached")
        assert s.status == ConversationStatus.EXHAUSTED
        assert s.outcome == ConversationOutcome.EXHAUSTED
        assert s.failure_reason == "max_turns reached"

    def test_fail_transitions_to_failed(self) -> None:
        s = _make_session()
        s.start()
        s.fail("unexpected error")
        assert s.status == ConversationStatus.FAILED
        assert s.failure_reason == "unexpected error"

    def test_cancel_transitions_to_cancelled(self) -> None:
        s = _make_session()
        s.start()
        s.cancel("user cancelled")
        assert s.status == ConversationStatus.CANCELLED

    def test_cannot_transition_from_terminal(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn())
        s.complete(ConversationOutcome.SUCCESS)
        with pytest.raises(ConversationAlreadyTerminalError):
            s.fail("oops")

    def test_is_terminal_after_complete(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn())
        s.complete(ConversationOutcome.FAILURE)
        assert s.is_terminal is True

    def test_is_running_only_when_running(self) -> None:
        s = _make_session()
        assert s.is_running is False
        s.start()
        assert s.is_running is True


# ─── Turn recording ───────────────────────────────────────────────────────────


class TestConversationTurnRecording:
    def test_record_turn_appends(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn(1))
        assert s.turn_count == 1

    def test_turn_number_must_be_sequential(self) -> None:
        from redforge.core.exceptions import ValidationError
        s = _make_session()
        s.start()
        with pytest.raises(ValidationError):
            s.record_turn(_make_turn(turn_number=2))

    def test_cannot_record_on_non_running(self) -> None:
        s = _make_session()
        with pytest.raises(ConversationNotRunningError):
            s.record_turn(_make_turn())

    def test_multiple_turns(self) -> None:
        s = _make_session()
        s.start()
        for i in range(1, 5):
            s.record_turn(_make_turn(i))
        assert s.turn_count == 4

    def test_emits_turn_recorded_event(self) -> None:
        s = _make_session()
        s.start()
        s.collect_events()
        s.record_turn(_make_turn())
        events = s.collect_events()
        assert any(isinstance(e, ConversationTurnRecorded) for e in events)

    def test_turns_are_immutable_tuple(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn(1))
        turns = s.turns
        assert isinstance(turns, tuple)
        # Verify original not modified by adding another turn
        s.record_turn(_make_turn(2))
        assert len(turns) == 1
        assert len(s.turns) == 2


# ─── Budget ───────────────────────────────────────────────────────────────────


class TestConversationSessionBudget:
    def test_budget_remaining_decrements(self) -> None:
        budget = ConversationBudget(max_turns=3)
        s = _make_session(budget=budget)
        s.start()
        assert s.budget_remaining_turns == 3
        s.record_turn(_make_turn(1))
        assert s.budget_remaining_turns == 2

    def test_total_estimated_tokens(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn(1))
        s.record_turn(_make_turn(2))
        assert s.total_estimated_tokens == 200  # 100 per turn


# ─── Metrics ──────────────────────────────────────────────────────────────────


class TestConversationMetrics:
    def test_metrics_populated_on_complete(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn(1, decision=DecisionAction.ESCALATE.value))
        s.record_turn(_make_turn(2, decision=DecisionAction.PIVOT.value))
        s.complete(ConversationOutcome.PARTIAL)
        assert s.metrics is not None
        assert s.metrics.total_turns == 2
        assert s.metrics.escalation_count == 1
        assert s.metrics.pivot_count == 1

    def test_metrics_none_before_completion(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn())
        assert s.metrics is None

    def test_success_rate_with_mix(self) -> None:
        s = _make_session()
        s.start()
        s.record_turn(_make_turn(1, evaluation_outcome="success"))
        s.record_turn(_make_turn(2, evaluation_outcome="failure"))
        s.complete(ConversationOutcome.PARTIAL)
        assert s.metrics is not None
        assert s.metrics.success_rate == pytest.approx(0.5, abs=0.01)


# ─── Events ───────────────────────────────────────────────────────────────────


class TestConversationEvents:
    def test_complete_emits_completed_event(self) -> None:
        s = _make_session()
        s.start()
        s.collect_events()
        s.record_turn(_make_turn())
        s.collect_events()
        s.complete(ConversationOutcome.SUCCESS)
        events = s.collect_events()
        completed = [e for e in events if isinstance(e, ConversationSessionCompleted)]
        assert len(completed) == 1
        assert completed[0].outcome == "success"

    def test_exhaust_emits_budget_exhausted_event(self) -> None:
        s = _make_session()
        s.start()
        s.collect_events()
        s.exhaust_budget("max_turns=10 reached")
        events = s.collect_events()
        exhausted = [e for e in events if isinstance(e, ConversationBudgetExhausted)]
        assert len(exhausted) == 1
        assert "max_turns" in exhausted[0].exhaustion_reason

    def test_fail_emits_failed_event(self) -> None:
        s = _make_session()
        s.start()
        s.collect_events()
        s.fail("crash")
        events = s.collect_events()
        failed = [e for e in events if isinstance(e, ConversationSessionFailed)]
        assert len(failed) == 1
        assert failed[0].reason == "crash"

    def test_cancel_emits_cancelled_event(self) -> None:
        s = _make_session()
        s.start()
        s.collect_events()
        s.cancel("user request")
        events = s.collect_events()
        cancelled = [e for e in events if isinstance(e, ConversationSessionCancelled)]
        assert len(cancelled) == 1


# ─── ConversationTurn ─────────────────────────────────────────────────────────


class TestConversationTurn:
    def test_is_error_when_error_set(self) -> None:
        t = _make_turn(error="network failure")
        assert t.is_error is True

    def test_is_not_error_when_no_error(self) -> None:
        t = _make_turn()
        assert t.is_error is False

    def test_duration_ms_is_zero_without_timestamps(self) -> None:
        t = _make_turn()
        assert t.duration_ms == 0
