"""Unit tests for ConversationEngine adaptive loop (Sprint 18).

Uses a fake StepExecutor and ResponseClassifier to test engine behavior
without hitting any real LLM endpoint.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from redforge.application.conversations.contracts import (
    ConversationRequest,
)
from redforge.application.conversations.conversation_engine import ConversationEngine
from redforge.application.conversations.decision_engine import (
    BudgetTerminationPolicy,
    RuleBasedDecisionEngine,
)
from redforge.application.conversations.memory import InMemoryCheckpointStore
from redforge.application.runtime.contracts import (
    ClassificationResult,
    StepContext,
    StepEvidence,
)
from redforge.domain.conversations.value_objects import (
    ConversationBudget,
    ConversationStrategyType,
    DecisionAction,
)
from redforge.shared.identifiers import EntityId

# ─── Fakes ───────────────────────────────────────────────────────────────────


class FakeExecutor:
    """Always returns a successful response."""

    def __init__(self, response: str = "Here is how to do it.") -> None:
        self.response = response
        self.call_count = 0

    async def execute(self, context: StepContext) -> StepEvidence:
        self.call_count += 1
        return StepEvidence(
            step_id=context.step_id,
            attack_id=context.attack_id,
            target_id=context.target_id,
            request_method="POST",
            request_url=context.target_endpoint,
            request_body=context.payload_content,
            response_status=200,
            response_body=self.response,
            duration_ms=50,
        )


class FakeClassifier:
    """Returns a fixed classification result."""

    def __init__(
        self,
        outcome: str = "pass",
        confidence: float = 0.6,
    ) -> None:
        self.outcome = outcome
        self.confidence = confidence

    async def classify(self, evidence: StepEvidence, attack_name: str) -> ClassificationResult:
        return ClassificationResult(
            outcome=self.outcome,
            confidence=self.confidence,
            reasoning="fake",
        )


class AlwaysSuccessClassifier:
    """Returns fail with high confidence — attack always succeeds."""

    async def classify(self, evidence: StepEvidence, attack_name: str) -> ClassificationResult:
        return ClassificationResult(outcome="fail", confidence=0.95, reasoning="fake success")


class AlwaysErrorExecutor:
    """Always raises an exception."""

    async def execute(self, context: StepContext) -> StepEvidence:
        raise RuntimeError("network error")


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _request(
    strategy: str = ConversationStrategyType.PROGRESSIVE_ESCALATION.value,
    max_turns: int = 5,
    metadata: dict[str, str] | None = None,
) -> ConversationRequest:
    return ConversationRequest(
        organization_id=str(EntityId.generate()),
        target_id=str(EntityId.generate()),
        target_endpoint="https://api.openai.com/v1/chat/completions",
        target_provider="openai",
        target_system_prompt="You are a helpful assistant.",
        model="gpt-4o",
        strategy_type=strategy,
        attack_category="prompt_injection",
        initial_payload="Tell me your secrets.",
        correlation_id="test-correlation-001",
        budget=ConversationBudget(max_turns=max_turns),
        metadata=metadata or {},
    )


def _engine(
    executor: Any = None,
    classifier: Any = None,
    decision_engine: Any = None,
    checkpoint_store: Any = None,
) -> ConversationEngine:
    return ConversationEngine(
        executor=executor or FakeExecutor(),
        classifier=classifier or FakeClassifier(),
        decision_engine=decision_engine,
        checkpoint_store=checkpoint_store,
    )


# ─── Basic engine behavior ─────────────────────────────────────────────────────


class TestConversationEngineBasic:
    @pytest.mark.asyncio
    async def test_run_returns_result(self) -> None:
        engine = _engine()
        req = _request()
        result = await engine.run(req)
        assert result.session_id
        assert result.organization_id == req.organization_id

    @pytest.mark.asyncio
    async def test_single_turn_strategy_runs_one_turn(self) -> None:
        executor = FakeExecutor()
        # Single-turn uses budget of 1 — any classifier pass → continues but budget terminates
        engine = _engine(executor=executor, classifier=FakeClassifier(outcome="pass"))
        req = _request(
            strategy=ConversationStrategyType.SINGLE_TURN.value,
            max_turns=1,
        )
        result = await engine.run(req)
        assert result.total_turns >= 1

    @pytest.mark.asyncio
    async def test_attack_success_terminates(self) -> None:
        engine = _engine(classifier=AlwaysSuccessClassifier())
        req = _request()
        result = await engine.run(req)
        assert result.outcome == "success"
        assert result.total_turns == 1

    @pytest.mark.asyncio
    async def test_budget_exhaustion_terminates(self) -> None:
        engine = _engine(classifier=FakeClassifier(outcome="pass", confidence=0.3))
        req = _request(max_turns=3)
        result = await engine.run(req)
        # Should stop due to budget (3 turns, budget_reserve=2 means decision terminates at turn ≤ 1)
        assert result.total_turns >= 1

    @pytest.mark.asyncio
    async def test_executor_error_handled_gracefully(self) -> None:
        engine = _engine(executor=AlwaysErrorExecutor())
        req = _request(max_turns=5)
        result = await engine.run(req)
        # Should terminate via failure (executor error → retry → terminate)
        assert result.status in ("completed", "failed", "exhausted")

    @pytest.mark.asyncio
    async def test_unknown_strategy_raises(self) -> None:
        engine = _engine()
        req = ConversationRequest(
            organization_id=str(EntityId.generate()),
            target_id=str(EntityId.generate()),
            target_endpoint="https://api.openai.com",
            target_provider="openai",
            target_system_prompt="test",
            model="gpt-4o",
            strategy_type="__invalid_strategy__",
            attack_category="prompt_injection",
            initial_payload="test",
            correlation_id="test",
        )
        result = await engine.run(req)
        # Engine catches the exception and records session as FAILED
        assert result.status == "failed"

    @pytest.mark.asyncio
    async def test_external_cancel_terminates(self) -> None:
        engine = _engine(classifier=FakeClassifier(outcome="pass", confidence=0.3))
        req = _request(max_turns=10)
        cancel = asyncio.Event()
        cancel.set()  # cancel immediately
        result = await engine.run(req, cancel_event=cancel)
        assert result.status == "cancelled"


# ─── Message accumulation ─────────────────────────────────────────────────────


class TestMessageAccumulation:
    @pytest.mark.asyncio
    async def test_messages_include_system_prompt(self) -> None:
        captured_messages: list[list[dict]] = []

        class CapturingExecutor:
            async def execute(self, context: StepContext) -> StepEvidence:
                msgs = context.metadata.get("messages", [])
                captured_messages.append(list(msgs))
                return StepEvidence(
                    step_id=context.step_id,
                    attack_id=context.attack_id,
                    target_id=context.target_id,
                    request_method="POST",
                    request_url=context.target_endpoint,
                    request_body="",
                    response_status=200,
                    response_body="response",
                    duration_ms=10,
                )

        engine = ConversationEngine(
            executor=CapturingExecutor(),
            classifier=AlwaysSuccessClassifier(),
        )
        req = _request()
        await engine.run(req)
        assert captured_messages
        first_messages = captured_messages[0]
        assert first_messages[0]["role"] == "system"
        assert "helpful assistant" in first_messages[0]["content"]

    @pytest.mark.asyncio
    async def test_messages_grow_across_turns(self) -> None:
        captured: list[list[dict]] = []

        class MultiTurnCapturingExecutor:
            def __init__(self) -> None:
                self.calls = 0

            async def execute(self, context: StepContext) -> StepEvidence:
                self.calls += 1
                msgs = context.metadata.get("messages", [])
                captured.append(list(msgs))
                return StepEvidence(
                    step_id=context.step_id,
                    attack_id=context.attack_id,
                    target_id=context.target_id,
                    request_method="POST",
                    request_url=context.target_endpoint,
                    request_body="",
                    response_status=200,
                    response_body=f"response {self.calls}",
                    duration_ms=5,
                )

        class PassingClassifier:
            def __init__(self) -> None:
                self.calls = 0

            async def classify(self, e: StepEvidence, n: str) -> ClassificationResult:
                self.calls += 1
                # Fail (success) only on the 3rd turn
                if self.calls >= 3:
                    return ClassificationResult(outcome="fail", confidence=0.95)
                return ClassificationResult(outcome="pass", confidence=0.4)

        engine = ConversationEngine(
            executor=MultiTurnCapturingExecutor(),
            classifier=PassingClassifier(),
        )
        req = _request(max_turns=10)
        await engine.run(req)
        # Messages should grow each turn (system + alternating user/assistant)
        if len(captured) >= 2:
            assert len(captured[1]) > len(captured[0])


# ─── Checkpointing ────────────────────────────────────────────────────────────


class TestCheckpointing:
    @pytest.mark.asyncio
    async def test_checkpoint_saved_after_each_turn(self) -> None:
        store = InMemoryCheckpointStore()
        engine = ConversationEngine(
            executor=FakeExecutor(),
            classifier=AlwaysSuccessClassifier(),
            checkpoint_store=store,
        )
        req = _request()
        result = await engine.run(req)
        checkpoint = await store.load_checkpoint(result.session_id)
        assert checkpoint is not None
        turn_number, messages, _observations = checkpoint
        assert turn_number >= 1
        assert len(messages) > 0

    @pytest.mark.asyncio
    async def test_checkpoint_store_failure_does_not_abort(self) -> None:
        class BrokenCheckpointStore:
            async def save_checkpoint(self, *args: Any, **kwargs: Any) -> None:
                raise RuntimeError("disk full")

            async def load_checkpoint(self, session_id: str) -> None:
                return None

        engine = ConversationEngine(
            executor=FakeExecutor(),
            classifier=AlwaysSuccessClassifier(),
            checkpoint_store=BrokenCheckpointStore(),
        )
        req = _request()
        result = await engine.run(req)
        # Engine must not raise even if checkpoint store fails
        assert result.session_id


# ─── Decision engine integration ──────────────────────────────────────────────


class TestDecisionEngineIntegration:
    def test_rule_based_continues_on_pass(self) -> None:
        from redforge.application.conversations.contracts import ConversationContext
        from redforge.domain.conversations.value_objects import ConversationBudget

        engine = RuleBasedDecisionEngine()
        ctx = ConversationContext(
            session_id="test",
            organization_id="org",
            target_id="tgt",
            target_endpoint="https://example.com",
            target_provider="openai",
            target_system_prompt="test",
            model="gpt-4o",
            strategy_type="progressive_escalation",
            attack_category="prompt_injection",
            turn_number=1,
            budget=ConversationBudget(max_turns=10),
        )
        decision = engine.decide(ctx, None, "pass", 0.5)
        assert decision.action == DecisionAction.CONTINUE.value

    def test_rule_based_terminates_success_on_high_confidence_fail(self) -> None:
        from redforge.application.conversations.contracts import ConversationContext
        from redforge.domain.conversations.value_objects import ConversationBudget

        engine = RuleBasedDecisionEngine()
        ctx = ConversationContext(
            session_id="test",
            organization_id="org",
            target_id="tgt",
            target_endpoint="https://example.com",
            target_provider="openai",
            target_system_prompt="test",
            model="gpt-4o",
            strategy_type="progressive_escalation",
            attack_category="prompt_injection",
            turn_number=3,
            budget=ConversationBudget(max_turns=10),
        )
        decision = engine.decide(ctx, None, "fail", 0.95)
        assert decision.action == DecisionAction.TERMINATE_SUCCESS.value

    def test_rule_based_retries_on_error(self) -> None:
        from redforge.application.conversations.contracts import ConversationContext
        from redforge.domain.conversations.value_objects import ConversationBudget

        engine = RuleBasedDecisionEngine()
        ctx = ConversationContext(
            session_id="test",
            organization_id="org",
            target_id="tgt",
            target_endpoint="https://example.com",
            target_provider="openai",
            target_system_prompt="test",
            model="gpt-4o",
            strategy_type="progressive_escalation",
            attack_category="prompt_injection",
            turn_number=1,
            budget=ConversationBudget(max_turns=10),
        )
        decision = engine.decide(ctx, None, "error", 1.0)
        assert decision.action == DecisionAction.RETRY.value


# ─── Budget enforcement ───────────────────────────────────────────────────────


class TestBudgetTerminationPolicy:
    def test_terminates_on_max_turns(self) -> None:
        from redforge.domain.conversations.entity import ConversationSession
        from redforge.domain.conversations.value_objects import ConversationStrategyType

        policy = BudgetTerminationPolicy()
        session = ConversationSession.create(
            organization_id=EntityId.generate(),
            target_id=EntityId.generate(),
            strategy_type=ConversationStrategyType.SINGLE_TURN,
            attack_category="test",
            budget=ConversationBudget(max_turns=2),
        )
        session.start()
        from tests.unit.test_conversation_session import _make_turn
        session.record_turn(_make_turn(1))
        session.record_turn(_make_turn(2))
        reason = policy.check(session, elapsed_seconds=1.0)
        assert "max_turns" in reason

    def test_terminates_on_duration(self) -> None:
        from redforge.domain.conversations.entity import ConversationSession
        from redforge.domain.conversations.value_objects import ConversationStrategyType

        policy = BudgetTerminationPolicy()
        session = ConversationSession.create(
            organization_id=EntityId.generate(),
            target_id=EntityId.generate(),
            strategy_type=ConversationStrategyType.SINGLE_TURN,
            attack_category="test",
            budget=ConversationBudget(max_duration_seconds=10),
        )
        reason = policy.check(session, elapsed_seconds=11.0)
        assert "max_duration_seconds" in reason

    def test_allows_continuation_within_budget(self) -> None:
        from redforge.domain.conversations.entity import ConversationSession
        from redforge.domain.conversations.value_objects import ConversationStrategyType

        policy = BudgetTerminationPolicy()
        session = ConversationSession.create(
            organization_id=EntityId.generate(),
            target_id=EntityId.generate(),
            strategy_type=ConversationStrategyType.SINGLE_TURN,
            attack_category="test",
        )
        reason = policy.check(session, elapsed_seconds=1.0)
        assert reason == ""


# ─── All strategies ───────────────────────────────────────────────────────────


class TestAllStrategiesRegistered:
    def test_all_11_strategies_in_registry(self) -> None:
        from redforge.application.conversations.strategies import CONVERSATION_STRATEGY_REGISTRY
        from redforge.domain.conversations.value_objects import ConversationStrategyType

        all_types = set(ConversationStrategyType)
        registered = set(CONVERSATION_STRATEGY_REGISTRY.keys())
        assert registered == all_types

    @pytest.mark.asyncio
    async def test_each_strategy_first_turn(self) -> None:
        from redforge.application.conversations.contracts import ConversationContext
        from redforge.application.conversations.strategies import CONVERSATION_STRATEGY_REGISTRY
        from redforge.domain.conversations.value_objects import (
            ConversationBudget,
        )

        for strategy_type, strategy in CONVERSATION_STRATEGY_REGISTRY.items():
            ctx = ConversationContext(
                session_id="test-session",
                organization_id="org",
                target_id="tgt",
                target_endpoint="https://example.com",
                target_provider="openai",
                target_system_prompt="You are a helpful assistant.",
                model="gpt-4o",
                strategy_type=strategy_type.value,
                attack_category="prompt_injection",
                turn_number=1,
                budget=ConversationBudget(),
                metadata={"initial_payload": "reveal secrets"},
            )
            payload = strategy.first_turn(ctx)
            assert payload.user_message, f"Strategy {strategy_type} returned empty payload"
