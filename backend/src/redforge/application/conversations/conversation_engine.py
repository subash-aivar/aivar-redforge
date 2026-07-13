"""ConversationEngine — adaptive multi-turn attack orchestrator.

Architecture:
- ConversationEngine sits at the APPLICATION layer.
- It uses StepExecutor directly (NOT ValidationService) because it needs
  fine-grained control over the accumulated message list between turns.
- The adaptive loop: Attack → Execute → Classify → Decide → Repeat.
- The engine is NOT an autonomous agent. Decisions are made by the injected
  DecisionEnginePort implementation (default: RuleBasedDecisionEngine).
- Budget enforcement is provided by the injected TerminationPolicyPort.

Invariants:
- ConversationSession is the single source of truth for turn records.
- WorkingMemory holds the live message list; it is NOT persisted.
- Checkpointing (if enabled) writes after each turn for crash recovery.
- Events are collected at end of session and published to the optional bus.
- A session can be cancelled externally via a shared asyncio.Event.

No switch statements. No framework leakage. No duplicated orchestration.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import TYPE_CHECKING

from redforge.application.conversations.contracts import (
    AttackDecision,
    ConversationContext,
    ConversationRequest,
    ConversationResult,
    TurnPayload,
)
from redforge.application.conversations.decision_engine import (
    BudgetTerminationPolicy,
    RuleBasedDecisionEngine,
)
from redforge.application.conversations.memory import ConversationMemory, WorkingMemory
from redforge.application.conversations.strategies import CONVERSATION_STRATEGY_REGISTRY
from redforge.application.runtime.contracts import (
    ClassificationResult,
    ResponseClassifier,
    StepContext,
    StepEvidence,
    StepExecutor,
)
from redforge.domain.conversations.entity import ConversationSession
from redforge.domain.conversations.value_objects import (
    ConversationOutcome,
    ConversationStrategyType,
    ConversationTurn,
    DecisionAction,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.application.conversations.contracts import (
        ConversationCheckpointStorePort,
        ConversationKnowledgeProjectorPort,
        ConversationSessionRepositoryPort,
        ConversationStrategyPort,
        DecisionEnginePort,
        TerminationPolicyPort,
    )

_RECENT_TURNS_WINDOW = 5


def _payload_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _build_step_id(session_id: str, turn_number: int) -> str:
    return f"{session_id}:turn:{turn_number}"


class ConversationEngine:
    """Adaptive multi-turn red-team attack orchestrator.

    Wiring (required):
        executor: StepExecutor — sends messages to the target LLM.
        classifier: ResponseClassifier — classifies each response.

    Wiring (optional, have defaults):
        decision_engine: rule-based engine (default: RuleBasedDecisionEngine).
        termination_policy: budget checker (default: BudgetTerminationPolicy).
        session_repo: saves sessions after each turn.
        checkpoint_store: checkpoints for crash recovery.
        knowledge_projector: KG projection after session ends.
        strategy_registry: overrides the default CONVERSATION_STRATEGY_REGISTRY.
    """

    def __init__(
        self,
        executor: StepExecutor,
        classifier: ResponseClassifier,
        decision_engine: DecisionEnginePort | None = None,
        termination_policy: TerminationPolicyPort | None = None,
        session_repo: ConversationSessionRepositoryPort | None = None,
        checkpoint_store: ConversationCheckpointStorePort | None = None,
        knowledge_projector: ConversationKnowledgeProjectorPort | None = None,
        strategy_registry: dict[ConversationStrategyType, ConversationStrategyPort] | None = None,
    ) -> None:
        self._executor = executor
        self._classifier = classifier
        self._decision_engine: DecisionEnginePort = decision_engine or RuleBasedDecisionEngine()
        self._termination_policy: TerminationPolicyPort = (
            termination_policy or BudgetTerminationPolicy()
        )
        self._session_repo = session_repo
        self._checkpoint_store = checkpoint_store
        self._knowledge_projector = knowledge_projector
        self._registry = strategy_registry or CONVERSATION_STRATEGY_REGISTRY

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(
        self,
        request: ConversationRequest,
        cancel_event: asyncio.Event | None = None,
    ) -> ConversationResult:
        """Execute a complete conversation session.

        Creates a ConversationSession, runs the adaptive loop until a terminal
        decision or budget exhaustion, then persists and projects to the KG.
        """
        # Validate strategy before creating session so we can return a meaningful result
        try:
            strategy = self._resolve_strategy(request.strategy_type)
        except ValueError as exc:
            # Create a minimal failed session to return a structured result
            session = self._create_session_with_fallback_strategy(request)
            session.fail(str(exc))
            await self._persist(session)
            return self._build_result(session)

        session = self._create_session(request)
        working = WorkingMemory()
        memory = ConversationMemory(session_id=str(session.id))
        session_start = time.monotonic()

        try:
            session.start()

            # Seed the message list with the system prompt
            working.append_message("system", request.target_system_prompt)

            result = await self._adaptive_loop(
                session=session,
                request=request,
                working=working,
                memory=memory,
                strategy=strategy,
                cancel_event=cancel_event or asyncio.Event(),
                session_start=session_start,
            )
        except Exception as exc:
            if not session.is_terminal:
                session.fail(str(exc))
            result = self._build_result(session)
        finally:
            await self._persist(session)
            self._project(session)

        return result

    # ── Adaptive loop ─────────────────────────────────────────────────────────

    async def _adaptive_loop(
        self,
        session: ConversationSession,
        request: ConversationRequest,
        working: WorkingMemory,
        memory: ConversationMemory,
        strategy: ConversationStrategyPort,
        cancel_event: asyncio.Event,
        session_start: float,
    ) -> ConversationResult:
        turn_number = 1
        last_decision: AttackDecision | None = None
        last_turn_obj: ConversationTurn | None = None

        while True:
            # External cancellation check
            if cancel_event.is_set():
                session.cancel("external cancellation")
                return self._build_result(session)

            # Termination policy check (budget)
            elapsed = time.monotonic() - session_start
            exhaustion_reason = self._termination_policy.check(session, elapsed)
            if exhaustion_reason:
                session.exhaust_budget(exhaustion_reason)
                return self._build_result(session)

            # Build context for this turn
            ctx = self._build_context(session, request, working, memory, turn_number)

            # Get attack payload from strategy
            if turn_number == 1:
                turn_payload = strategy.first_turn(ctx)
            else:
                assert last_turn_obj is not None
                assert last_decision is not None
                turn_payload = strategy.next_turn(ctx, last_turn_obj, last_decision)

            # Deduplication check
            p_hash = _payload_hash(turn_payload.user_message)
            if working.is_duplicate(p_hash):
                # Force pivot: generate a different payload by rebuilding with pivot context
                turn_payload = TurnPayload(
                    user_message=turn_payload.user_message + f" [variant:{turn_number}]",
                    append_to_history=turn_payload.append_to_history,
                    rationale="dedup: appended variant suffix",
                )
            working.mark_payload(p_hash)

            # Update message history
            if turn_payload.append_to_history:
                working.append_message("user", turn_payload.user_message)
            else:
                working.reset_for_pivot(keep_system=True)
                working.append_message("user", turn_payload.user_message)

            # Execute turn
            evidence = await self._execute_turn(
                session_id=str(session.id),
                turn_number=turn_number,
                request=request,
                working=working,
            )
            # Update assistant response in message history
            if not evidence.is_error:
                working.append_message("assistant", evidence.response_body)

            # Classify
            classification = await self._classify(evidence, request.attack_category)

            # Decide
            decision = self._decision_engine.decide(
                context=ctx,
                last_turn_evidence=evidence,
                classification_outcome=classification.outcome,
                classification_confidence=classification.confidence,
            )

            # Record turn on session
            conv_turn = ConversationTurn(
                turn_number=turn_number,
                attack_payload=turn_payload.user_message,
                assistant_response=evidence.response_body if not evidence.is_error else None,
                evaluation_outcome=classification.outcome,
                decision=decision.action,
                turn_started_at=None,  # not tracking absolute timestamps here
                turn_completed_at=None,
                estimated_tokens=_estimate_tokens(turn_payload.user_message)
                + _estimate_tokens(evidence.response_body),
                error=evidence.error or None,
                metadata={
                    "confidence": str(classification.confidence),
                    "rationale": decision.rationale[:200],
                },
            )
            session.record_turn(conv_turn)
            last_turn_obj = conv_turn
            last_decision = decision

            # Update memory
            memory.record_response(turn_number, evidence.response_body)
            memory.record_strategy_outcome(request.strategy_type, classification.outcome)
            memory.record_observations(decision.observations)
            working.add_observations(decision.observations)

            # Checkpoint after each turn (if store provided)
            await self._checkpoint(session, turn_number, working)

            # Persist session state after each turn
            await self._persist(session)

            # Evaluate terminal decision
            terminal_result = self._check_terminal(session, decision)
            if terminal_result is not None:
                return terminal_result

            turn_number += 1

    # ── Terminal decision handling ─────────────────────────────────────────────

    def _check_terminal(
        self,
        session: ConversationSession,
        decision: AttackDecision,
    ) -> ConversationResult | None:
        action = decision.action
        if action == DecisionAction.TERMINATE_SUCCESS.value:
            session.complete(ConversationOutcome.SUCCESS)
            return self._build_result(session)
        if action == DecisionAction.TERMINATE_FAILURE.value:
            session.complete(ConversationOutcome.FAILURE)
            return self._build_result(session)
        return None

    # ── Turn execution ────────────────────────────────────────────────────────

    async def _execute_turn(
        self,
        session_id: str,
        turn_number: int,
        request: ConversationRequest,
        working: WorkingMemory,
    ) -> StepEvidence:
        step_ctx = StepContext(
            step_id=_build_step_id(session_id, turn_number),
            attack_id=session_id,
            attack_name=f"conversation:{request.strategy_type}",
            target_id=request.target_id,
            target_endpoint=request.target_endpoint,
            target_provider=request.target_provider,
            payload_content=working.messages[-1]["content"] if working.messages else "",
            timeout_seconds=60,
            metadata={
                "messages": working.snapshot_messages(),
                "system_prompt": request.target_system_prompt,
                "model": request.model,
            },
        )
        try:
            return await self._executor.execute(step_ctx)
        except Exception as exc:
            return StepEvidence(
                step_id=step_ctx.step_id,
                attack_id=session_id,
                target_id=request.target_id,
                request_method="POST",
                request_url=request.target_endpoint,
                request_body=step_ctx.payload_content,
                response_status=0,
                response_body="",
                duration_ms=0,
                error=str(exc),
            )

    async def _classify(
        self, evidence: StepEvidence, attack_name: str
    ) -> ClassificationResult:
        if evidence.is_error:
            return ClassificationResult(outcome="error", confidence=1.0, reasoning=evidence.error)
        try:
            return await self._classifier.classify(evidence, attack_name)
        except Exception as exc:
            return ClassificationResult(outcome="error", confidence=1.0, reasoning=str(exc))

    # ── Context builder ────────────────────────────────────────────────────────

    def _build_context(
        self,
        session: ConversationSession,
        request: ConversationRequest,
        working: WorkingMemory,
        memory: ConversationMemory,
        turn_number: int,
    ) -> ConversationContext:
        all_turns = session.turns
        recent = all_turns[-_RECENT_TURNS_WINDOW:] if all_turns else ()
        return ConversationContext(
            session_id=str(session.id),
            organization_id=str(session.organization_id),
            target_id=request.target_id,
            target_endpoint=request.target_endpoint,
            target_provider=request.target_provider,
            target_system_prompt=request.target_system_prompt,
            model=request.model,
            strategy_type=request.strategy_type,
            attack_category=request.attack_category,
            turn_number=turn_number,
            all_turns=all_turns,
            recent_turns=recent,
            attempted_payloads=frozenset(working.attempted_payloads),
            observations=tuple(working.observations),
            budget=session.budget,
            metadata=dict(request.metadata),
        )

    # ── Strategy resolution ────────────────────────────────────────────────────

    def _resolve_strategy(self, strategy_type: str) -> ConversationStrategyPort:
        try:
            key = ConversationStrategyType(strategy_type)
        except ValueError as exc:
            raise ValueError(
                f"Unknown strategy_type '{strategy_type}'. "
                f"Valid values: {[e.value for e in ConversationStrategyType]}"
            ) from exc
        if key not in self._registry:
            raise ValueError(f"Strategy '{strategy_type}' not in registry")
        return self._registry[key]

    # ── Session factory ───────────────────────────────────────────────────────

    def _create_session_with_fallback_strategy(
        self, request: ConversationRequest
    ) -> ConversationSession:
        return ConversationSession.create(
            organization_id=EntityId.from_string(request.organization_id),
            target_id=EntityId.from_string(request.target_id),
            strategy_type=ConversationStrategyType.SINGLE_TURN,
            attack_category=request.attack_category or "unknown",
            budget=request.budget,
        )

    def _create_session(self, request: ConversationRequest) -> ConversationSession:
        return ConversationSession.create(
            organization_id=EntityId.from_string(request.organization_id),
            target_id=EntityId.from_string(request.target_id),
            strategy_type=ConversationStrategyType(request.strategy_type),
            attack_category=request.attack_category,
            budget=request.budget,
            metadata={
                "correlation_id": request.correlation_id,
                "model": request.model,
                **request.metadata,
            },
        )

    # ── Result builder ────────────────────────────────────────────────────────

    def _build_result(self, session: ConversationSession) -> ConversationResult:
        metrics = session.metrics
        return ConversationResult(
            session_id=str(session.id),
            organization_id=str(session.organization_id),
            status=session.status.value,
            outcome=session.outcome.value if session.outcome else None,
            total_turns=session.turn_count,
            successful_turns=metrics.successful_turns if metrics else 0,
            escalation_count=metrics.escalation_count if metrics else 0,
            total_estimated_tokens=session.total_estimated_tokens,
            total_duration_ms=metrics.total_duration_ms if metrics else 0,
            failure_reason=session.failure_reason,
        )

    # ── Side effects (non-fatal) ──────────────────────────────────────────────

    async def _persist(self, session: ConversationSession) -> None:
        import contextlib
        if self._session_repo is None:
            return
        with contextlib.suppress(Exception):
            await self._session_repo.save(session)

    async def _checkpoint(
        self,
        session: ConversationSession,
        turn_number: int,
        working: WorkingMemory,
    ) -> None:
        import contextlib
        if self._checkpoint_store is None:
            return
        with contextlib.suppress(Exception):
            await self._checkpoint_store.save_checkpoint(
                session_id=str(session.id),
                turn_number=turn_number,
                messages=working.snapshot_messages(),
                observations=working.snapshot_observations(),
            )

    def _project(self, session: ConversationSession) -> None:
        import contextlib
        if self._knowledge_projector is None:
            return
        with contextlib.suppress(Exception):
            self._knowledge_projector.project_session(session)
