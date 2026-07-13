"""Protocol contracts for the Conversation Engine.

Every collaborator injected into ConversationEngine is defined here as a
@runtime_checkable Protocol. No concrete implementations are imported.

Key design rules:
- All Protocols are @runtime_checkable for isinstance() checks in tests.
- No Protocol has a concrete default implementation — the engine requires
  explicit wiring (same pattern as EvaluationEngine in Sprint 16).
- All async methods are co-routines; sync methods are plain methods.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.application.runtime.contracts import StepEvidence
    from redforge.domain.conversations.entity import ConversationSession
    from redforge.domain.conversations.value_objects import (
        ConversationBudget,
        ConversationTurn,
    )


# ─── DTOs flowing between engine components ───────────────────────────────────


@dataclass(frozen=True)
class ConversationContext:
    """Read-only context snapshot passed to strategies and decision engine.

    Constructed by ConversationEngine before calling each strategy or decision
    step. Immutable — strategies cannot mutate engine state through this object.
    """

    session_id: str
    organization_id: str
    target_id: str
    target_endpoint: str
    target_provider: str
    target_system_prompt: str
    model: str
    strategy_type: str              # ConversationStrategyType.value
    attack_category: str
    turn_number: int                # which turn we're about to execute (1-indexed)
    all_turns: tuple[ConversationTurn, ...] = ()
    recent_turns: tuple[ConversationTurn, ...] = ()  # last min(5, total) turns
    attempted_payloads: frozenset[str] = field(default_factory=frozenset)
    observations: tuple[str, ...] = ()
    budget: ConversationBudget | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TurnPayload:
    """What a ConversationStrategy produces for one turn.

    user_message: the attack text to send as the next user message.
    append_to_history: if True (default), ConversationEngine appends this
      message to the growing message list. Set False for pivot turns that
      restart the conversation thread.
    rationale: optional explanation for logging/forensics.
    """

    user_message: str
    append_to_history: bool = True
    rationale: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackDecision:
    """Output of DecisionEngine — what to do after evaluating a turn.

    action: one of DecisionAction values.
    rationale: human-readable explanation for the decision.
    confidence: 0.0-1.0 confidence in this decision.
    observations: key patterns extracted from the response for memory.
    """

    action: str                     # DecisionAction.value
    rationale: str
    confidence: float = 0.5
    observations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be 0.0-1.0, got {self.confidence}")


@dataclass(frozen=True)
class ConversationRequest:
    """Everything ConversationEngine needs to start a session."""

    organization_id: str
    target_id: str
    target_endpoint: str
    target_provider: str
    target_system_prompt: str
    model: str
    strategy_type: str              # ConversationStrategyType.value
    attack_category: str
    initial_payload: str
    correlation_id: str
    budget: ConversationBudget | None = None
    policy_id: str | None = None
    campaign_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ConversationResult:
    """What ConversationEngine returns after completing a session."""

    session_id: str
    organization_id: str
    status: str
    outcome: str | None
    total_turns: int
    successful_turns: int
    escalation_count: int
    total_estimated_tokens: int
    total_duration_ms: int
    failure_reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.outcome == "success"


# ─── Protocols ────────────────────────────────────────────────────────────────


@runtime_checkable
class ConversationStrategyPort(Protocol):
    """Produces the attack payload for each turn of a conversation.

    The strategy does NOT execute — it only decides WHAT to send next.
    HOW to send it (message list accumulation) is ConversationEngine's job.

    first_turn: called once to get the opening attack message.
    next_turn: called after each non-terminal decision to get the follow-up.
    """

    @property
    def name(self) -> str:
        """Strategy identifier (matches ConversationStrategyType value)."""
        ...

    def first_turn(self, context: ConversationContext) -> TurnPayload:
        """Return the opening attack payload."""
        ...

    def next_turn(
        self,
        context: ConversationContext,
        last_turn: ConversationTurn,
        decision: AttackDecision,
    ) -> TurnPayload:
        """Return the next payload given conversation history and last decision."""
        ...


@runtime_checkable
class DecisionEnginePort(Protocol):
    """Rule-based engine that decides what to do after evaluating a turn.

    NOT an LLM judge — uses heuristics on the classification result and
    turn history to produce an AttackDecision.
    """

    def decide(
        self,
        context: ConversationContext,
        last_turn_evidence: StepEvidence,
        classification_outcome: str,  # "pass"|"fail"|"error"|"inconclusive"
        classification_confidence: float,
    ) -> AttackDecision:
        ...


@runtime_checkable
class TerminationPolicyPort(Protocol):
    """Checks whether a budget limit has been hit.

    Called after each turn before dispatching the next one. Returns a
    non-empty string (the exhaustion reason) if the session must terminate,
    or an empty string if execution can continue.
    """

    def check(
        self,
        session: ConversationSession,
        elapsed_seconds: float,
    ) -> str:
        """Return exhaustion reason (non-empty) or "" to continue."""
        ...


@runtime_checkable
class ConversationSessionRepositoryPort(Protocol):
    """Persistence boundary for ConversationSession aggregates."""

    async def save(self, session: ConversationSession) -> None:
        ...

    async def get(self, session_id: str) -> ConversationSession | None:
        ...


@runtime_checkable
class ConversationCheckpointStorePort(Protocol):
    """Optional checkpoint store for conversation recovery.

    When provided, ConversationEngine writes a lightweight checkpoint after
    each turn. This enables resuming a long-running conversation after a
    process restart or crash.
    """

    async def save_checkpoint(
        self,
        session_id: str,
        turn_number: int,
        messages: list[dict[str, Any]],
        observations: list[str],
    ) -> None:
        ...

    async def load_checkpoint(
        self, session_id: str
    ) -> tuple[int, list[dict[str, Any]], list[str]] | None:
        """Return (last_turn_number, messages, observations) or None."""
        ...


@runtime_checkable
class ConversationKnowledgeProjectorPort(Protocol):
    """Projects ConversationSession lifecycle events into the Knowledge Graph."""

    def project_session(self, session: ConversationSession) -> int:
        """Project session node + edges. Returns nodes added."""
        ...
