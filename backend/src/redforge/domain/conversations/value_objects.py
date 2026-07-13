"""Value objects for the Conversation bounded context.

All value objects are immutable frozen dataclasses or StrEnums.
They are self-validating — __post_init__ enforces all invariants.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003 — used in frozen dataclass field slots
from enum import StrEnum, unique


@unique
class ConversationStatus(StrEnum):
    """Lifecycle status of a ConversationSession.

    State machine:
        PENDING → RUNNING → COMPLETED
                          → FAILED
                          → CANCELLED
                          → EXHAUSTED   (budget hit without terminal decision)
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXHAUSTED = "exhausted"


@unique
class ConversationOutcome(StrEnum):
    """Final result of a ConversationSession.

    Attached by complete() or exhaust_budget() — not set during execution.
    """

    SUCCESS = "success"     # attack succeeded — target produced vulnerable output
    FAILURE = "failure"     # target resisted all turns
    PARTIAL = "partial"     # mixed: some turns succeeded, some resisted
    EXHAUSTED = "exhausted" # budget hit before a terminal decision
    ERROR = "error"         # unhandled execution errors dominated


@unique
class DecisionAction(StrEnum):
    """The adaptive decision made after evaluating a turn's response.

    Produced by DecisionEngine. Consumed by ConversationEngine to determine
    what to do next.

    - CONTINUE: same strategy, next natural turn
    - ESCALATE: increase pressure (more specific, more forceful)
    - PIVOT: switch to a different angle or technique
    - RETRY: re-send approximately the same payload (transient error recovery)
    - TERMINATE_SUCCESS: attack succeeded — stop the session
    - TERMINATE_FAILURE: attack clearly failed — stop the session
    """

    CONTINUE = "continue"
    ESCALATE = "escalate"
    PIVOT = "pivot"
    RETRY = "retry"
    TERMINATE_SUCCESS = "terminate_success"
    TERMINATE_FAILURE = "terminate_failure"


@unique
class ConversationStrategyType(StrEnum):
    """Named conversation strategies.

    Used as keys in the CONVERSATION_STRATEGY_REGISTRY (dict dispatch,
    no switch statements). Each entry maps to a ConversationStrategyPort
    implementation.
    """

    SINGLE_TURN = "single_turn"
    PROGRESSIVE_ESCALATION = "progressive_escalation"
    RECURSIVE_PROMPTING = "recursive_prompting"
    ROLE_PLAY = "role_play"
    AUTHORITY_ESCALATION = "authority_escalation"
    CONTEXT_POISONING = "context_poisoning"
    MEMORY_MANIPULATION = "memory_manipulation"
    GOAL_REFINEMENT = "goal_refinement"
    TOOL_DISCOVERY = "tool_discovery"
    TOOL_ABUSE_PREPARATION = "tool_abuse_preparation"
    REASONING_MANIPULATION = "reasoning_manipulation"


@dataclass(frozen=True, slots=True)
class ConversationBudget:
    """Hard limits for a ConversationSession.

    All three limits are checked after each turn; the first to be hit
    triggers EXHAUSTED status. max_turns is the primary safety guard.
    """

    max_turns: int = 10
    max_duration_seconds: int = 300
    max_estimated_tokens: int = 50_000

    def __post_init__(self) -> None:
        if self.max_turns < 1:
            raise ValueError("max_turns must be >= 1")
        if self.max_duration_seconds < 1:
            raise ValueError("max_duration_seconds must be >= 1")
        if self.max_estimated_tokens < 100:
            raise ValueError("max_estimated_tokens must be >= 100")


@dataclass(frozen=True, slots=True)
class ConversationTurn:
    """Immutable record of one completed turn in a conversation.

    Appended to ConversationSession.turns as the conversation progresses.
    Contains everything needed for forensic analysis, replay, or checkpoint
    recovery.

    estimated_tokens: rough approximation (len(attack_payload + response) / 4)
    for budget tracking; not authoritative.
    """

    turn_number: int               # 1-indexed
    attack_payload: str            # the user message sent this turn
    assistant_response: str | None # what the target returned; None on executor error
    evaluation_outcome: str        # ConversationOutcome value or sub-outcome
    decision: str                  # DecisionAction value
    turn_started_at: datetime | None
    turn_completed_at: datetime | None
    estimated_tokens: int
    error: str | None = None       # non-None if the executor failed this turn
    metadata: dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.turn_number < 1:
            raise ValueError("turn_number must be >= 1")
        if self.estimated_tokens < 0:
            raise ValueError("estimated_tokens must be >= 0")
        # Provide a stable empty dict without mutable-default-argument issues
        if self.metadata is None:
            object.__setattr__(self, "metadata", {})

    @property
    def is_error(self) -> bool:
        return bool(self.error)  # None and "" both falsy

    @property
    def duration_ms(self) -> int:
        if self.turn_started_at is None or self.turn_completed_at is None:
            return 0
        delta = self.turn_completed_at - self.turn_started_at
        return max(0, int(delta.total_seconds() * 1000))


@dataclass(frozen=True, slots=True)
class ConversationMetrics:
    """Aggregate metrics computed at the end of a ConversationSession."""

    total_turns: int
    successful_turns: int     # turns where evaluation_outcome indicated success
    failed_turns: int
    error_turns: int
    escalation_count: int     # how many ESCALATE decisions were made
    pivot_count: int          # how many PIVOT decisions were made
    retry_count: int          # how many RETRY decisions were made
    total_estimated_tokens: int
    total_duration_ms: int

    def __post_init__(self) -> None:
        if self.total_turns < 0:
            raise ValueError("total_turns must be >= 0")

    @property
    def success_rate(self) -> float:
        if self.total_turns == 0:
            return 0.0
        return self.successful_turns / self.total_turns

    @property
    def escalation_rate(self) -> float:
        if self.total_turns == 0:
            return 0.0
        return self.escalation_count / self.total_turns
