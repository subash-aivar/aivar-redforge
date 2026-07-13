"""Domain exceptions for the Conversation bounded context."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, ValidationError


class ConversationBudgetExhaustedError(ValidationError):
    """Raised when a ConversationSession has hit its budget limit."""

    def __init__(self, session_id: str, reason: str) -> None:
        super().__init__(f"Conversation '{session_id}' budget exhausted: {reason}")
        self.session_id = session_id
        self.exhaustion_reason = reason


class MaxTurnsExceededError(ConversationBudgetExhaustedError):
    """Raised specifically when the max_turns budget is hit."""

    def __init__(self, session_id: str, max_turns: int) -> None:
        super().__init__(session_id, f"max_turns={max_turns} reached")
        self.max_turns = max_turns


class ConversationAlreadyTerminalError(ConflictError):
    """Raised when an operation is attempted on a terminal conversation."""

    def __init__(self, session_id: str, status: str) -> None:
        super().__init__(
            f"ConversationSession '{session_id}' is already terminal: {status}"
        )
        self.session_id = session_id
        self.status = status


class InvalidConversationTransitionError(ConflictError):
    """Raised when a lifecycle transition is not allowed from the current status."""

    def __init__(self, current: str, attempted: str) -> None:
        super().__init__(
            f"Cannot transition conversation from '{current}' to '{attempted}'"
        )
        self.current = current
        self.attempted = attempted


class ConversationNotRunningError(ConflictError):
    """Raised when a turn is recorded on a non-running session."""

    def __init__(self, session_id: str, status: str) -> None:
        super().__init__(
            f"Cannot record turn on session '{session_id}': status is '{status}'"
        )


class EmptyConversationError(ValidationError):
    """Raised when complete() is called on a session with no turns."""

    def __init__(self, session_id: str) -> None:
        super().__init__(f"ConversationSession '{session_id}' has no recorded turns")
