"""Domain exceptions for the Agent & MCP bounded context."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, ValidationError


class AgentSessionAlreadyTerminalError(ConflictError):
    def __init__(self, session_id: str, status: str) -> None:
        super().__init__(f"AgentSession '{session_id}' is already terminal: {status}")
        self.session_id = session_id
        self.status = status


class AgentSessionNotRunningError(ConflictError):
    def __init__(self, session_id: str, status: str) -> None:
        super().__init__(
            f"Cannot record invocation on session '{session_id}': status is '{status}'"
        )


class InvalidAgentSessionTransitionError(ConflictError):
    def __init__(self, current: str, attempted: str) -> None:
        super().__init__(
            f"Cannot transition agent session from '{current}' to '{attempted}'"
        )


class ToolLoopError(ValidationError):
    """Raised when a recursive tool loop exceeds the allowed depth."""

    def __init__(self, tool_name: str, depth: int, max_depth: int) -> None:
        super().__init__(
            f"Tool '{tool_name}' exceeded max recursion depth {max_depth} (reached {depth})"
        )
        self.tool_name = tool_name
        self.depth = depth
        self.max_depth = max_depth


class AgentBudgetExhaustedError(ValidationError):
    def __init__(self, session_id: str, reason: str) -> None:
        super().__init__(f"AgentSession '{session_id}' budget exhausted: {reason}")
        self.session_id = session_id
        self.exhaustion_reason = reason


class MCPSessionError(ConflictError):
    def __init__(self, session_id: str, reason: str) -> None:
        super().__init__(f"MCPSession '{session_id}' error: {reason}")


class UnknownToolError(ValidationError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(f"Tool '{tool_name}' not registered in this session")
        self.tool_name = tool_name
