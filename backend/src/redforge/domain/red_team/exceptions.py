"""Exceptions for the Red Team bounded context — Sprint 34/35."""

from __future__ import annotations


class RedTeamError(Exception):
    """Base for all red team domain errors."""


class GoalAchievedSignal(RedTeamError):  # noqa: N818
    """Raised (as a control-flow signal) when the campaign goal is achieved.

    Not an error — the orchestrator catches this to exit the execution
    loop cleanly and record the result.
    """

    def __init__(self, node_id: str, total_findings: int) -> None:
        super().__init__(f"Goal achieved by node {node_id!r} with {total_findings} findings")
        self.node_id = node_id
        self.total_findings = total_findings


class BudgetExhaustedError(RedTeamError):
    """Raised when a BudgetConstraint limit is exceeded."""

    def __init__(self, limit_type: str, limit_value: int) -> None:
        super().__init__(f"Budget exhausted: {limit_type}={limit_value}")
        self.limit_type = limit_type
        self.limit_value = limit_value


class AttackGraphCycleError(RedTeamError):
    """Raised when the attack dependency graph contains a cycle."""


class AttackGraphNotRunningError(RedTeamError):
    """Raised when attempting to execute a graph that is not in RUNNING state."""


class AttackGraphAlreadyTerminalError(RedTeamError):
    """Raised when attempting to transition an already-terminal graph."""


class AttackNodeNotFoundError(RedTeamError):
    """Raised when referencing a node_id that does not exist in the graph."""

    def __init__(self, node_id: str) -> None:
        super().__init__(f"AttackNode not found: {node_id!r}")
        self.node_id = node_id
