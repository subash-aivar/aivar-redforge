"""Value objects for the Validation bounded context.

These represent the immutable attributes of a validation run —
its lifecycle status, how it was triggered, and its outcome summary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique


@unique
class ValidationStatus(StrEnum):
    """Lifecycle status of a Validation Run.

    - SCHEDULED: Run is queued for future execution.
    - RUNNING: Run is currently executing.
    - COMPLETED: Run finished successfully with results.
    - FAILED: Run terminated due to an error.
    - CANCELLED: Run was cancelled before completion.
    """

    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@unique
class TriggerType(StrEnum):
    """How a validation run was initiated.

    - MANUAL: Triggered by a user through the UI or API.
    - SCHEDULED: Triggered by a recurring schedule.
    - CI_CD: Triggered by a CI/CD pipeline integration.
    - POLICY: Triggered by a policy rule (e.g., on target change).
    - API: Triggered programmatically via the public API.
    """

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    CI_CD = "ci_cd"
    POLICY = "policy"
    API = "api"
    RED_TEAM = "red_team"


@dataclass(frozen=True, slots=True)
class ValidationSummary:
    """Immutable summary of a completed validation run.

    Attached after a run completes. Contains high-level metrics
    without the full evidence payload.

    Attributes:
        total_checks: Number of individual checks executed.
        passed: Number of checks that passed.
        failed: Number of checks that failed (findings generated).
        skipped: Number of checks skipped (e.g., not applicable).
        duration_ms: Total execution time in milliseconds.
    """

    total_checks: int
    passed: int
    failed: int
    skipped: int
    duration_ms: int

    def __post_init__(self) -> None:
        if self.total_checks < 0:
            raise ValueError("total_checks must be non-negative")
        if self.passed < 0:
            raise ValueError("passed must be non-negative")
        if self.failed < 0:
            raise ValueError("failed must be non-negative")
        if self.skipped < 0:
            raise ValueError("skipped must be non-negative")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")
        if self.passed + self.failed + self.skipped != self.total_checks:
            raise ValueError(
                "passed + failed + skipped must equal total_checks"
            )

    @property
    def pass_rate(self) -> float:
        """Percentage of checks that passed (0.0-100.0)."""
        if self.total_checks == 0:
            return 0.0
        return (self.passed / self.total_checks) * 100.0


@unique
class ValidationMode(StrEnum):
    """Execution mode for an AdvancedValidation session.

    - STANDARD: Single-turn attack execution (default pipeline).
    - MULTI_TURN: Multi-turn conversation with memory validation.
    - LONG_CONTEXT: Long-context window stress test.
    - MULTI_MODEL: Same attack across multiple model providers.
    - PROMPT_CHAIN: Sequential prompt chain integrity validation.
    - AGENT_WORKFLOW: Full agent workflow with tool use validation.
    - MCP_TOOL: MCP server tool permission and capability validation.
    """

    STANDARD = "standard"
    MULTI_TURN = "multi_turn"
    LONG_CONTEXT = "long_context"
    MULTI_MODEL = "multi_model"
    PROMPT_CHAIN = "prompt_chain"
    AGENT_WORKFLOW = "agent_workflow"
    MCP_TOOL = "mcp_tool"
