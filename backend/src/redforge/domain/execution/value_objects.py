"""Value objects for the Execution Engine bounded context.

Models the building blocks of execution orchestration: plans, stages,
steps, strategies, and failure handling.
"""

from dataclasses import dataclass, field
from enum import StrEnum, unique


@unique
class PlanStatus(StrEnum):
    """Lifecycle status of an Execution Plan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


@unique
class StepStatus(StrEnum):
    """Lifecycle status of a single execution step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"


@unique
class FailureStrategy(StrEnum):
    """How the engine handles step failures.

    - FAIL_FAST: Stop entire plan on first failure.
    - CONTINUE: Continue remaining steps, report failures at end.
    - RETRY_THEN_CONTINUE: Retry failed steps, then continue.
    """

    FAIL_FAST = "fail_fast"
    CONTINUE = "continue"
    RETRY_THEN_CONTINUE = "retry_then_continue"


@unique
class ExecutionMode(StrEnum):
    """How steps within a stage are dispatched."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Configuration for step retry behavior."""

    max_retries: int = 3
    backoff_seconds: int = 5

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.backoff_seconds < 0:
            raise ValueError("backoff_seconds must be non-negative")


@dataclass(frozen=True, slots=True)
class TimeoutPolicy:
    """Timeout configuration for execution steps and plans."""

    step_timeout_seconds: int = 60
    plan_timeout_seconds: int = 3600

    def __post_init__(self) -> None:
        if self.step_timeout_seconds <= 0:
            raise ValueError("step_timeout_seconds must be positive")
        if self.plan_timeout_seconds <= 0:
            raise ValueError("plan_timeout_seconds must be positive")


@dataclass(frozen=True, slots=True)
class StepResult:
    """Outcome of a single execution step."""

    status: StepStatus
    evidence_id: str | None = None
    error_message: str = ""
    duration_ms: int = 0
    retries_used: int = 0


@dataclass(frozen=True, slots=True)
class ExecutionStep:
    """A single atomic unit of execution within a stage.

    Each step maps to one attack execution against the target.
    """

    step_id: str
    attack_id: str
    target_id: str
    order: int = 0
    status: StepStatus = StepStatus.PENDING
    result: StepResult | None = None

    def __post_init__(self) -> None:
        if not self.step_id:
            raise ValueError("step_id must not be empty")
        if not self.attack_id:
            raise ValueError("attack_id must not be empty")
        if not self.target_id:
            raise ValueError("target_id must not be empty")


@dataclass(frozen=True, slots=True)
class ExecutionStage:
    """A group of steps executed together with a shared mode.

    Stages enable grouping attacks: e.g., run all injection attacks
    in parallel, then run exfiltration attacks sequentially.
    """

    stage_id: str
    name: str
    mode: ExecutionMode
    steps: tuple[ExecutionStep, ...] = field(default_factory=tuple)
    order: int = 0

    def __post_init__(self) -> None:
        if not self.stage_id:
            raise ValueError("stage_id must not be empty")
        if not self.name:
            raise ValueError("name must not be empty")

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def is_complete(self) -> bool:
        return all(
            s.status in {StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED}
            for s in self.steps
        )
