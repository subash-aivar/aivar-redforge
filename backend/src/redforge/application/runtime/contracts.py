"""Runtime execution contracts (protocols).

These define the extension points for the execution pipeline.
Each protocol can be implemented by infrastructure adapters.

Protocols:
- StepExecutor: executes one attack step → produces Evidence data
- ResponseClassifier: analyzes response → determines pass/fail
- ExecutionDispatcher: traverses plan and dispatches steps
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class StepContext:
    """Everything needed to execute one step.

    Passed to StepExecutor. Contains references to domain objects
    but does NOT embed them — keeps infrastructure decoupled.
    """

    step_id: str
    attack_id: str
    attack_name: str
    target_id: str
    target_endpoint: str
    target_provider: str
    payload_content: str
    timeout_seconds: int = 60
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StepEvidence:
    """Raw evidence captured from one execution step.

    This is the output of StepExecutor. It will be used to create
    a domain Evidence entity by the orchestrator.
    """

    step_id: str
    attack_id: str
    target_id: str
    request_method: str
    request_url: str
    request_body: str
    response_status: int
    response_body: str
    duration_ms: int
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.error != ""


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """Output of ResponseClassifier.

    Maps to the existing EvidenceResult enum values.
    """

    outcome: str  # "pass" | "fail" | "error" | "inconclusive"
    confidence: float  # 0.0 to 1.0
    reasoning: str = ""

    def __post_init__(self) -> None:
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@runtime_checkable
class StepExecutor(Protocol):
    """Executes one attack step against a target.

    Input: StepContext (attack + target + payload)
    Output: StepEvidence (request/response capture)

    Implementations:
    - ChatCompletionExecutor (LLM chat targets)
    - ToolUseExecutor (function-calling targets)
    - Future: AgentExecutor, RAGExecutor, MCPExecutor
    """

    async def execute(self, context: StepContext) -> StepEvidence:
        """Execute one step. Must capture request and response."""
        ...


@runtime_checkable
class ResponseClassifier(Protocol):
    """Classifies a step's evidence to determine pass/fail.

    Input: StepEvidence (what happened)
    Output: ClassificationResult (what it means)

    Implementations:
    - KeywordClassifier (simple pattern matching)
    - LLMClassifier (use another LLM to judge)
    - Future: MLClassifier (trained model)
    """

    async def classify(
        self, evidence: StepEvidence, attack_name: str
    ) -> ClassificationResult:
        """Analyze evidence and determine the outcome."""
        ...


@runtime_checkable
class ExecutionDispatcher(Protocol):
    """Dispatches execution steps from a plan.

    Input: ExecutionPlan + StepExecutor
    Output: list of StepEvidence

    Implementations:
    - InProcessDispatcher (sequential, same process)
    - Future: QueueDispatcher (distributed, worker-based)
    """

    async def dispatch(
        self,
        steps: list[StepContext],
        executor: StepExecutor,
    ) -> list[StepEvidence]:
        """Dispatch all steps and collect evidence."""
        ...
