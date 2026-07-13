"""Validation Orchestrator — thin coordination service.

Wires together existing domain objects for runtime execution:
1. Resolves policy → attack IDs
2. Builds step contexts from attacks + target
3. Dispatches steps via ExecutionDispatcher
4. Classifies evidence via ResponseClassifier
5. Produces findings from failed classifications
6. Returns execution summary

Contains ZERO business logic. Only coordination.
Business rules live in domain entities (ValidationRun, Evidence, Finding).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from redforge.application.runtime.contracts import (
    ClassificationResult,
    ExecutionDispatcher,
    ResponseClassifier,
    StepContext,
    StepEvidence,
    StepExecutor,
)
from redforge.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    """Input to the orchestrator — what to execute."""

    run_id: str
    policy_id: str
    target_id: str
    target_endpoint: str
    target_provider: str
    attack_steps: list[AttackStep]
    timeout_seconds: int = 60


@dataclass(frozen=True, slots=True)
class AttackStep:
    """One attack to execute (resolved from policy)."""

    attack_id: str
    attack_name: str
    payload_content: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """Combined result of execution + classification for one step."""

    step_id: str
    attack_id: str
    attack_name: str
    evidence: StepEvidence
    classification: ClassificationResult


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Complete output of the orchestrator."""

    run_id: str
    total_steps: int
    passed: int
    failed: int
    errors: int
    inconclusive: int
    duration_ms: int
    outcomes: list[StepOutcome]

    @property
    def pass_rate(self) -> float:
        if self.total_steps == 0:
            return 0.0
        return (self.passed / self.total_steps) * 100.0


class ValidationOrchestrator:
    """Thin orchestration service coordinating the execution pipeline.

    Does NOT contain business logic. Coordinates:
    - StepExecutor (runs one attack)
    - ExecutionDispatcher (sequences multiple steps)
    - ResponseClassifier (determines pass/fail)

    All three are injected via protocols — replaceable.
    """

    def __init__(
        self,
        dispatcher: ExecutionDispatcher,
        executor: StepExecutor,
        classifier: ResponseClassifier,
    ) -> None:
        self._dispatcher = dispatcher
        self._executor = executor
        self._classifier = classifier

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a validation run end-to-end.

        Steps:
        1. Build step contexts from request
        2. Dispatch steps (sequential in-process for now)
        3. Classify each evidence result
        4. Aggregate into ExecutionResult
        """
        import time

        start = time.perf_counter()

        # 1. Build step contexts
        step_contexts = self._build_contexts(request)

        logger.info(
            "orchestrator_started",
            run_id=request.run_id,
            step_count=len(step_contexts),
            target_id=request.target_id,
        )

        # 2. Dispatch and collect evidence
        evidence_list = await self._dispatcher.dispatch(
            step_contexts, self._executor
        )

        # 3. Classify each result
        outcomes: list[StepOutcome] = []
        for i, evidence in enumerate(evidence_list):
            attack_name = (
                request.attack_steps[i].attack_name
                if i < len(request.attack_steps)
                else "unknown"
            )

            if evidence.is_error:
                classification = ClassificationResult(
                    outcome="error",
                    confidence=1.0,
                    reasoning=evidence.error,
                )
            else:
                classification = await self._classifier.classify(
                    evidence, attack_name
                )

            outcomes.append(StepOutcome(
                step_id=evidence.step_id,
                attack_id=evidence.attack_id,
                attack_name=attack_name,
                evidence=evidence,
                classification=classification,
            ))

        # 4. Aggregate
        duration_ms = int((time.perf_counter() - start) * 1000)
        passed = sum(1 for o in outcomes if o.classification.outcome == "pass")
        failed = sum(1 for o in outcomes if o.classification.outcome == "fail")
        errors = sum(1 for o in outcomes if o.classification.outcome == "error")
        inconclusive = sum(
            1 for o in outcomes if o.classification.outcome == "inconclusive"
        )

        logger.info(
            "orchestrator_completed",
            run_id=request.run_id,
            total=len(outcomes),
            passed=passed,
            failed=failed,
            errors=errors,
            duration_ms=duration_ms,
        )

        return ExecutionResult(
            run_id=request.run_id,
            total_steps=len(outcomes),
            passed=passed,
            failed=failed,
            errors=errors,
            inconclusive=inconclusive,
            duration_ms=duration_ms,
            outcomes=outcomes,
        )

    def _build_contexts(self, request: ExecutionRequest) -> list[StepContext]:
        """Transform AttackSteps into executable StepContexts."""
        contexts: list[StepContext] = []
        for i, step in enumerate(request.attack_steps):
            contexts.append(StepContext(
                step_id=f"{request.run_id}-step-{i}",
                attack_id=step.attack_id,
                attack_name=step.attack_name,
                target_id=request.target_id,
                target_endpoint=request.target_endpoint,
                target_provider=request.target_provider,
                payload_content=step.payload_content,
                timeout_seconds=request.timeout_seconds,
                metadata=step.metadata,
            ))
        return contexts
