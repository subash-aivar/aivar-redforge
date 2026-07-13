"""In-process execution dispatcher.

Traverses steps sequentially within a single process.
This is the reference implementation — future distributed
dispatchers will replace this with queue-based execution.

The dispatcher's interface is protocol-based, so swapping to
Redis/SQS/Kafka workers requires only a new implementation.
"""

from __future__ import annotations

from redforge.application.runtime.contracts import (
    StepContext,
    StepEvidence,
    StepExecutor,
)
from redforge.core.logging import get_logger

logger = get_logger(__name__)


class InProcessDispatcher:
    """Sequential in-process step dispatcher.

    Executes steps one at a time in the current process.
    Captures errors without stopping the entire batch
    (individual step failures are recorded in StepEvidence).
    """

    async def dispatch(
        self,
        steps: list[StepContext],
        executor: StepExecutor,
    ) -> list[StepEvidence]:
        """Execute all steps sequentially, collecting evidence."""
        results: list[StepEvidence] = []

        for step in steps:
            logger.info(
                "step_dispatched",
                step_id=step.step_id,
                attack_id=step.attack_id,
                target_id=step.target_id,
            )
            try:
                evidence = await executor.execute(step)
            except Exception as exc:
                logger.warning(
                    "step_execution_error",
                    step_id=step.step_id,
                    error=str(exc),
                )
                evidence = StepEvidence(
                    step_id=step.step_id,
                    attack_id=step.attack_id,
                    target_id=step.target_id,
                    request_method="POST",
                    request_url=step.target_endpoint,
                    request_body=step.payload_content,
                    response_status=0,
                    response_body="",
                    duration_ms=0,
                    error=f"{type(exc).__name__}: {exc}",
                )
            results.append(evidence)

        return results
