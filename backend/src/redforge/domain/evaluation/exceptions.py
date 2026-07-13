"""Domain exceptions for the Response Evaluation Intelligence bounded context."""

from redforge.core.exceptions import NotFoundError, RedForgeError, ValidationError


class EvaluationError(RedForgeError):
    """Base exception for all Evaluation domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="EVALUATION_ERROR")


class EvaluationResultNotFoundError(NotFoundError):
    """Raised when an evaluation result cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(resource="EvaluationResult", identifier=identifier)


class EmptyEvaluationTrailError(ValidationError):
    """Raised when attempting to create an EvaluationResult with zero
    EvaluationEvidence entries — an evaluation with no evaluator having
    run is not a valid outcome, it means the pipeline was misconfigured
    (no evaluators registered for the relevant stages)."""

    def __init__(self, attack_id: str) -> None:
        super().__init__(
            message=(
                f"Cannot create an EvaluationResult with zero evaluation "
                f"evidence for attack '{attack_id}' — no evaluator produced "
                f"a result"
            ),
            details={"attack_id": attack_id},
        )


class EvaluationAlreadySupersededError(ValidationError):
    """Raised when attempting to supersede an already-superseded result."""

    def __init__(self, evaluation_id: str) -> None:
        super().__init__(
            message=f"EvaluationResult '{evaluation_id}' is already superseded",
            details={"evaluation_id": evaluation_id},
        )


class NoEvaluatorsConfiguredError(EvaluationError):
    """Raised when EvaluationEngine.evaluate() is invoked with zero
    evaluators registered for every stage (Rule, Semantic, Pattern) —
    distinct from EmptyEvaluationTrailError, which is the domain
    aggregate's own construction-time guard; this is the earlier,
    more specific signal that the *pipeline itself* has nothing to run,
    not just that a particular run happened to produce no evidence."""

    def __init__(self) -> None:
        super().__init__(
            "EvaluationEngine has no evaluators configured for any stage "
            "(rule, semantic, or pattern) — nothing to run"
        )
        self.error_code = "NO_EVALUATORS_CONFIGURED"
