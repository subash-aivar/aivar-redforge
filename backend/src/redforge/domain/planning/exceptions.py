"""Domain exceptions for the Attack Planning & Strategy bounded context."""

from redforge.core.exceptions import NotFoundError, RedForgeError, ValidationError


class PlanningError(RedForgeError):
    """Base exception for all Attack Planning domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="PLANNING_ERROR")


class AttackPlanNotFoundError(NotFoundError):
    """Raised when an attack plan cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(resource="AttackPlan", identifier=identifier)


class EmptyPlanError(ValidationError):
    """Raised when attempting to create a plan with zero steps.

    A plan with no attacks selected is not a valid outcome of planning
    — it's either "nothing was compatible" (which callers must decide
    how to handle explicitly) or a bug in selection, never a silently
    accepted empty plan.
    """

    def __init__(self, target_id: str) -> None:
        super().__init__(
            message=f"Cannot create an AttackPlan with zero steps for target '{target_id}'",
            details={"target_id": target_id},
        )


class AttackPlanCycleError(ValidationError):
    """Raised when a proposed attack sequence's dependency graph
    contains a cycle — cannot be topologically ordered."""

    def __init__(self, target_id: str, detail: str) -> None:
        super().__init__(
            message=f"Cannot build AttackPlan for target '{target_id}': {detail}",
            details={"target_id": target_id, "detail": detail},
        )


class PlanAlreadySupersededError(ValidationError):
    """Raised when attempting to supersede an already-superseded plan."""

    def __init__(self, plan_id: str) -> None:
        super().__init__(
            message=f"AttackPlan '{plan_id}' is already superseded",
            details={"plan_id": plan_id},
        )


class NoCompatibleAttacksError(PlanningError):
    """Raised by selection when zero candidate attacks survive
    capability/criteria filtering — a distinct, more diagnosable
    signal than a generic EmptyPlanError, since it specifically means
    "the taxonomy had candidates, but none matched this target."""

    def __init__(self, target_id: str, capability_summary: str) -> None:
        super().__init__(
            f"No compatible attacks found for target '{target_id}' "
            f"given available capabilities: {capability_summary}"
        )
        self.error_code = "NO_COMPATIBLE_ATTACKS"
        self.target_id = target_id


class PlanningStrategyNotImplementedError(PlanningError):
    """Raised for PlanningStrategy members declared but not yet backed
    by a working StrategyProtocol implementation (MULTI_TURN, AUTONOMOUS
    — see PlanningStrategy's docstring). This is a deliberate, explicit
    "not yet" signal, distinct from a silent no-op or a generic
    NotImplementedError that would be indistinguishable from a real bug.
    """

    def __init__(self, strategy: str) -> None:
        super().__init__(
            f"PlanningStrategy '{strategy}' has no implementation yet — "
            "reserved for future adaptive/autonomous planning"
        )
        self.error_code = "PLANNING_STRATEGY_NOT_IMPLEMENTED"
        self.strategy = strategy
