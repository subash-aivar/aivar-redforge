"""Domain exceptions for the Attack Path Engine — M22 Phase 5."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, ValidationError


class InvalidPathConfidenceError(ValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid path confidence: {raw!r}")


class PathExplosionExceededError(ValidationError):
    pass


class InvalidPathStatusTransitionError(ConflictError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(
            f"Invalid attack-path status transition: {from_status} -> {to_status}"
        )


class AttackPathSeedInvalidError(ValidationError):
    pass


class InferenceGateRejectedError(ValidationError):
    pass


class AttackPathComputeBudgetExceededError(ValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Attack path compute budget exceeded: {reason}")
