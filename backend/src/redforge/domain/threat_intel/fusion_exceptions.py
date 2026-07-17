"""Domain exceptions for Threat Fusion — M22 Phase 4."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, ValidationError


class InvalidFusionWeightError(ValidationError):
    pass


class InvalidFusionConfidenceError(ValidationError):
    pass


class InvalidIndicatorCanonicalKeyError(ValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(
            f"Invalid fused indicator canonical key: {raw!r} — expected "
            "'{type}:{normalized_value}' with a known FusedIndicatorType prefix"
        )


class InvalidIndicatorLifecycleTransitionError(ConflictError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(
            f"Invalid fused-indicator lifecycle transition: {from_status} -> {to_status}"
        )


class FusionBatchTooLargeError(ValidationError):
    def __init__(self, size: int, maximum: int) -> None:
        super().__init__(
            f"Fusion batch size {size} exceeds maximum of {maximum} indicators"
        )
