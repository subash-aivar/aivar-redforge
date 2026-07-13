"""Domain exceptions for the Evidence bounded context."""

from redforge.core.exceptions import RedForgeError, ValidationError


class EvidenceError(RedForgeError):
    """Base exception for all Evidence domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="EVIDENCE_ERROR")


class EvidenceNotFoundError(EvidenceError):
    """Raised when Evidence cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Evidence '{identifier}' not found")
        self.error_code = "EVIDENCE_NOT_FOUND"


class EvidenceImmutableError(ValidationError):
    """Raised when attempting to modify finalized evidence.

    Evidence is append-only. Once finalized, it cannot be modified.
    This is a core architectural invariant.
    """

    def __init__(self, evidence_id: str) -> None:
        super().__init__(
            message=f"Evidence '{evidence_id}' is finalized and cannot be modified",
            details={"evidence_id": evidence_id},
        )


class EvidenceNotFinalizedError(ValidationError):
    """Raised when an operation requires finalized evidence."""

    def __init__(self, evidence_id: str) -> None:
        super().__init__(
            message=f"Evidence '{evidence_id}' has not been finalized",
            details={"evidence_id": evidence_id},
        )
