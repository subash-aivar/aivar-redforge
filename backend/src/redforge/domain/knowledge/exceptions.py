"""Domain exceptions for the Knowledge bounded context."""

from redforge.core.exceptions import RedForgeError, ValidationError


class KnowledgeError(RedForgeError):
    """Base exception for all Knowledge domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="KNOWLEDGE_ERROR")


class KnowledgeNotFoundError(KnowledgeError):
    """Raised when a Knowledge item cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Knowledge item '{identifier}' not found")
        self.error_code = "KNOWLEDGE_NOT_FOUND"


class InvalidKnowledgeTransitionError(ValidationError):
    """Raised when an invalid knowledge status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition knowledge item from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class KnowledgeArchivedError(ValidationError):
    """Raised when modifying an archived knowledge item."""

    def __init__(self, item_id: str) -> None:
        super().__init__(
            message=f"Knowledge item '{item_id}' is archived",
            details={"item_id": item_id},
        )
