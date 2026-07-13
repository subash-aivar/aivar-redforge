"""Domain exceptions for the Prompt & Payload Engine."""

from redforge.core.exceptions import RedForgeError, ValidationError


class PayloadError(RedForgeError):
    """Base exception for all Payload Engine errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="PAYLOAD_ERROR")


class TemplateNotFoundError(PayloadError):
    """Raised when a template cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Template '{identifier}' not found")
        self.error_code = "TEMPLATE_NOT_FOUND"


class TemplateRenderError(ValidationError):
    """Raised when a template cannot be rendered (missing variables, etc.)."""

    def __init__(self, template_id: str, reason: str) -> None:
        super().__init__(
            message=f"Failed to render template '{template_id}': {reason}",
            details={"template_id": template_id, "reason": reason},
        )


class InvalidTemplateTransitionError(ValidationError):
    """Raised when an invalid template status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition template from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class TemplateArchivedError(ValidationError):
    """Raised when modifying an archived template."""

    def __init__(self, template_id: str) -> None:
        super().__init__(
            message=f"Template '{template_id}' is archived",
            details={"template_id": template_id},
        )
