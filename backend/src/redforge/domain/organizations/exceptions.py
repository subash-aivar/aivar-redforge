"""Domain exceptions for the Organization bounded context.

These exceptions represent business rule violations specific to Organizations.
They inherit from the platform-wide RedForgeError hierarchy and carry semantic
meaning that the infrastructure layer maps to appropriate responses.
"""

from redforge.core.exceptions import ConflictError, RedForgeError, ValidationError


class OrganizationError(RedForgeError):
    """Base exception for all Organization domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="ORGANIZATION_ERROR")


class OrganizationNotFoundError(OrganizationError):
    """Raised when an Organization cannot be located by its identifier or slug."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Organization '{identifier}' not found")
        self.error_code = "ORGANIZATION_NOT_FOUND"


class OrganizationSlugTakenError(ConflictError):
    """Raised when an Organization slug is already in use."""

    def __init__(self, slug: str) -> None:
        super().__init__(message=f"Organization slug '{slug}' is already taken")
        self.slug = slug


class OrganizationInactiveError(ValidationError):
    """Raised when an operation is attempted on an inactive Organization."""

    def __init__(self, organization_id: str) -> None:
        super().__init__(
            message=f"Organization '{organization_id}' is not active",
            details={"organization_id": organization_id},
        )


class InvalidOrganizationTransitionError(ValidationError):
    """Raised when an invalid status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition organization from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )
