"""Domain exceptions for the RBAC (custom role/group) bounded context."""

from redforge.core.exceptions import ConflictError, RedForgeError, ValidationError


class RbacError(RedForgeError):
    """Base exception for all RBAC domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="RBAC_ERROR")


class RoleNotFoundError(RbacError):
    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Role '{identifier}' not found")
        self.error_code = "ROLE_NOT_FOUND"


class GroupNotFoundError(RbacError):
    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Group '{identifier}' not found")
        self.error_code = "GROUP_NOT_FOUND"


class DuplicateRoleNameError(ConflictError):
    def __init__(self, name: str) -> None:
        super().__init__(message=f"A role named '{name}' already exists in this organization")


class DuplicateGroupNameError(ConflictError):
    def __init__(self, name: str) -> None:
        super().__init__(message=f"A group named '{name}' already exists in this organization")


class SystemRoleImmutableError(ValidationError):
    def __init__(self) -> None:
        super().__init__(
            message="System roles cannot be modified, have permissions changed, or be deleted"
        )


class UnknownPermissionError(ValidationError):
    def __init__(self, value: str) -> None:
        super().__init__(message=f"'{value}' is not a recognized permission")


class PrivilegeEscalationError(ValidationError):
    """Raised when an actor attempts to grant a permission they do not
    themselves hold (bounded delegation — see application/rbac/grant_policy.py)."""

    def __init__(self, permission: str) -> None:
        super().__init__(
            message=f"Cannot grant permission '{permission}': you do not hold it yourself"
        )


class RoleHasActiveAssignmentsError(ValidationError):
    def __init__(self, role_id: str) -> None:
        super().__init__(
            message=f"Role '{role_id}' has active user/group assignments and cannot be deleted"
        )


class GroupHasMembersError(ValidationError):
    def __init__(self, group_id: str) -> None:
        super().__init__(message=f"Group '{group_id}' has active members and cannot be deleted")
