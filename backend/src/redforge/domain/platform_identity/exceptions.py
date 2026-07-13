"""Domain exceptions for the Platform Identity bounded context."""

from __future__ import annotations

from redforge.core.exceptions import RedForgeError


class PlatformAssignmentNotFoundError(RedForgeError):
    def __init__(self, assignment_id: str) -> None:
        super().__init__(
            message=f"Platform assignment '{assignment_id}' not found.",
            error_code="PLATFORM_ASSIGNMENT_NOT_FOUND",
        )
        self.assignment_id = assignment_id


class PlatformAssignmentAlreadyRevokedError(RedForgeError):
    def __init__(self, assignment_id: str) -> None:
        super().__init__(
            message=f"Platform assignment '{assignment_id}' is already revoked.",
            error_code="PLATFORM_ASSIGNMENT_ALREADY_REVOKED",
        )
        self.assignment_id = assignment_id


class DuplicateActivePlatformAssignmentError(RedForgeError):
    def __init__(self, user_id: str, role: str) -> None:
        super().__init__(
            message=(
                f"User '{user_id}' already has an active '{role}' "
                "platform assignment."
            ),
            error_code="PLATFORM_ASSIGNMENT_DUPLICATE_ACTIVE",
        )
        self.user_id = user_id
        self.role = role


class LastSuperAdminProtectionError(RedForgeError):
    def __init__(self, assignment_id: str) -> None:
        super().__init__(
            message=(
                "Cannot revoke this assignment: it is the last active "
                "PLATFORM_SUPER_ADMIN. Grant another Super Admin before "
                "revoking this one."
            ),
            error_code="PLATFORM_LAST_SUPER_ADMIN_PROTECTED",
        )
        self.assignment_id = assignment_id


class BootstrapDisabledError(RedForgeError):
    def __init__(self) -> None:
        super().__init__(
            message=(
                "Platform Super Admin bootstrap is not enabled on this "
                "server. Set REDFORGE_PLATFORM_BOOTSTRAP_ENABLED=true and "
                "REDFORGE_PLATFORM_BOOTSTRAP_PRINCIPAL_EMAIL to enable it."
            ),
            error_code="PLATFORM_BOOTSTRAP_DISABLED",
        )


class BootstrapAlreadyConsumedError(RedForgeError):
    def __init__(self) -> None:
        super().__init__(
            message=(
                "Platform Super Admin bootstrap has already been "
                "consumed. Ask an existing platform Super Admin to grant "
                "further platform access."
            ),
            error_code="PLATFORM_BOOTSTRAP_ALREADY_CONSUMED",
        )


class BootstrapPrincipalMismatchError(RedForgeError):
    def __init__(self) -> None:
        super().__init__(
            message=(
                "The authenticated principal does not match the "
                "server-configured bootstrap principal."
            ),
            error_code="PLATFORM_BOOTSTRAP_PRINCIPAL_MISMATCH",
        )


class NonGrantablePlatformRoleError(RedForgeError):
    def __init__(self, role: str) -> None:
        super().__init__(
            message=(
                f"Platform role '{role}' cannot be granted yet — its "
                "permission workflow has not shipped."
            ),
            error_code="PLATFORM_ROLE_NOT_GRANTABLE",
        )
        self.role = role
