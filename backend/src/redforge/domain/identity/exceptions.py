"""Domain exceptions for the Identity bounded context.

These exceptions represent business rule violations specific to users,
memberships, and access control. They inherit from the platform-wide
RedForgeError hierarchy.
"""

from redforge.core.exceptions import ConflictError, RedForgeError, ValidationError


class IdentityError(RedForgeError):
    """Base exception for all Identity domain errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, error_code="IDENTITY_ERROR")


class UserNotFoundError(IdentityError):
    """Raised when a User cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"User '{identifier}' not found")
        self.error_code = "USER_NOT_FOUND"


class UserAlreadyExistsError(ConflictError):
    """Raised when attempting to register a user with an email that already exists."""

    def __init__(self, email: str) -> None:
        super().__init__(message=f"User with email '{email}' already exists")
        self.email = email


class UserInactiveError(ValidationError):
    """Raised when an operation is attempted on an inactive user."""

    def __init__(self, user_id: str) -> None:
        super().__init__(
            message=f"User '{user_id}' is not active",
            details={"user_id": user_id},
        )


class InvalidUserTransitionError(ValidationError):
    """Raised when an invalid user status transition is attempted."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=f"Cannot transition user from '{current_status}' to '{target_status}'",
            details={"current_status": current_status, "target_status": target_status},
        )


class MembershipNotFoundError(IdentityError):
    """Raised when a Membership cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Membership '{identifier}' not found")
        self.error_code = "MEMBERSHIP_NOT_FOUND"


class MembershipAlreadyExistsError(ConflictError):
    """Raised when a user already has a membership in the organization."""

    def __init__(self, user_id: str, organization_id: str) -> None:
        super().__init__(
            message=(
                f"User '{user_id}' already has a membership "
                f"in organization '{organization_id}'"
            )
        )
        self.user_id = user_id
        self.organization_id = organization_id


class InsufficientPermissionError(RedForgeError):
    """Raised when a user lacks the required permission for an operation."""

    def __init__(self, permission: str) -> None:
        super().__init__(
            message=f"Insufficient permission: '{permission}' required",
            error_code="INSUFFICIENT_PERMISSION",
        )
        self.permission = permission


class MembershipNotActiveError(ValidationError):
    """Raised when an operation requires an ACTIVE membership but the
    membership is SUSPENDED or REMOVED."""

    def __init__(self, membership_id: str, status: str) -> None:
        super().__init__(
            message=f"Membership '{membership_id}' is not active (status: {status})",
            details={"membership_id": membership_id, "status": status},
        )


class LastOwnerError(ValidationError):
    """Raised when an operation would leave an Organization with zero
    active OWNER memberships — e.g. removing, suspending, or demoting
    the sole remaining owner without first transferring ownership."""

    def __init__(self, organization_id: str, operation: str) -> None:
        super().__init__(
            message=(
                f"Cannot {operation}: organization '{organization_id}' would be "
                f"left with no owner. Transfer ownership first."
            ),
            details={"organization_id": organization_id, "operation": operation},
        )


class SelfPrivilegeEscalationError(ValidationError):
    """Raised when a user attempts to change their own role or status —
    role/status changes must always be performed by a different member
    with sufficient privilege, never by the acting user on themselves."""

    def __init__(self, user_id: str, operation: str) -> None:
        super().__init__(
            message=f"Users cannot {operation} their own membership",
            details={"user_id": user_id, "operation": operation},
        )


class OwnerAssignmentNotAllowedError(ValidationError):
    """Raised when a caller attempts to assign the OWNER role through any
    path other than MembershipService.transfer_ownership().

    OWNER can only ever be granted by transfer_ownership(), which
    atomically promotes the new owner and demotes the previous one in the
    same transaction. Every other path that can set a role — the generic
    change_role() workflow, and inviting a new member directly as OWNER —
    has no such atomicity guarantee and would let a caller create a
    second OWNER without demoting anyone, breaking the
    single-owner-at-a-time invariant the rest of the system (ownership
    transfer, last-owner protection) relies on.

    Raised from two call sites: MembershipService.change_role (target is
    a membership_id) and InvitationService.invite (target is the
    invitation's intended email) — the `context` field distinguishes
    them for callers/logs.
    """

    def __init__(self, target_identifier: str, *, context: str = "membership") -> None:
        super().__init__(
            message=(
                f"Cannot assign OWNER role to {context} '{target_identifier}'. "
                "Use transfer_ownership instead."
            ),
            details={"target_identifier": target_identifier, "context": context},
        )


class InvitationNotFoundError(IdentityError):
    """Raised when an Invitation cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(message=f"Invitation '{identifier}' not found")
        self.error_code = "INVITATION_NOT_FOUND"


class InvitationExpiredError(ValidationError):
    """Raised when acting on an Invitation past its expiration."""

    def __init__(self, invitation_id: str) -> None:
        super().__init__(
            message=f"Invitation '{invitation_id}' has expired",
            details={"invitation_id": invitation_id},
        )


class InvitationAlreadyProcessedError(ConflictError):
    """Raised when acting on an Invitation that is no longer PENDING
    (already accepted, rejected, or revoked) by a DIFFERENT actor/outcome
    than the one being requested — see Invitation.accept's idempotency
    note for the one case this is deliberately NOT raised."""

    def __init__(self, invitation_id: str, status: str) -> None:
        super().__init__(
            message=f"Invitation '{invitation_id}' was already {status}",
        )
        self.invitation_id = invitation_id
        self.status = status


class DuplicateInvitationError(ConflictError):
    """Raised when a PENDING invitation already exists for this
    (organization, email) pair — callers should resend the existing
    invitation instead of creating a new one."""

    def __init__(self, organization_id: str, email: str) -> None:
        super().__init__(
            message=(
                f"A pending invitation for '{email}' already exists in "
                f"organization '{organization_id}'"
            ),
        )
        self.organization_id = organization_id
        self.email = email


class InvitationEmailMismatchError(ValidationError):
    """Raised when the accepting user's email does not match the
    invitation's target email — prevents one user from consuming an
    invitation addressed to someone else."""

    def __init__(self, invitation_id: str) -> None:
        super().__init__(
            message=f"Invitation '{invitation_id}' was not addressed to this account",
            details={"invitation_id": invitation_id},
        )
