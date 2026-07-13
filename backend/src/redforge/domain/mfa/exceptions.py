from __future__ import annotations

from redforge.core.exceptions import RedForgeError


class MFAFactorNotFoundError(RedForgeError):
    def __init__(self, user_id: str) -> None:
        super().__init__(
            message=f"No MFA factor found for user '{user_id}'.",
            error_code="MFA_FACTOR_NOT_FOUND",
        )


class MFAEnrollmentNotFoundError(RedForgeError):
    def __init__(self) -> None:
        super().__init__(
            message="No pending MFA enrollment found. Begin enrollment first.",
            error_code="MFA_ENROLLMENT_NOT_FOUND",
        )


class MFAInvalidCodeError(RedForgeError):
    def __init__(self) -> None:
        super().__init__(
            message="Invalid or expired verification code.",
            error_code="MFA_INVALID_CODE",
        )


class MFAAlreadyActiveError(RedForgeError):
    def __init__(self) -> None:
        super().__init__(
            message=(
                "An active MFA factor already exists for this user. "
                "Revoke it before re-enrolling."
            ),
            error_code="MFA_ALREADY_ACTIVE",
        )


class MFANotActiveError(RedForgeError):
    def __init__(self) -> None:
        super().__init__(
            message="No active MFA factor exists for this user.",
            error_code="MFA_NOT_ACTIVE",
        )


class PrivilegedAssuranceRequiredError(RedForgeError):
    """Raised when a privileged platform mutation is attempted without a
    current, valid step-up assurance token. Distinct error_code so the
    frontend can route the user into the step-up flow rather than
    showing a generic permission-denied message.
    """

    def __init__(self) -> None:
        super().__init__(
            message=(
                "This action requires a current privileged authentication "
                "assurance. Complete MFA step-up verification and retry."
            ),
            error_code="MFA_ASSURANCE_REQUIRED",
        )


class PrivilegedAssuranceExpiredError(RedForgeError):
    def __init__(self) -> None:
        super().__init__(
            message="Your privileged authentication assurance has expired. Verify again.",
            error_code="MFA_ASSURANCE_EXPIRED",
        )
