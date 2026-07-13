"""Domain exceptions for the Security Authorization bounded context (M10)."""

from redforge.core.exceptions import RedForgeError, ValidationError


class SecurityAuthorizationError(RedForgeError):
    """Base exception for all Security Authorization domain errors."""

    def __init__(self, message: str, error_code: str = "AUTHORIZATION_ERROR") -> None:
        super().__init__(message=message, error_code=error_code)


class SecurityAuthorizationNotFoundError(SecurityAuthorizationError):
    """Raised when a SecurityAuthorization cannot be located."""

    def __init__(self, identifier: str) -> None:
        super().__init__(
            message=f"Security authorization '{identifier}' not found",
            error_code="AUTHORIZATION_NOT_FOUND",
        )


class InvalidAuthorizationTransitionError(ValidationError):
    """Raised when an illegal SecurityAuthorization lifecycle transition
    is attempted. The lifecycle graph is fixed — see
    AuthorizationStatus's docstring — there is no code path that can
    mutate status outside SecurityAuthorization's own methods."""

    def __init__(self, current_status: str, target_status: str) -> None:
        super().__init__(
            message=(
                f"Cannot transition authorization from '{current_status}' "
                f"to '{target_status}'"
            ),
            details={"current_status": current_status, "target_status": target_status},
        )


class EmptyAuthorizationScopeError(ValidationError):
    """Raised when submitting an authorization with no scope entities or
    no action classes for approval."""

    def __init__(self, authorization_id: str) -> None:
        super().__init__(
            message=(
                f"Authorization '{authorization_id}' must have at least one "
                "scope entity and one action class before submission"
            ),
            details={"authorization_id": authorization_id},
        )


class ApprovalAlreadyDecidedError(ValidationError):
    """Raised when attempting to decide an AuthorizationApproval that has
    already been decided. Approval history is immutable — never
    overwritten in place. This is also the error surfaced when two
    concurrent approve()/reject() calls race: with a locked read (see
    SqlAlchemyAuthorizationApprovalRepository.get_by_authorization_id_for_update),
    the loser of the race observes the winner's already-decided state
    and raises this instead of silently overwriting it."""

    def __init__(self, approval_id: str, existing_decision: str) -> None:
        super().__init__(
            message=(
                f"Approval '{approval_id}' has already been decided "
                f"({existing_decision}) and cannot be re-decided"
            ),
            details={"approval_id": approval_id, "existing_decision": existing_decision},
        )


class SelfApprovalForbiddenError(ValidationError):
    """Raised when the requester attempts to approve or reject their own
    authorization. Unconditional — no role or permission overrides this,
    including Super Admin (see M10 brief section 5)."""

    def __init__(self, authorization_id: str) -> None:
        super().__init__(
            message=f"The requester of authorization '{authorization_id}' cannot approve it",
            details={"authorization_id": authorization_id},
        )


class UnknownActionClassError(ValidationError):
    """Raised when a requested action class string does not match any
    member of the closed ActionClass taxonomy. Callers (application
    layer / ExecutionPolicyService) must treat this as a fail-safe DENY,
    never as a 500 error that could be mistaken for an outage."""

    def __init__(self, raw_value: str) -> None:
        super().__init__(
            message=f"Unknown action class: '{raw_value}'",
            details={"action_class": raw_value},
        )


class NonCanonicalScopeEntityError(ValidationError):
    """Raised when a scope entity does not resolve to a real, same-tenant
    canonical entity at creation time."""

    def __init__(self, entity_type: str, entity_id: str) -> None:
        super().__init__(
            message=(
                f"'{entity_type}:{entity_id}' does not resolve to a canonical "
                "entity owned by this organization"
            ),
            details={"entity_type": entity_type, "entity_id": entity_id},
        )


class ExecutionNotAuthorizedError(SecurityAuthorizationError):
    """Raised by execution dispatch boundaries (e.g. CampaignEngine) when
    ExecutionPolicyService does not return ALLOW. Carries the reason
    code so callers can distinguish DENY from APPROVAL_REQUIRED without
    parsing message text."""

    def __init__(self, decision: str, reason_code: str) -> None:
        super().__init__(
            message=f"Execution not authorized: {decision} ({reason_code})",
            error_code=reason_code,
        )
        self.decision = decision
        self.reason_code = reason_code
