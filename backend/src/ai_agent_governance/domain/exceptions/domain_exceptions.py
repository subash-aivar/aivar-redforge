from __future__ import annotations


class AgentGovernanceDomainError(Exception):
    pass


class TenantMismatch(AgentGovernanceDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class InvalidEnvelopeTransition(AgentGovernanceDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid envelope transition {from_state} -> {to_state}")


class EnvelopeActivationRequirements(AgentGovernanceDomainError):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)


class HumanApprovalCategoryLocked(AgentGovernanceDomainError):
    def __init__(self) -> None:
        super().__init__("RequiresHumanApprovalFor removal requires ai_posture:admin sign-off")


class DeviationImmutable(AgentGovernanceDomainError):
    def __init__(self) -> None:
        super().__init__("Deviation event core fields are immutable after creation")


class InvalidReviewTransition(AgentGovernanceDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid review transition {from_state} -> {to_state}")


class ReviewNotesRequired(AgentGovernanceDomainError):
    def __init__(self) -> None:
        super().__init__("ConfirmedBenign requires non-null ReviewNotes")


class EnvelopeRevisionLinkRequired(AgentGovernanceDomainError):
    def __init__(self) -> None:
        super().__init__(
            "ReviewState=EnvelopeUpdated requires linked AgentOperationalEnvelopeRevised"
        )


class DuplicateActionReport(AgentGovernanceDomainError):
    def __init__(self, key: str) -> None:
        super().__init__(f"Duplicate idempotency key: {key}")
