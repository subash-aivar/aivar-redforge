"""Domain exceptions for the Compliance bounded context."""

from __future__ import annotations


class ComplianceDomainError(Exception):
    """Base for all compliance domain errors."""


class FrameworkNotFoundError(ComplianceDomainError):
    def __init__(self, framework_key: str) -> None:
        super().__init__(f"Framework not found: '{framework_key}'")
        self.framework_key = framework_key


class FrameworkAlreadyPublishedError(ComplianceDomainError):
    def __init__(self, framework_key: str) -> None:
        super().__init__(f"Framework '{framework_key}' is already published")
        self.framework_key = framework_key


class FrameworkRetiredError(ComplianceDomainError):
    """Raised when attempting to publish a previously retired framework."""

    def __init__(self, framework_key: str) -> None:
        super().__init__(
            f"Framework '{framework_key}' is retired and cannot be re-published. "
            "Create a new framework version instead."
        )
        self.framework_key = framework_key


class ControlRequirementNotFoundError(ComplianceDomainError):
    def __init__(self, requirement_id: str) -> None:
        super().__init__(f"ControlRequirement not found: '{requirement_id}'")
        self.requirement_id = requirement_id


class ControlMappingNotFoundError(ComplianceDomainError):
    def __init__(self, source_id: str, target_id: str) -> None:
        super().__init__(
            f"No active mapping between '{source_id}' and '{target_id}'"
        )
        self.source_id = source_id
        self.target_id = target_id


class DuplicateControlMappingError(ComplianceDomainError):
    def __init__(self, source_id: str, target_id: str) -> None:
        super().__init__(
            f"An active mapping between '{source_id}' and '{target_id}' already exists"
        )
        self.source_id = source_id
        self.target_id = target_id


class CrossFrameworkMappingRequiredError(ComplianceDomainError):
    """Raised when source and target controls belong to the same framework."""

    def __init__(self, framework_key: str) -> None:
        super().__init__(
            f"A ControlMapping must relate controls from different frameworks; "
            f"both controls belong to '{framework_key}'"
        )
        self.framework_key = framework_key


class CatalogIntegrityError(ComplianceDomainError):
    """Raised by CatalogIntegrityValidator when the catalog is inconsistent."""


# ─── M24 Phase 2 — Organization Assessment ───────────────────────────────────


class ControlAssessmentInvariantError(ComplianceDomainError):
    """Raised when an assessment aggregate invariant is violated."""


class ProfileNotFoundError(ComplianceDomainError):
    def __init__(self, profile_id: str) -> None:
        super().__init__(f"ComplianceProfile not found: '{profile_id}'")
        self.profile_id = profile_id


class ProfileNotActiveError(ComplianceDomainError):
    def __init__(self, profile_id: str, detail: str) -> None:
        super().__init__(f"ComplianceProfile '{profile_id}' is not active: {detail}")
        self.profile_id = profile_id


class AssessmentPeriodNotFoundError(ComplianceDomainError):
    def __init__(self, period_id: str) -> None:
        super().__init__(f"AssessmentPeriod not found: '{period_id}'")
        self.period_id = period_id


class AssessmentPeriodNotOpenError(ComplianceDomainError):
    def __init__(self, period_id: str, detail: str) -> None:
        super().__init__(f"AssessmentPeriod '{period_id}' is not open: {detail}")
        self.period_id = period_id


class ControlAssessmentNotFoundError(ComplianceDomainError):
    def __init__(self, assessment_id: str) -> None:
        super().__init__(f"ControlAssessment not found: '{assessment_id}'")
        self.assessment_id = assessment_id


class DuplicateControlAssessmentError(ComplianceDomainError):
    def __init__(self, period_id: str, requirement_id: str) -> None:
        super().__init__(
            f"ControlAssessment already exists for period '{period_id}' "
            f"and requirement '{requirement_id}'"
        )
        self.period_id = period_id
        self.requirement_id = requirement_id


class DuplicateEvidenceLinkError(ComplianceDomainError):
    def __init__(self, evidence_id: str) -> None:
        super().__init__(
            f"Evidence '{evidence_id}' is already confirmed on this assessment"
        )
        self.evidence_id = evidence_id


class InvalidControlStatusTransitionError(ComplianceDomainError):
    def __init__(self, current: str, target: str, reason: str) -> None:
        super().__init__(
            f"Invalid ControlStatus transition '{current}' → '{target}': {reason}"
        )
        self.current = current
        self.target = target


class FrameworkNotInProfileError(ComplianceDomainError):
    def __init__(self, framework_key: str, profile_id: str) -> None:
        super().__init__(
            f"Framework '{framework_key}' is not selected on profile '{profile_id}'"
        )
        self.framework_key = framework_key
        self.profile_id = profile_id


class EvidenceReferenceNotFoundError(ComplianceDomainError):
    """Raised when a confirmed evidence_id does not resolve in-tenant."""

    def __init__(self, evidence_id: str) -> None:
        super().__init__(
            f"Evidence reference '{evidence_id}' was not found for this organization"
        )
        self.evidence_id = evidence_id


class AssessmentPeriodCloseBlockedError(ComplianceDomainError):
    """Raised when closing a period that still has incomplete assessments."""

    def __init__(
        self,
        period_id: str,
        incomplete_assessment_ids: tuple[str, ...],
    ) -> None:
        ids = ", ".join(incomplete_assessment_ids) or "(none)"
        super().__init__(
            f"AssessmentPeriod '{period_id}' cannot close: "
            f"ControlAssessment(s) not technically_validated: {ids}"
        )
        self.period_id = period_id
        self.incomplete_assessment_ids = incomplete_assessment_ids


class DuplicateActiveProfileFrameworkError(ComplianceDomainError):
    """Raised when activating a profile that shares a framework with another active profile."""

    def __init__(
        self,
        organization_id: str,
        framework_key: str,
        existing_profile_id: str,
    ) -> None:
        super().__init__(
            f"Organization '{organization_id}' already has an active ComplianceProfile "
            f"('{existing_profile_id}') for framework '{framework_key}'"
        )
        self.organization_id = organization_id
        self.framework_key = framework_key
        self.existing_profile_id = existing_profile_id


# ─── M24 Phase 3 — Evidence Recommendation ────────────────────────────────────


class RecommendationInvariantError(ComplianceDomainError):
    """Raised when a recommendation aggregate invariant is violated."""


class RecommendationNotFoundError(ComplianceDomainError):
    def __init__(self, recommendation_id: str) -> None:
        super().__init__(f"EvidenceRecommendation not found: '{recommendation_id}'")
        self.recommendation_id = recommendation_id


class RecommendationBatchNotFoundError(ComplianceDomainError):
    def __init__(self, batch_id: str) -> None:
        super().__init__(f"RecommendationBatch not found: '{batch_id}'")
        self.batch_id = batch_id


class InvalidRecommendationTransitionError(ComplianceDomainError):
    def __init__(
        self,
        current: str,
        target: str,
        *,
        reason: str = "",
    ) -> None:
        detail = f": {reason}" if reason else ""
        super().__init__(
            f"Invalid recommendation transition '{current}' → '{target}'{detail}"
        )
        self.current = current
        self.target = target


class DuplicateRecommendationError(ComplianceDomainError):
    def __init__(self, dedup_key: str, existing_id: str) -> None:
        super().__init__(
            f"Active recommendation already exists for '{dedup_key}' "
            f"(existing id '{existing_id}')"
        )
        self.dedup_key = dedup_key
        self.existing_id = existing_id


class RecommendationNotLinkableError(ComplianceDomainError):
    """Raised when accept→link is requested for a non-linkable source kind."""

    def __init__(self, recommendation_id: str, source_kind: str) -> None:
        super().__init__(
            f"Recommendation '{recommendation_id}' source kind '{source_kind}' "
            "cannot create a ConfirmedEvidenceLink — only validation_evidence "
            "and confirmed_control_evidence references are linkable"
        )
        self.recommendation_id = recommendation_id
        self.source_kind = source_kind


class RecommendationNotAcceptedError(ComplianceDomainError):
    def __init__(self, recommendation_id: str, status: str) -> None:
        super().__init__(
            f"Recommendation '{recommendation_id}' must be accepted before linking "
            f"(current status: '{status}')"
        )
        self.recommendation_id = recommendation_id
        self.status = status
