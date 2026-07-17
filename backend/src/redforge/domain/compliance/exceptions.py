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
