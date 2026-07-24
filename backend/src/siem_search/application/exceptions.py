"""Application-layer errors for siem_search's Search Engine
(M42 Phase 10 / M44E).

Validation and provider-selection failures are always one of these
typed errors — never a bare `ValueError`/`KeyError` — so a search
outcome can carry an inspectable failure rather than an opaque string.
"""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationForbiddenError(ApplicationError):
    def __init__(self, required_role: str) -> None:
        super().__init__(f"Requires role {required_role}")
        self.required_role = required_role


class ApplicationValidationError(ApplicationError):
    """Base type for every pre-execution request-shape validation failure."""


class EmptyBatchSearchError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("SearchBatchQuery.queries must contain at least one SearchQuery")


class InvalidPaginationError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid pagination: {reason}")


class InvalidFilterError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid filter: {reason}")


class InvalidSortError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid sort: {reason}")


class ProviderSelectionError(ApplicationError):
    """Base type for every search-provider-selection failure."""


class UnsupportedProviderError(ProviderSelectionError):
    def __init__(self, entity_type: object) -> None:
        super().__init__(f"No search provider registered for entity type {entity_type!r}")
        self.entity_type = entity_type


class UnsupportedProviderVersionError(ProviderSelectionError):
    def __init__(self, entity_type: object, requested: object) -> None:
        super().__init__(
            f"No search provider registered for entity type {entity_type!r} compatible with "
            f"schema version {requested}"
        )
        self.entity_type = entity_type
        self.requested = requested


class AmbiguousProviderSelectionError(ProviderSelectionError):
    def __init__(
        self, entity_type: object, requested: object, candidate_versions: tuple[object, ...]
    ) -> None:
        super().__init__(
            f"{len(candidate_versions)} search providers registered for entity type "
            f"{entity_type!r} are all compatible with requested schema version {requested}: "
            f"{candidate_versions} — selection is ambiguous"
        )
        self.entity_type = entity_type
        self.requested = requested
        self.candidate_versions = candidate_versions


class DuplicateProviderRegistrationError(ApplicationError):
    def __init__(self, entity_type: object, schema_version: object) -> None:
        super().__init__(
            f"A search provider for entity type {entity_type!r} at schema version "
            f"{schema_version} is already registered"
        )
        self.entity_type = entity_type
        self.schema_version = schema_version
