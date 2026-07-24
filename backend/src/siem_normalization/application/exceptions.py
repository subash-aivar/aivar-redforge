"""Application-layer errors for siem_normalization's Event Normalization
Framework (M42 Phase 4 / M43D).

Selection-strategy and validation failures are always one of these
typed errors — never a bare `ValueError`/`KeyError` — so a
`NormalizationResult` can carry an inspectable failure rather than an
opaque string.
"""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationForbiddenError(ApplicationError):
    def __init__(self, required_role: str) -> None:
        super().__init__(f"Requires role {required_role}")
        self.required_role = required_role


class ApplicationValidationError(ApplicationError):
    """Base type for every pre-lookup request-shape validation failure."""


class MissingRequiredFieldError(ApplicationValidationError):
    def __init__(self, field_name: str) -> None:
        super().__init__(f"Missing required field: {field_name}")
        self.field_name = field_name


class EmptyBatchNormalizationError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("NormalizeBatchCommand.events must contain at least one event command")


class InvalidSchemaVersionRequestError(ApplicationValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid requested schema version: {raw!r}")
        self.raw = raw


class RegistrySelectionError(ApplicationError):
    """Base type for every normalizer-selection-strategy failure."""


class UnsupportedProviderError(RegistrySelectionError):
    def __init__(self, provider: str) -> None:
        super().__init__(f"No normalizer registered for provider {provider!r}")
        self.provider = provider


class UnsupportedVersionError(RegistrySelectionError):
    def __init__(self, provider: str, requested: object) -> None:
        super().__init__(
            f"No normalizer registered for provider {provider!r} compatible with "
            f"schema version {requested}"
        )
        self.provider = provider
        self.requested = requested


class AmbiguousNormalizerSelectionError(RegistrySelectionError):
    def __init__(
        self, provider: str, requested: object, candidate_versions: tuple[object, ...]
    ) -> None:
        super().__init__(
            f"{len(candidate_versions)} normalizers registered for provider {provider!r} are "
            f"all compatible with requested schema version {requested}: {candidate_versions} — "
            "selection is ambiguous"
        )
        self.provider = provider
        self.requested = requested
        self.candidate_versions = candidate_versions


class DuplicateNormalizerRegistrationError(ApplicationError):
    def __init__(self, provider: str, schema_version: object) -> None:
        super().__init__(
            f"A normalizer for provider {provider!r} at schema version {schema_version} "
            "is already registered"
        )
        self.provider = provider
        self.schema_version = schema_version
