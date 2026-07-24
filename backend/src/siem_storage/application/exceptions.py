"""Application-layer errors for siem_storage's Storage Foundation
(M42 Phase 5 / M43E).

Validation and strategy-selection failures are always one of these
typed errors — never a bare `ValueError`/`KeyError` — so a
`StorageResult` can carry an inspectable failure rather than an opaque
string.
"""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationForbiddenError(ApplicationError):
    def __init__(self, required_role: str) -> None:
        super().__init__(f"Requires role {required_role}")
        self.required_role = required_role


class ApplicationValidationError(ApplicationError):
    """Base type for every pre-planning request-shape validation failure."""


class MissingRequiredFieldError(ApplicationValidationError):
    def __init__(self, field_name: str) -> None:
        super().__init__(f"Missing required field: {field_name}")
        self.field_name = field_name


class EmptyBatchStorageError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("StoreBatchCommand.events must contain at least one CanonicalEvent")


class TenantContextMismatchError(ApplicationValidationError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant context mismatch: expected {expected}, got {actual}")


class InvalidInitialTierError(ApplicationValidationError):
    def __init__(self, requested: object) -> None:
        super().__init__(f"New events must enter storage at the HOT tier, got {requested}")
        self.requested = requested


class InvalidLifecycleTransitionError(ApplicationValidationError):
    def __init__(self, current: object, target: object) -> None:
        super().__init__(f"Invalid lifecycle transition {current} → {target}")
        self.current = current
        self.target = target


class InvalidArchivalRequestError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid archival request: {reason}")


class RetentionPolicyIncompatibleError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Retention policy is incompatible with this request: {reason}")


class StorageStrategySelectionError(ApplicationError):
    """Base type for every storage-strategy-selection failure."""


class UnsupportedStorageTierError(StorageStrategySelectionError):
    def __init__(self, tier: object) -> None:
        super().__init__(f"No storage strategy registered for tier {tier}")
        self.tier = tier


class DuplicateStorageStrategyRegistrationError(ApplicationError):
    def __init__(self, tier: object) -> None:
        super().__init__(f"A storage strategy for tier {tier} is already registered")
        self.tier = tier
