"""Infrastructure-layer persistence errors for campaign_intel,
mirroring `malware_intel.infrastructure.persistence.exceptions`'s
convention."""

from __future__ import annotations


class CampaignIntelPersistenceError(Exception):
    """Base type for every campaign_intel infrastructure persistence
    error."""


class CampaignIntelIntegrityError(CampaignIntelPersistenceError):
    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(f"Persistence integrity error during {operation}: {reason}")
        self.operation = operation
        self.reason = reason


class OptimisticLockConflictError(CampaignIntelPersistenceError):
    """Raised when a `save()` call's expected `row_version` no longer
    matches the persisted row — a concurrent writer already updated this
    Campaign. The caller must reload and retry."""

    def __init__(self, campaign_id: str, expected_version: int, actual_version: int) -> None:
        super().__init__(
            f"Optimistic lock conflict on Campaign {campaign_id}: "
            f"expected row_version={expected_version}, actual={actual_version}"
        )
        self.campaign_id = campaign_id
        self.expected_version = expected_version
        self.actual_version = actual_version
