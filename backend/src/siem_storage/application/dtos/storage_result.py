"""Immutable storage-result DTOs (M43E §7).

Read-once outcomes returned synchronously to the caller — never
persisted (the Storage Foundation's responsibility ends at producing a
`StoragePlan`; it never writes anything itself).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_storage.application.dtos.storage_plan import StoragePlan
    from siem_storage.domain.value_objects.retention import RetentionPolicy


class StorageStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNSUPPORTED_TIER = "unsupported_tier"
    ARCHIVE_PLANNED = "archive_planned"
    RETENTION_APPLIED = "retention_applied"
    PARTIALLY_ACCEPTED = "partially_accepted"


@dataclass(frozen=True, slots=True)
class StorageFailure:
    stage: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class StorageResult:
    status: StorageStatus
    plan: StoragePlan | None = None
    applied_retention_policy: RetentionPolicy | None = None
    failures: tuple[StorageFailure, ...] = ()

    def __post_init__(self) -> None:
        plan_required = self.status in (StorageStatus.ACCEPTED, StorageStatus.ARCHIVE_PLANNED)
        if plan_required and self.plan is None:
            raise ValueError(f"{self.status} StorageResult must carry a plan")
        if not plan_required and self.plan is not None:
            raise ValueError(f"{self.status} StorageResult must not carry a plan")

        policy_required = self.status == StorageStatus.RETENTION_APPLIED
        if policy_required and self.applied_retention_policy is None:
            raise ValueError(f"{self.status} StorageResult must carry applied_retention_policy")
        if not policy_required and self.applied_retention_policy is not None:
            raise ValueError(f"{self.status} StorageResult must not carry applied_retention_policy")


@dataclass(frozen=True, slots=True)
class BatchStorageResult:
    status: StorageStatus
    results: tuple[StorageResult, ...] = field(default_factory=tuple)

    @property
    def accepted_count(self) -> int:
        return sum(1 for r in self.results if r.status == StorageStatus.ACCEPTED)

    @property
    def rejected_count(self) -> int:
        return len(self.results) - self.accepted_count

    @property
    def accepted_plans(self) -> tuple[StoragePlan, ...]:
        return tuple(
            r.plan
            for r in self.results
            if r.status == StorageStatus.ACCEPTED and r.plan is not None
        )
