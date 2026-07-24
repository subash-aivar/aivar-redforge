"""Immutable command-outcome DTOs for Resource Discovery (M45E).
Read-once results returned synchronously to the caller — never
persisted, never carrying security findings, risk scores, or
compliance data."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.application.dtos.discovery_job_record import DiscoveryJobRecord


@dataclass(frozen=True, slots=True)
class DiscoveryStarted:
    record: DiscoveryJobRecord


@dataclass(frozen=True, slots=True)
class DiscoveryCompleted:
    record: DiscoveryJobRecord


@dataclass(frozen=True, slots=True)
class DiscoveryCancelled:
    job_id: str
    tenant_id: str


@dataclass(frozen=True, slots=True)
class DiscoveryProgress:
    job_id: str
    discovered_count: int
    updated_count: int
    failed_count: int


@dataclass(frozen=True, slots=True)
class DiscoveryStatistics:
    total_jobs: int
    in_progress_jobs: int
    completed_jobs: int
    failed_jobs: int
    cancelled_jobs: int
    total_assets_discovered: int


class BatchDiscoveryStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class BatchDiscoveryFailure:
    index: int
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class BatchDiscoveryResult:
    status: BatchDiscoveryStatus
    started: tuple[DiscoveryStarted, ...] = field(default_factory=tuple)
    failures: tuple[BatchDiscoveryFailure, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return len(self.started)

    @property
    def failed_count(self) -> int:
        return len(self.failures)
