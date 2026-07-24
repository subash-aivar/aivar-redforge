"""Immutable command-outcome DTOs for the Cloud Provider Framework
(M45C). Read-once results returned synchronously to the caller —
never persisted."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.application.dtos.provider_record import ProviderRecord


@dataclass(frozen=True, slots=True)
class ProviderRegistered:
    record: ProviderRecord


@dataclass(frozen=True, slots=True)
class ProviderUpdated:
    record: ProviderRecord


@dataclass(frozen=True, slots=True)
class ProviderEnabled:
    record: ProviderRecord


@dataclass(frozen=True, slots=True)
class ProviderDisabled:
    record: ProviderRecord


@dataclass(frozen=True, slots=True)
class ProviderRemoved:
    provider_id: str
    tenant_id: str


class BatchProviderStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class BatchProviderFailure:
    index: int
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class BatchProviderResult:
    status: BatchProviderStatus
    registered: tuple[ProviderRegistered, ...] = field(default_factory=tuple)
    failures: tuple[BatchProviderFailure, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return len(self.registered)

    @property
    def failed_count(self) -> int:
        return len(self.failures)
