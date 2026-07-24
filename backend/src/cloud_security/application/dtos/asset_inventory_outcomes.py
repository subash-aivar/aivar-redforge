"""Immutable command-outcome DTOs for the Cloud Asset Inventory
(M45B). Read-once results returned synchronously to the caller —
never persisted."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.application.dtos.asset_inventory_record import AssetInventoryRecord


@dataclass(frozen=True, slots=True)
class AssetRegistered:
    record: AssetInventoryRecord


@dataclass(frozen=True, slots=True)
class AssetUpdated:
    record: AssetInventoryRecord


@dataclass(frozen=True, slots=True)
class AssetMoved:
    record: AssetInventoryRecord
    from_account_id: str
    to_account_id: str


@dataclass(frozen=True, slots=True)
class AssetDeleted:
    asset_id: str
    tenant_id: str


class BatchAssetStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIALLY_SUCCEEDED = "partially_succeeded"


@dataclass(frozen=True, slots=True)
class BatchAssetFailure:
    index: int
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class BatchAssetResult:
    status: BatchAssetStatus
    registered: tuple[AssetRegistered, ...] = field(default_factory=tuple)
    failures: tuple[BatchAssetFailure, ...] = field(default_factory=tuple)

    @property
    def succeeded_count(self) -> int:
        return len(self.registered)

    @property
    def failed_count(self) -> int:
        return len(self.failures)
