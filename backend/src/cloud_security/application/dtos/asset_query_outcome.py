"""Immutable read-outcome DTOs for the Cloud Asset Inventory's query
side (M45B), mirroring `siem_search`/`siem_analytics`'s
outcome-with-status shape (M44E/M44F)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.application.dtos.asset_inventory_record import AssetInventoryRecord


class AssetQueryStatus(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    UNSUPPORTED_PROVIDER = "unsupported_provider"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AssetQueryFailure:
    stage: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class AssetQueryOutcome:
    status: AssetQueryStatus
    records: tuple[AssetInventoryRecord, ...] = field(default_factory=tuple)
    failures: tuple[AssetQueryFailure, ...] = ()

    def __post_init__(self) -> None:
        if self.status == AssetQueryStatus.SUCCEEDED and self.failures:
            raise ValueError("SUCCEEDED AssetQueryOutcome must not carry failures")
        if self.status != AssetQueryStatus.SUCCEEDED and self.records:
            raise ValueError(f"{self.status} AssetQueryOutcome must not carry records")
