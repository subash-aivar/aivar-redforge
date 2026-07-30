"""Immutable CQRS query objects for attack_surface_management (M49B)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from attack_surface_management.domain.value_objects.enums import (
        AssetClassification,
        AssetLifecycleState,
        AssetType,
        Criticality,
        ExposureState,
    )
    from attack_surface_management.domain.value_objects.identifiers import AssetId, TenantId


@dataclass(frozen=True, slots=True)
class GetAssetQuery:
    tenant_id: TenantId
    asset_id: AssetId


@dataclass(frozen=True, slots=True)
class ListAssetsQuery:
    tenant_id: TenantId
    asset_type: AssetType | None = None
    classification: AssetClassification | None = None
    criticality: Criticality | None = None
    exposure_state: ExposureState | None = None
    lifecycle_state: AssetLifecycleState | None = None
    limit: int = 50
    offset: int = 0
