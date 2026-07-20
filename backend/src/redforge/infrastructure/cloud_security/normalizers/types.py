"""Normalized draft types produced by cloud asset normalizers."""

from __future__ import annotations

from dataclasses import dataclass, field

from redforge.domain.cloud_security.entities import AssetRelationship
from redforge.domain.cloud_security.value_objects import CloudAssetType, NormalizedConfig


@dataclass(frozen=True, slots=True)
class NormalizedAssetDraft:
    """Provider-agnostic draft ready for CloudAsset.discover / apply_discovery."""

    asset_type: CloudAssetType
    provider_id: str
    display_name: str
    region_code: str
    az_name: str | None
    tags: dict[str, str]
    provider_metadata: dict[str, object]
    normalized_config: NormalizedConfig
    relationships: list[AssetRelationship] = field(default_factory=list)
