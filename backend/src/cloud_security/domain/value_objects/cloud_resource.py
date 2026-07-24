"""CloudResource — a raw, provider-reported resource reference (M45A),
the input a `CloudAsset` is discovered/enriched from. Distinct from
`CloudAsset` (the aggregate): a `CloudResource` is what a provider
handed back; a `CloudAsset` is what this domain owns and evolves."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cloud_security.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudAssetType
    from cloud_security.domain.value_objects.identifiers import RegionId, ResourceId


@dataclass(frozen=True, slots=True)
class CloudResource:
    resource_id: ResourceId
    native_id: str
    asset_type: CloudAssetType
    region_id: RegionId | None = None

    def __post_init__(self) -> None:
        if not self.native_id.strip():
            raise EmptyIdentifierError("CloudResource.native_id")
