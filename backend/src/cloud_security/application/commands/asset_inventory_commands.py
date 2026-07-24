"""Immutable CQRS command objects for the Cloud Asset Inventory (M45B).

`CloudAsset` (M45A) remains the single aggregate these commands act
against — the inventory is an orchestration layer over it, not a
parallel model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
from cloud_security.domain.value_objects.cloud_tag import CloudTagSet

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.cloud_resource import CloudResource
    from cloud_security.domain.value_objects.cloud_tag import CloudTag
    from cloud_security.domain.value_objects.enums import CloudRiskLevel
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        RegionId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class RegisterAssetCommand:
    tenant_id: TenantId
    account_id: AccountId
    resource: CloudResource
    tags: CloudTagSet = field(default_factory=CloudTagSet)
    metadata: CloudMetadata = field(default_factory=CloudMetadata)


@dataclass(frozen=True, slots=True)
class UpdateAssetCommand:
    tenant_id: TenantId
    tags: CloudTagSet | None = None
    risk_level: CloudRiskLevel | None = None
    metadata: CloudMetadata | None = None


@dataclass(frozen=True, slots=True)
class DeleteAssetCommand:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class MoveAssetCommand:
    tenant_id: TenantId
    account_id: AccountId | None = None
    region_id: RegionId | None = None


@dataclass(frozen=True, slots=True)
class TagAssetCommand:
    tenant_id: TenantId
    tag: CloudTag


@dataclass(frozen=True, slots=True)
class UntagAssetCommand:
    tenant_id: TenantId
    tag_key: str


@dataclass(frozen=True, slots=True)
class BatchAssetCommand:
    tenant_id: TenantId
    commands: tuple[RegisterAssetCommand, ...] = field(default_factory=tuple)
