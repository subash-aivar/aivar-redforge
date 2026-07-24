"""Immutable CQRS command objects for `CloudAsset` operations (M45A)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
from cloud_security.domain.value_objects.cloud_tag import CloudTagSet

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.cloud_resource import CloudResource
    from cloud_security.domain.value_objects.enums import CloudRiskLevel
    from cloud_security.domain.value_objects.identifiers import AccountId, TenantId


@dataclass(frozen=True, slots=True)
class DiscoverCloudAssetCommand:
    tenant_id: TenantId
    account_id: AccountId
    resource: CloudResource
    tags: CloudTagSet = field(default_factory=CloudTagSet)
    metadata: CloudMetadata = field(default_factory=CloudMetadata)


@dataclass(frozen=True, slots=True)
class UpdateCloudAssetCommand:
    tenant_id: TenantId
    tags: CloudTagSet | None = None
    risk_level: CloudRiskLevel | None = None
    metadata: CloudMetadata | None = None
