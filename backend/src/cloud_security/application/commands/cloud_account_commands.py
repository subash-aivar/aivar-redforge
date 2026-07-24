"""Immutable CQRS command objects for `CloudAccount` operations (M45A)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cloud_security.domain.value_objects.cloud_tag import CloudTagSet

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import ProviderId, TenantId


@dataclass(frozen=True, slots=True)
class RegisterCloudAccountCommand:
    tenant_id: TenantId
    provider_id: ProviderId
    platform_type: CloudPlatformType
    display_name: str
    tags: CloudTagSet = field(default_factory=CloudTagSet)


@dataclass(frozen=True, slots=True)
class LinkCloudCredentialCommand:
    tenant_id: TenantId
    credential_id: str
    credential_type: str


@dataclass(frozen=True, slots=True)
class StartCloudDiscoveryCommand:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class CompleteCloudDiscoveryCommand:
    tenant_id: TenantId
    discovered_asset_count: int
