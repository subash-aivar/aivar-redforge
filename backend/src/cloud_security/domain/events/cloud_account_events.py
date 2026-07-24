"""Domain events produced by the `CloudAccount` aggregate (M45A)."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_security.domain.events.base import BaseDomainEvent
from cloud_security.domain.value_objects.enums import CloudPlatformType


@dataclass(frozen=True, slots=True)
class CloudAccountRegistered(BaseDomainEvent):
    platform_type: CloudPlatformType = CloudPlatformType.OTHER
    display_name: str = ""


@dataclass(frozen=True, slots=True)
class CredentialLinked(BaseDomainEvent):
    credential_type: str = ""


@dataclass(frozen=True, slots=True)
class DiscoveryCompleted(BaseDomainEvent):
    discovered_asset_count: int = 0
