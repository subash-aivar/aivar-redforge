"""Domain events produced by the `CloudProviderRegistration` aggregate
(M45C)."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_security.domain.events.base import BaseDomainEvent
from cloud_security.domain.value_objects.enums import CloudPlatformType


@dataclass(frozen=True, slots=True)
class ProviderRegistered(BaseDomainEvent):
    platform_type: CloudPlatformType = CloudPlatformType.OTHER
    display_name: str = ""


@dataclass(frozen=True, slots=True)
class ProviderUpdated(BaseDomainEvent):
    updated_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProviderEnabled(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class ProviderDisabled(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class ProviderRemoved(BaseDomainEvent):
    pass
