"""Immutable CQRS command objects for the Cloud Provider Framework
(M45C). `CloudProviderRegistration` remains the single aggregate these
commands act against."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cloud_security.domain.value_objects.provider_capability_set import ProviderCapabilitySet

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class RegisterProviderCommand:
    tenant_id: TenantId
    platform_type: CloudPlatformType
    display_name: str
    capabilities: ProviderCapabilitySet = field(default_factory=ProviderCapabilitySet)


@dataclass(frozen=True, slots=True)
class UpdateProviderCommand:
    tenant_id: TenantId
    display_name: str | None = None
    capabilities: ProviderCapabilitySet | None = None


@dataclass(frozen=True, slots=True)
class EnableProviderCommand:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class DisableProviderCommand:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class RemoveProviderCommand:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class BatchProviderCommand:
    tenant_id: TenantId
    commands: tuple[RegisterProviderCommand, ...] = field(default_factory=tuple)
