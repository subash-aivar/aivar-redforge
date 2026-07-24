"""Immutable CQRS query objects for the Cloud Provider Framework
(M45C)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudPlatformType, ProviderCapability
    from cloud_security.domain.value_objects.identifiers import ProviderId, TenantId


@dataclass(frozen=True, slots=True)
class GetProviderQuery:
    tenant_id: TenantId
    provider_id: ProviderId


@dataclass(frozen=True, slots=True)
class ListProvidersQuery:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class ListProvidersByPlatformQuery:
    tenant_id: TenantId
    platform_type: CloudPlatformType


@dataclass(frozen=True, slots=True)
class ListEnabledProvidersQuery:
    tenant_id: TenantId


@dataclass(frozen=True, slots=True)
class ListProvidersByCapabilityQuery:
    tenant_id: TenantId
    capability: ProviderCapability
