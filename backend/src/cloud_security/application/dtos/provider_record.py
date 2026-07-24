"""ProviderRecord — the read-only projection of a
`CloudProviderRegistration` returned by the application layer (M45C).
Never mutated; rebuilt fresh from the aggregate each time."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.value_objects.enums import CloudPlatformType, ProviderStatus
    from cloud_security.domain.value_objects.provider_capability_set import (
        ProviderCapabilitySet,
    )


@dataclass(frozen=True, slots=True)
class ProviderRecord:
    provider_id: str
    tenant_id: str
    platform_type: CloudPlatformType
    display_name: str
    capabilities: ProviderCapabilitySet
    status: ProviderStatus
    registered_at: datetime
    updated_at: datetime
