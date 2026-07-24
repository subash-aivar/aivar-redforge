"""CloudAccountDto — the read-only projection of a `CloudAccount`
returned by the application layer (M45A). Never mutated; rebuilt fresh
from the aggregate each time."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.value_objects.enums import (
        CloudConnectionStatus,
        CloudDiscoveryState,
        CloudPlatformType,
    )


@dataclass(frozen=True, slots=True)
class CloudAccountDto:
    account_id: str
    tenant_id: str
    provider_id: str
    platform_type: CloudPlatformType
    display_name: str
    connection_status: CloudConnectionStatus
    discovery_state: CloudDiscoveryState
    has_linked_credential: bool
    registered_at: datetime
