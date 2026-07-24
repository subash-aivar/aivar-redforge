"""DiscoveryJobRecord — the read-only projection of a
`CloudDiscoveryJob` returned by the application layer (M45E). Never
mutated; rebuilt fresh from the aggregate each time. Carries progress
and completion metadata only — never security findings or risk data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.value_objects.enums import DiscoveryJobStatus


@dataclass(frozen=True, slots=True)
class DiscoveryJobRecord:
    job_id: str
    tenant_id: str
    account_id: str
    provider_id: str
    status: DiscoveryJobStatus
    started_at: datetime
    discovered_count: int
    updated_count: int
    failed_count: int
    discovered_asset_ids: tuple[str, ...] = field(default_factory=tuple)
    completed_at: datetime | None = None
    cancelled_at: datetime | None = None
    failure_reason: str | None = None
