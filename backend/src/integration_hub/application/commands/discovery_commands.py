from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from integration_hub.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class RunDiscovery:
    tenant_id: TenantId
    connector_id: UUID
    mode: str
    triggered_by: str
    roles: tuple[str, ...]
    resume_sync_run_id: UUID | None = None
    """If set, continue a previous PARTIAL/RUNNING run from its persisted
    cursor instead of starting a new one — the re-invocation path for a
    run that hit the per-invocation max-pages safety limit."""
    max_pages: int = 25
    """Safety limit on pages fetched in a single invocation of this
    synchronous request/response endpoint. A connector whose vendor API
    has more pages than this leaves the run PARTIAL for a subsequent
    `resume_sync_run_id` call rather than blocking the HTTP request
    indefinitely."""


@dataclass(frozen=True, slots=True)
class CancelDiscovery:
    tenant_id: TenantId
    connector_id: UUID
    sync_run_id: UUID
    roles: tuple[str, ...]
