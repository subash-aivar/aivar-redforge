"""DTOs / commands for M26 Phase 6 Runtime Visibility."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class IngestRuntimeEventsCommand:
    organization_id: str
    cloud_account_id: UUID
    events: list[dict[str, Any]]
    source: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeEventDTO:
    event_id: str
    organization_id: str
    cloud_account_id: str
    event_type: str
    source: str
    severity: str
    outcome: str
    event_time: datetime
    ingested_at: datetime
    event_name: str
    provider_event_id: str
    source_ip: str
    target_resource: str
    identity: dict[str, Any]
    host: dict[str, Any]
    container: dict[str, Any]
    correlation_refs: dict[str, Any]
    cspm_snapshot: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RuntimeProcessDTO:
    process_id: str
    organization_id: str
    runtime_event_id: str
    process_name: str
    executable_path: str
    pid: int | None
    parent_pid: int | None
    command_line: str
    user_name: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class RuntimeNetworkConnectionDTO:
    connection_id: str
    organization_id: str
    runtime_event_id: str
    direction: str
    protocol: str
    local_address: str
    local_port: int | None
    remote_address: str
    remote_port: int | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class RuntimeSummaryDTO:
    organization_id: str
    total_events: int
    by_event_type: dict[str, int]
    by_source: dict[str, int]
    process_count: int
    connection_count: int


@dataclass(frozen=True, slots=True)
class IngestResultDTO:
    organization_id: str
    accepted: int
    inserted: int
    skipped_duplicates: int
    event_ids: list[str]
