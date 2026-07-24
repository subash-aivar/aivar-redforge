"""Queries for TelemetrySource."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from detection.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetTelemetrySource:
    tenant_id: TenantId
    source_id: UUID


@dataclass(frozen=True, slots=True)
class ListTelemetrySources:
    tenant_id: TenantId
    limit: int = 100
    offset: int = 0
    active_only: bool = False
    source_type: str | None = None
