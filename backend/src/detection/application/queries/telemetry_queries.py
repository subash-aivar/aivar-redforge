"""Queries for TelemetrySource."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetTelemetrySource:
    tenant_id: UUID
    source_id: UUID


@dataclass(frozen=True, slots=True)
class ListTelemetrySources:
    tenant_id: UUID
    limit: int = 100
    offset: int = 0
    active_only: bool = False
    source_type: str | None = None
