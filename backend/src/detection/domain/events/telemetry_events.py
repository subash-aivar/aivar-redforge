"""Domain events for TelemetrySource aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class TelemetrySourceRegistered(BaseDomainEvent):
    name: str
    source_type: str
    schema_version: str
    trust_level: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TelemetrySourceDeactivated(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TelemetrySourceHealthChanged(BaseDomainEvent):
    previous_status: str
    new_status: str
    detail: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class TelemetrySourceSchemaUpdated(BaseDomainEvent):
    previous_schema_version: str
    new_schema_version: str
