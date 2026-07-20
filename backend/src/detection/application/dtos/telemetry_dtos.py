"""DTOs for TelemetrySource and simulation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class TelemetrySourceDTO:
    id: str
    tenant_id: str
    name: str
    source_type: str
    trust_level: str
    lifecycle_state: str
    description: str | None
    schema_version: str
    schema: dict[str, Any]
    connection: dict[str, Any]
    health_status: str
    health: dict[str, Any]
    latency_expected_seconds: float
    latency_max_seconds: float | None
    retention_seconds: float
    created_at: str
    updated_at: str
    version: int


@dataclass(frozen=True, slots=True)
class TelemetrySourcePageDTO:
    items: list[TelemetrySourceDTO]
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class SchemaValidationResultDTO:
    is_valid: bool
    missing_fields: list[str]
    unsupported_fields: list[str]
    issues: list[dict[str, str]]
    schema_version: str | None
    compatible: bool


@dataclass(frozen=True, slots=True)
class SimulationResultDTO:
    simulation_id: str
    rule_id: str
    rule_version: str | None
    source_id: str
    match_count: int
    events_evaluated: int
    duration_ms: float
    truncated: bool
    source_unavailable: bool
    sample_matches: list[dict[str, Any]]
    evidence: dict[str, Any]
    simulated_at: str
    creates_findings: bool = False
    findings_created: int = 0  # always 0 — isolation invariant


@dataclass(frozen=True, slots=True)
class ValidateSourceResultDTO:
    source_id: str
    provider_registered: bool
    schema_version_valid: bool
    health_status: str | None
    capabilities: list[str] = field(default_factory=list)
    detail: str | None = None
