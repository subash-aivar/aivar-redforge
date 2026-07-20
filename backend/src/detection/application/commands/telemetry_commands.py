"""Commands for TelemetrySource and simulation use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RegisterTelemetrySource:
    tenant_id: UUID
    name: str
    source_type: str
    trust_level: str
    schema_version: str
    fields: list[dict[str, Any]]
    adapter_key: str
    tenant_scope_assertion: str
    latency_expected_seconds: float
    retention_seconds: float
    description: str | None = None
    credential_vault_ref: UUID | None = None
    endpoint_url: str | None = None
    options: dict[str, str] | None = None
    latency_max_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class DeactivateTelemetrySource:
    tenant_id: UUID
    source_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class UpdateTelemetrySourceHealth:
    tenant_id: UUID
    source_id: UUID
    status: str
    detail: str | None = None
    success: bool | None = None


@dataclass(frozen=True, slots=True)
class UpdateTelemetrySource:
    tenant_id: UUID
    source_id: UUID
    description: str | None = None
    trust_level: str | None = None
    schema_version: str | None = None
    fields: list[dict[str, Any]] | None = None
    adapter_key: str | None = None
    tenant_scope_assertion: str | None = None
    endpoint_url: str | None = None
    options: dict[str, str] | None = None
    latency_expected_seconds: float | None = None
    latency_max_seconds: float | None = None
    retention_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class ValidateRuleAgainstSchema:
    tenant_id: UUID
    rule_id: UUID
    source_id: UUID
    version: str | None = None


@dataclass(frozen=True, slots=True)
class SimulateRule:
    tenant_id: UUID
    rule_id: UUID
    source_id: UUID
    window_start: str
    window_end: str
    version: str | None = None
    limit: int = 1000
    # Optional synthetic events for isolated simulation without a live adapter
    synthetic_events: list[dict[str, Any]] | None = None
