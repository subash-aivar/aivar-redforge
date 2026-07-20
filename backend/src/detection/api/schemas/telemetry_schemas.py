"""Pydantic schemas for TelemetrySource and simulation APIs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FieldDefinitionSchema(BaseModel):
    path: str
    data_type: str = "string"
    required: bool = False
    description: str = ""


class RegisterTelemetrySourceRequest(BaseModel):
    name: str
    source_type: str
    trust_level: str = "Secondary"
    schema_version: str
    fields: list[FieldDefinitionSchema]
    adapter_key: str
    tenant_scope_assertion: str
    latency_expected_seconds: float = 60.0
    retention_seconds: float = 2_592_000.0  # 30 days
    description: str | None = None
    endpoint_url: str | None = None
    options: dict[str, str] = Field(default_factory=dict)
    latency_max_seconds: float | None = None


class UpdateTelemetrySourceRequest(BaseModel):
    description: str | None = None
    trust_level: str | None = None
    schema_version: str | None = None
    fields: list[FieldDefinitionSchema] | None = None
    adapter_key: str | None = None
    tenant_scope_assertion: str | None = None
    endpoint_url: str | None = None
    options: dict[str, str] | None = None
    latency_expected_seconds: float | None = None
    latency_max_seconds: float | None = None
    retention_seconds: float | None = None
    health_status: str | None = None
    health_detail: str | None = None
    health_success: bool | None = None
    deactivate_reason: str | None = None


class ValidateSourceResponse(BaseModel):
    source_id: str
    provider_registered: bool
    schema_version_valid: bool
    health_status: str | None
    capabilities: list[str]
    detail: str | None = None


class TelemetrySourceResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    source_type: str
    trust_level: str
    lifecycle_state: str
    description: str | None
    schema_version: str
    schema_: dict[str, Any] = Field(alias="schema")
    connection: dict[str, Any]
    health_status: str
    health: dict[str, Any]
    latency_expected_seconds: float
    latency_max_seconds: float | None
    retention_seconds: float
    created_at: str
    updated_at: str
    version: int

    model_config = {"populate_by_name": True}


class ListTelemetrySourcesResponse(BaseModel):
    items: list[TelemetrySourceResponse]
    limit: int
    offset: int


class ValidateRuleAgainstSchemaRequest(BaseModel):
    source_id: str
    version: str | None = None


class SchemaValidationResponse(BaseModel):
    is_valid: bool
    missing_fields: list[str]
    unsupported_fields: list[str]
    issues: list[dict[str, str]]
    schema_version: str | None
    compatible: bool


class SimulateRuleRequest(BaseModel):
    source_id: str
    window_start: str
    window_end: str
    version: str | None = None
    limit: int = 1000
    synthetic_events: list[dict[str, Any]] | None = None


class SimulationResultResponse(BaseModel):
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
    findings_created: int = 0
