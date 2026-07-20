"""Pydantic schemas for execution and finding APIs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScheduleExecutionRequest(BaseModel):
    rule_id: str
    source_id: str
    window_start: str
    window_end: str
    trigger: str = "OnDemand"
    rule_version: str | None = None
    source_type: str | None = None


class RecordExecutionResultRequest(BaseModel):
    telemetry_records_evaluated: int = 0
    findings_produced: int = 0
    duration_ms: float = 0.0
    cpu_ms: float = 0.0
    finding_ids: list[str] = Field(default_factory=list)
    failed: bool = False
    timed_out: bool = False
    error_type: str | None = None
    error_message: str | None = None


class DetectionExecutionResponse(BaseModel):
    id: str
    tenant_id: str
    rule_id: str
    rule_version: str | None
    source_id: str
    source_type: str | None
    window_start: str
    window_end: str
    state: str
    trigger: str
    stats: dict[str, Any]
    error: dict[str, Any] | None
    finding_refs: list[str]
    scheduled_at: str
    started_at: str | None
    completed_at: str | None
    version: int


class ListExecutionsResponse(BaseModel):
    items: list[DetectionExecutionResponse]
    limit: int
    offset: int


class DetectionFindingResponse(BaseModel):
    id: str
    tenant_id: str
    finding_key: str
    rule_id: str
    rule_version: str | None
    execution_id: str
    asset_id: str
    asset_type: str | None
    signal_id: str
    telemetry_fingerprint: str
    severity: str
    confidence: str
    state: str
    observed_at: str
    detected_at: str
    last_seen_at: str
    mitre: dict[str, Any] | None
    correlation: dict[str, Any]
    analyst_note: dict[str, Any] | None
    escalation: dict[str, Any] | None
    reopened_from: str | None
    version: int
    deduplicated: bool = False


class ListFindingsResponse(BaseModel):
    items: list[DetectionFindingResponse]
    limit: int
    offset: int


class TriageFindingRequest(BaseModel):
    note: str | None = None


class ConfirmFindingRequest(BaseModel):
    pass


class FalsePositiveRequest(BaseModel):
    justification: str


class SuppressFindingRequest(BaseModel):
    justification: str


class EscalateFindingRequest(BaseModel):
    investigation_id: str
