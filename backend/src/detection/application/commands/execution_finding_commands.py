"""Commands for DetectionExecution and DetectionFinding use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from detection.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class ScheduleRuleExecution:
    tenant_id: TenantId
    rule_id: UUID
    source_id: str
    window_start: str
    window_end: str
    trigger: str = "OnDemand"
    rule_version: str | None = None
    source_type: str | None = None


@dataclass(frozen=True, slots=True)
class RecordExecutionResult:
    tenant_id: TenantId
    execution_id: UUID
    telemetry_records_evaluated: int = 0
    findings_produced: int = 0
    duration_ms: float = 0.0
    cpu_ms: float = 0.0
    finding_ids: list[UUID] | None = None
    failed: bool = False
    timed_out: bool = False
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class ProduceFinding:
    tenant_id: TenantId
    rule_id: UUID
    execution_id: UUID
    asset_id: str
    signal_id: str
    observed_at: str
    fingerprint_fields: dict[str, Any]
    rule_version: str | None = None
    asset_type: str | None = None
    signal_source_id: str | None = None
    severity: str = "High"
    confidence: str = "Medium"
    technique_id: str | None = None
    tactic: str | None = None
    dedup_window_seconds: int = 900


@dataclass(frozen=True, slots=True)
class TriageFinding:
    tenant_id: TenantId
    finding_id: UUID
    analyst: str
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ConfirmFinding:
    tenant_id: TenantId
    finding_id: UUID
    analyst: str


@dataclass(frozen=True, slots=True)
class MarkFindingFalsePositive:
    tenant_id: TenantId
    finding_id: UUID
    analyst: str
    justification: str


@dataclass(frozen=True, slots=True)
class SuppressFinding:
    tenant_id: TenantId
    finding_id: UUID
    analyst: str
    justification: str


@dataclass(frozen=True, slots=True)
class EscalateFindingToInvestigation:
    tenant_id: TenantId
    finding_id: UUID
    analyst: str
    investigation_id: str
