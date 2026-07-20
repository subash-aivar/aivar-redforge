"""DTOs for DetectionExecution and DetectionFinding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class DetectionExecutionDTO:
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


@dataclass(frozen=True, slots=True)
class ExecutionPageDTO:
    items: list[DetectionExecutionDTO]
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class DetectionFindingDTO:
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


@dataclass(frozen=True, slots=True)
class FindingPageDTO:
    items: list[DetectionFindingDTO]
    limit: int
    offset: int
