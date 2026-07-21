"""Application DTOs for reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ReportInstanceDTO:
    instance_id: str
    tenant_id: str
    template_id: str
    report_type: str
    status: str
    trigger: str
    narrative: str
    narrative_variant: str
    content: dict[str, Any]
    artifact_ref: str | None
    error_reason: str | None
    generated_by: str
    created_at: str
    completed_at: str | None
    schedule_id: str | None = None


@dataclass(frozen=True, slots=True)
class ScheduledReportDTO:
    schedule_id: str
    tenant_id: str
    template_id: str
    schedule: str
    cadence_minutes: int
    status: str
    next_run_at: str
    last_run_at: str | None
    parameters: dict[str, Any] = field(default_factory=dict)
    recipients: list[str] = field(default_factory=list)
    created_by: str = ""
    created_at: str = ""
