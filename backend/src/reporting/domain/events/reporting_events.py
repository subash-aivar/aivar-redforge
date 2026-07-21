"""Domain events for reporting Phase 2."""

from __future__ import annotations

from dataclasses import dataclass

from reporting.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ReportGenerationStarted(BaseDomainEvent):
    template_id: str = ""
    triggered_by: str = ""


@dataclass(frozen=True, slots=True)
class ReportGenerationCompleted(BaseDomainEvent):
    template_id: str = ""
    artifact_ref: str = ""


@dataclass(frozen=True, slots=True)
class ReportGenerationFailed(BaseDomainEvent):
    error_reason: str = ""


@dataclass(frozen=True, slots=True)
class ReportDelivered(BaseDomainEvent):
    recipient_count: int = 0


@dataclass(frozen=True, slots=True)
class ScheduledReportCreated(BaseDomainEvent):
    template_id: str = ""
    schedule: str = ""
