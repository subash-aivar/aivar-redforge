"""Domain events produced by analytics BC."""

from __future__ import annotations

from dataclasses import dataclass

from analytics.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class AnalyticsDataSetRegistered(BaseDomainEvent):
    domain: str = ""
    schema_version: str = ""


@dataclass(frozen=True, slots=True)
class AnalyticsDataSetPopulated(BaseDomainEvent):
    records_ingested: int = 0
    checkpoint: str = ""


@dataclass(frozen=True, slots=True)
class AnalyticsDataSetRebuildStarted(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class AnalyticsDataSetRebuildCompleted(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class KPIComputed(BaseDomainEvent):
    kpi_type: str = ""
    value: float | None = None
    unit: str = ""
    definition_version: int = 1


@dataclass(frozen=True, slots=True)
class KPIComputationFailed(BaseDomainEvent):
    kpi_type: str = ""
    error_reason: str = ""


@dataclass(frozen=True, slots=True)
class AnomalyDetected(BaseDomainEvent):
    signal_type: str = ""
    severity: str = ""
    score: float = 0.0


@dataclass(frozen=True, slots=True)
class AnalyticsQueryCreated(BaseDomainEvent):
    name: str = ""
    domain: str = ""


@dataclass(frozen=True, slots=True)
class AnalyticsQueryExecuted(BaseDomainEvent):
    executed_by: str = ""
    row_count: int = 0
    duration_ms: int = 0
