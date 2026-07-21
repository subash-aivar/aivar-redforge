"""Enums for reporting BC (M33 Phase 2 — ADR-M33-001)."""

from __future__ import annotations

from enum import StrEnum


class ReportType(StrEnum):
    """Platform report types — Phase 2 (4) + Phase 4 (3) = 7 total."""

    SECURITY_PROGRAM_DASHBOARD = "SecurityProgramDashboard"
    EXECUTIVE_SECURITY_REPORT = "ExecutiveSecurityReport"
    KPI_TREND_REPORT = "KpiTrendReport"
    ANOMALY_SUMMARY_REPORT = "AnomalySummaryReport"
    # Phase 4
    DETECTION_ANALYTICS_REPORT = "DetectionAnalyticsReport"
    CAMPAIGN_EFFECTIVENESS_REPORT = "CampaignEffectivenessReport"
    PREDICTIVE_THREAT_FORECAST = "PredictiveThreatForecast"


class ReportFormat(StrEnum):
    PDF = "PDF"
    HTML = "HTML"
    JSON = "JSON"
    CSV = "CSV"
    XLSX = "XLSX"
    BI_CONNECTOR = "BI_CONNECTOR"


class DeliveryChannel(StrEnum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    NOOP = "noop"


class DeliveryStatus(StrEnum):
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    SKIPPED = "Skipped"


class ReportStatus(StrEnum):
    PENDING = "Pending"
    GENERATING = "Generating"
    COMPLETE = "Complete"
    FAILED = "Failed"


class ScheduleStatus(StrEnum):
    ACTIVE = "Active"
    PAUSED = "Paused"
    ERROR = "Error"


class ReportTrigger(StrEnum):
    SCHEDULED = "Scheduled"
    ON_DEMAND = "OnDemand"


class NarrativeVariantId(StrEnum):
    """Narrative variants selected by dominant (worst) KPI pattern."""

    MTTD_DEGRADATION = "MTTD Degradation"
    COVERAGE_GAP = "Coverage Gap"
    EXPOSURE_WORSENING = "Exposure Worsening"
    CAMPAIGN_UNDERPERFORMANCE = "Campaign Underperformance"
    AI_RISK_ELEVATION = "AI Risk Elevation"
    GENERAL_PROGRAM_PATTERN = "General Program Pattern"


class AnalyticsRole(StrEnum):
    VIEWER = "analytics:viewer"
    ANALYST = "analytics:analyst"
    ENGINEER = "analytics:engineer"
    ADMIN = "analytics:admin"
