"""Canonical enums for analytics BC (M33 Finalization §2)."""

from __future__ import annotations

from enum import StrEnum


class SecurityDomain(StrEnum):
    VULNERABILITY = "Vulnerability"
    DETECTION = "Detection"
    RED_TEAM = "RedTeam"
    CAMPAIGN = "Campaign"
    EXPOSURE = "Exposure"
    AI_POSTURE = "AIPosture"
    CROSS_DOMAIN = "CrossDomain"


class KPIType(StrEnum):
    MTTD = "MTTD"
    COVERAGE_PCT = "CoveragePct"
    EXPOSURE_TREND = "ExposureTrend"
    CAMPAIGN_SUCCESS_RATE = "CampaignSuccessRate"
    AI_RISK_TREND = "AIRiskTrend"
    MTTR = "MTTR"  # stub — REQUIRES_M34_DATA


class KPIStatus(StrEnum):
    ACTIVE = "Active"
    COMPUTING = "Computing"
    INSUFFICIENT_DATA = "InsufficientData"
    REQUIRES_M34_DATA = "RequiresM34Data"
    ERROR = "Error"


class DataSetStatus(StrEnum):
    ACTIVE = "Active"
    REBUILDING = "Rebuilding"
    PAUSED = "Paused"
    DEPRECATED = "Deprecated"
    ERROR = "Error"


class AnomalySignalType(StrEnum):
    VULNERABILITY_INGEST_RATE = "VulnerabilityIngestRate"
    DETECTION_FP_RATE = "DetectionFpRate"
    CAMPAIGN_EVASION_RATE = "CampaignEvasionRate"
    EXPOSURE_SCORE_DELTA = "ExposureScoreDelta"
    AI_RISK_SCORE_DELTA = "AIRiskScoreDelta"


class DetectionMethod(StrEnum):
    ZSCORE = "ZScore"
    IQR = "IQR"
    IQR_ROLLING = "IQRRolling"
    ML_ISOLATION_FOREST = "MLIsolationForest"


class AnomalySeverity(StrEnum):
    INFO = "Info"
    WARNING = "Warning"
    CRITICAL = "Critical"


class AnalyticsRole(StrEnum):
    VIEWER = "analytics:viewer"
    ANALYST = "analytics:analyst"
    ENGINEER = "analytics:engineer"
    ADMIN = "analytics:admin"
