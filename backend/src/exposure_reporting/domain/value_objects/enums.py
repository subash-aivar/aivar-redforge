"""Enums for exposure_reporting BC (M32 Phase 5)."""

from __future__ import annotations

from enum import StrEnum


class ReportType(StrEnum):
    BOARD_RISK_SUMMARY = "BoardRiskSummary"
    REMEDIATION_ROADMAP = "RemediationRoadmap"
    COMPLIANCE_GAP_REPORT = "ComplianceGapReport"
    TENANT_EXPOSURE_DASHBOARD = "TenantExposureDashboard"
    EXPOSURE_SCORE_TREND = "ExposureScoreTrend"


class ReportStatus(StrEnum):
    GENERATED = "Generated"
    DELIVERED = "Delivered"


class BusinessCriticality(StrEnum):
    MISSION_CRITICAL = "MissionCritical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NON_CRITICAL = "NonCritical"


class ImpactDomain(StrEnum):
    REVENUE = "Revenue"
    OPERATIONS = "Operations"
    COMPLIANCE = "Compliance"
    REPUTATION = "Reputation"
    SAFETY = "Safety"
    GENERAL = "General"


class NarrativeTemplateId(StrEnum):
    CRITICAL_EXPLOIT_AVAILABILITY = "Critical Exploit Availability"
    ACTIVE_THREAT_ACTOR_TARGETING = "Active Threat Actor Targeting"
    CONFIRMED_ACTIVE_EXPLOITATION = "Confirmed Active Exploitation"
    DETECTION_COVERAGE_CRITICAL_GAP = "Detection Coverage Critical Gap"
    INTERNET_ATTACK_SURFACE_EXPANSION = "Internet Attack Surface Expansion"
    AI_SYSTEM_EXPOSURE_RISK = "AI System Exposure Risk"
    GENERAL_EXPOSURE_ACCUMULATION = "General Exposure Accumulation"


class ReportingRole(StrEnum):
    VIEWER = "exposure:viewer"
    ANALYST = "exposure:analyst"
    ENGINEER = "exposure:engineer"
    ADMIN = "exposure:admin"
