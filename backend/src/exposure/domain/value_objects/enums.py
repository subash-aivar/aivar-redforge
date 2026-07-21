"""Closed enums for the exposure bounded context (M32)."""

from __future__ import annotations

from enum import StrEnum


class SignalDomain(StrEnum):
    VULNERABILITY_MANAGEMENT = "VulnerabilityManagement"
    CLOUD_SECURITY = "CloudSecurity"


class ExposureStatus(StrEnum):
    ACTIVE = "Active"
    RESOLVED = "Resolved"
    SUPPRESSED = "Suppressed"


class RiskAmplifierType(StrEnum):
    INTERNET_EXPOSURE = "InternetExposure"
    DETECTION_GAP = "DetectionGap"
    THREAT_ACTOR_MATCH = "ThreatActorMatch"
    KEV_PRESENT = "KevPresent"
    CONFIRMED_EXPLOITATION = "ConfirmedExploitation"
    CLOUD_MISCONFIGURATION = "CloudMisconfiguration"
    AI_SYSTEM_RISK = "AISystemRisk"


class ExposureRole(StrEnum):
    VIEWER = "exposure:viewer"
    ANALYST = "exposure:analyst"
    SIMULATION_READER = "exposure:simulation_reader"
    ENGINEER = "exposure:engineer"
    ADMIN = "exposure:admin"


# Default weight seeds — product form score *= (1 + weight)
DEFAULT_AMPLIFIER_WEIGHTS: dict[RiskAmplifierType, float] = {
    RiskAmplifierType.KEV_PRESENT: 1.0,
    RiskAmplifierType.INTERNET_EXPOSURE: 0.3,
    RiskAmplifierType.DETECTION_GAP: 0.5,
    RiskAmplifierType.CLOUD_MISCONFIGURATION: 0.3,
    RiskAmplifierType.AI_SYSTEM_RISK: 0.5,
    RiskAmplifierType.THREAT_ACTOR_MATCH: 1.0,
    RiskAmplifierType.CONFIRMED_EXPLOITATION: 2.0,
}
