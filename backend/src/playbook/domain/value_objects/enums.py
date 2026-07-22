"""Frozen enums for playbook BC (M35)."""

from __future__ import annotations

from enum import StrEnum


class ActionImpactLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PlaybookStatus(StrEnum):
    DRAFT = "DRAFT"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    DEPRECATED = "DEPRECATED"


class VersionStatus(StrEnum):
    DRAFT = "DRAFT"
    PUBLISHED = "PUBLISHED"


class TestOutcome(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class KillSwitchState(StrEnum):
    ARMED = "ARMED"
    TRIGGERED = "TRIGGERED"


class TriggerSourceContext(StrEnum):
    M28_FINDING = "M28_FINDING"
    M34_INCIDENT = "M34_INCIDENT"
    M32_EXPOSURE = "M32_EXPOSURE"
    MANUAL = "MANUAL"


class ConnectorType(StrEnum):
    CLOUD_AWS = "CLOUD_AWS"
    CLOUD_AZURE = "CLOUD_AZURE"
    CLOUD_GCP = "CLOUD_GCP"
    EDR_CROWDSTRIKE = "EDR_CROWDSTRIKE"
    EDR_SENTINELONE = "EDR_SENTINELONE"
    EDR_DEFENDER = "EDR_DEFENDER"
    NETWORK_PALOALTO = "NETWORK_PALOALTO"
    NETWORK_CISCO = "NETWORK_CISCO"
    IDENTITY_OKTA = "IDENTITY_OKTA"
    IDENTITY_AZURE_AD = "IDENTITY_AZURE_AD"
    IDENTITY_PING = "IDENTITY_PING"
    ITSM_SERVICENOW = "ITSM_SERVICENOW"
    ITSM_JIRA = "ITSM_JIRA"
    COMM_SLACK = "COMM_SLACK"
    COMM_TEAMS = "COMM_TEAMS"
