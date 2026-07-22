"""Shared helpers for M35 code generation."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
TESTS = ROOT / "tests"
MIG = SRC / "redforge" / "infrastructure" / "database" / "migrations" / "versions"


def w(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content if content.endswith("\n") else content + "\n"
    path.write_text(text)


def empty_inits(*paths: Path) -> None:
    for p in paths:
        w(p / "__init__.py", "")


CONNECTOR_TYPES = """
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
"""

IMPACT = """
class ActionImpactLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
"""

FAILURE_MODES = """
class ConnectorFailureMode(StrEnum):
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILURE = "AUTH_FAILURE"
    CLIENT_ERROR = "CLIENT_ERROR"
    SERVER_ERROR = "SERVER_ERROR"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
"""
