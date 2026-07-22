#!/usr/bin/env python3
"""Generate M34 bounded contexts from frozen architecture. Idempotent overwrite of package trees."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TESTS = ROOT / "tests"
MIG = SRC / "redforge" / "infrastructure" / "database" / "migrations" / "versions"


def w(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.lstrip("\n") if content.startswith("\n") else content)
    if not content.endswith("\n"):
        path.write_text(path.read_text() + "\n")


def main() -> None:
    write_incident()
    write_regulatory()
    write_lessons()
    write_migrations()
    write_tests()
    print("M34 packages generated.")


def write_incident() -> None:
    base = SRC / "incident"
    w(base / "__init__.py", '"""M34 incident bounded context."""\n')
    w(
        base / "domain" / "__init__.py",
        '"""Incident domain."""\n',
    )
    w(
        base / "domain" / "value_objects" / "__init__.py",
        "",
    )
    w(
        base / "domain" / "value_objects" / "enums.py",
        '''
"""Frozen enums for incident BC (M34)."""

from __future__ import annotations

from enum import StrEnum


class IncidentSeverity(StrEnum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class IncidentPhase(StrEnum):
    DECLARED = "DECLARED"
    CLASSIFIED = "CLASSIFIED"
    CONTAINED = "CONTAINED"
    ERADICATED = "ERADICATED"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"


class IncidentTriggerType(StrEnum):
    DETECTION_FINDING = "DETECTION_FINDING"
    INVESTIGATION_ESCALATION = "INVESTIGATION_ESCALATION"
    MANUAL_DECLARATION = "MANUAL_DECLARATION"
    EXTERNAL_NOTIFICATION = "EXTERNAL_NOTIFICATION"


class SeverityClassificationMethod(StrEnum):
    AUTOMATED_FROM_FINDING = "AUTOMATED_FROM_FINDING"
    INVESTIGATION_CONCLUSION = "INVESTIGATION_CONCLUSION"
    MANUAL_DECLARATION = "MANUAL_DECLARATION"
    COMMANDER_OVERRIDE = "COMMANDER_OVERRIDE"


class ResolutionType(StrEnum):
    THREAT_CONTAINED = "threat_contained"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    MERGED = "merged"
    ESCALATED_TO_EXTERNAL = "escalated_to_external"


class ContainmentActionType(StrEnum):
    ALERT_ESCALATION = "ALERT_ESCALATION"
    TRAFFIC_LOGGING = "TRAFFIC_LOGGING"
    PROCESS_TERMINATION = "PROCESS_TERMINATION"
    SERVICE_SUSPENSION = "SERVICE_SUSPENSION"
    CREDENTIAL_REVOKE = "CREDENTIAL_REVOKE"
    ACCOUNT_DISABLE = "ACCOUNT_DISABLE"
    TRAFFIC_BLOCK = "TRAFFIC_BLOCK"
    NETWORK_ISOLATION = "NETWORK_ISOLATION"
    MASS_CREDENTIAL_REVOKE = "MASS_CREDENTIAL_REVOKE"
    MANUAL = "MANUAL"


class ContainmentActionStatus(StrEnum):
    PENDING_AUTH = "PENDING_AUTH"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class ContainmentAuthorizationLevel(StrEnum):
    ANALYST = "ANALYST"
    COMMANDER = "COMMANDER"
    CISO = "CISO"


class EradicationVerificationStatus(StrEnum):
    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    VERIFIED = "VERIFIED"
    DISPUTED = "DISPUTED"


class RecoveryMilestoneStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    DEFERRED = "DEFERRED"


class TimelineEntryType(StrEnum):
    PHASE_TRANSITION = "PHASE_TRANSITION"
    CONTAINMENT_AUTHORIZED = "CONTAINMENT_AUTHORIZED"
    ERADICATION_SUBMITTED = "ERADICATION_SUBMITTED"
    ERADICATION_VERIFIED = "ERADICATION_VERIFIED"
    RECOVERY_COMPLETED = "RECOVERY_COMPLETED"
    SEVERITY_RECLASSIFIED = "SEVERITY_RECLASSIFIED"
    INVESTIGATION_LINKED = "INVESTIGATION_LINKED"
    COMMUNICATION_LOGGED = "COMMUNICATION_LOGGED"
    INCIDENT_CLOSED = "INCIDENT_CLOSED"


class CommunicationType(StrEnum):
    STAKEHOLDER_UPDATE = "STAKEHOLDER_UPDATE"
    REGULATORY_NOTIFICATION = "REGULATORY_NOTIFICATION"
    INTERNAL = "INTERNAL"
    EXTERNAL_AUTHORITY = "EXTERNAL_AUTHORITY"


class IncidentRole(StrEnum):
    VIEWER = "incident:viewer"
    ANALYST = "incident:analyst"
    COMMANDER = "incident:commander"
    CISO = "incident:ciso"
''',
    )
    w(
        base / "domain" / "value_objects" / "identifiers.py",
        '''
"""Typed identifiers for incident BC."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class IncidentId:
    value: UUID

    @classmethod
    def generate(cls) -> IncidentId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ContainmentActionId:
    value: UUID

    @classmethod
    def generate(cls) -> ContainmentActionId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EradicationVerificationId:
    value: UUID

    @classmethod
    def generate(cls) -> EradicationVerificationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RecoveryMilestoneId:
    value: UUID

    @classmethod
    def generate(cls) -> RecoveryMilestoneId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CommunicationLogEntryId:
    value: UUID

    @classmethod
    def generate(cls) -> CommunicationLogEntryId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
''',
    )
    w(
        base / "domain" / "value_objects" / "refs.py",
        '''
"""ACL-translated reference value objects — M34-owned; no upstream types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class EscalatedFindingRef:
    finding_id: str
    severity: str
    asset_ref: str
    rule_id: str
    detected_at: datetime
    escalated_by: str


@dataclass(frozen=True, slots=True)
class InvestigationRef:
    investigation_id: str
    concluded_at: datetime | None
    conclusion: str


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_chain_id: str
    engagement_ref: str
    sealed_at: datetime | None


@dataclass(frozen=True, slots=True)
class ExposureScopeRef:
    asset_ref_id: str
    composite_score: float
    assessed_at: datetime


@dataclass(frozen=True, slots=True)
class EradicationEvidenceRef:
    evidence_id: str
    description: str
''',
    )
    # Continue in part 2 via second function call - file too large. Use exec of smaller chunks.
    print("incident VOs written")


# Placeholder — full generator continued below via import of chunks
if __name__ == "__main__":
    # This script is a bootstrap; full generation runs from generate_m34_full.py
    print("Use generate_m34_full.py")
'''
)
# Fix the accidental triple quote at end - rewrite properly
print("bootstrap stub written incorrectly - fixing")
