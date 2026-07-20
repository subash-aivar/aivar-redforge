"""Enumerations for the evidence domain."""

from __future__ import annotations

from enum import StrEnum


class EvidenceType(StrEnum):
    COMMAND_OUTPUT = "CommandOutput"
    NETWORK_CAPTURE = "NetworkCapture"
    SCREEN_CAPTURE = "ScreenCapture"
    LOG_EXTRACT = "LogExtract"
    FILE_ARTIFACT = "FileArtifact"
    MEMORY_DUMP = "MemoryDump"
    ANALYST_ANNOTATION = "AnalystAnnotation"
    ROLLBACK_PROOF = "RollbackProof"
    SAFETY_CHECK_LOG = "SafetyCheckLog"
    KILL_SWITCH_LOG = "KillSwitchLog"


class EvidenceIntegrityStatus(StrEnum):
    VERIFIED = "Verified"
    TAMPERED = "Tampered"
    UNKNOWN = "Unknown"


class RetentionClass(StrEnum):
    STANDARD = "Standard"
    LEGAL = "Legal"
    REGULATORY = "Regulatory"


class ChainState(StrEnum):
    OPEN = "Open"
    SEALED = "Sealed"
    SUBMITTED = "Submitted"
    ARCHIVED = "Archived"


class ChainIntegrityStatus(StrEnum):
    VERIFIED = "Verified"
    BROKEN = "Broken"
    UNKNOWN = "Unknown"


class CustodyAction(StrEnum):
    COLLECTED = "Collected"
    TRANSFERRED = "Transferred"
    VERIFIED = "Verified"
    QUARANTINED = "Quarantined"
    DELETION_REQUESTED = "DeletionRequested"
    RETENTION_EXPIRED = "RetentionExpired"


# Role required to seal an evidence chain (freeze §11.2 / authz model).
EVIDENCE_SEALER_ROLE = "evidence:sealer"

# Retention windows in years (freeze §11.2).
RETENTION_YEARS: dict[RetentionClass, int] = {
    RetentionClass.STANDARD: 3,
    RetentionClass.LEGAL: 7,
    RetentionClass.REGULATORY: 10,
}
