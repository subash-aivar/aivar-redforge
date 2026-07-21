"""Campaign enums."""

from __future__ import annotations

from enum import StrEnum


class CampaignKind(StrEnum):
    ONE_SHOT = "OneShot"
    RECURRING = "Recurring"
    CONTINUOUS = "Continuous"


class CampaignClassification(StrEnum):
    FULL_KILL_CHAIN = "FullKillChain"
    THREAT_ACTOR_EMULATION = "ThreatActorEmulation"
    COMPLIANCE_VALIDATION = "ComplianceValidation"
    DETECTION_TUNING = "DetectionTuning"
    RED_VS_BLUE = "RedVsBlue"


class CampaignState(StrEnum):
    DRAFT = "Draft"
    PENDING_APPROVAL = "PendingApproval"
    APPROVED = "Approved"
    SCHEDULED = "Scheduled"
    RUNNING = "Running"
    PAUSED = "Paused"
    COMPLETED = "Completed"
    FAILED = "Failed"
    ARCHIVED = "Archived"


class ObjectiveType(StrEnum):
    ACCESS_ACHIEVED = "AccessAchieved"
    DATA_ACCESSED = "DataAccessed"
    PRIVILEGE_ESCALATED = "PrivilegeEscalated"
    LATERAL_MOVEMENT_ACHIEVED = "LateralMovementAchieved"
    DETECTION_EVADED = "DetectionEvaded"
    COMPLIANCE_CONTROL_BYPASSED = "ComplianceControlBypassed"
    CUSTOM_DEFINED = "CustomDefined"


class ObjectiveState(StrEnum):
    PENDING = "Pending"
    ACHIEVED = "Achieved"
    FAILED = "Failed"
    INCONCLUSIVE = "Inconclusive"
    SKIPPED = "Skipped"


class InstanceState(StrEnum):
    STARTING = "Starting"
    RUNNING = "Running"
    PAUSED = "Paused"
    COMPLETED = "Completed"
    FAILED = "Failed"
    ABORTED = "Aborted"


class QuorumType(StrEnum):
    UNANIMOUS = "Unanimous"
    MAJORITY = "Majority"
