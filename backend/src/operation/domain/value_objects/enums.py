"""Enumerations for the operation domain."""

from __future__ import annotations

from enum import StrEnum


class OperationState(StrEnum):
    PLANNING = "Planning"
    PENDING_OPERATION_APPROVAL = "PendingOperationApproval"
    APPROVED = "Approved"
    QUEUED = "Queued"
    RUNNING = "Running"
    PAUSED = "Paused"
    COMPLETED = "Completed"
    ABORTED = "Aborted"
    FAILED = "Failed"


class OperationClassification(StrEnum):
    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "InitialAccess"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    DEFENSE_EVASION = "DefenseEvasion"
    CREDENTIAL_ACCESS = "CredentialAccess"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "LateralMovement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    COMMAND_AND_CONTROL = "CommandAndControl"
    IMPACT = "Impact"


class StepType(StrEnum):
    ATTACK_STEP = "AttackStep"
    VERIFICATION_STEP = "VerificationStep"
    SAFETY_CHECKPOINT = "SafetyCheckpoint"
    HUMAN_APPROVAL_GATE = "HumanApprovalGate"
    DELAY_STEP = "DelayStep"


class StepState(StrEnum):
    PENDING = "Pending"
    AUTHORIZED = "Authorized"
    RUNNING = "Running"
    COMPLETED = "Completed"
    SKIPPED = "Skipped"
    FAILED = "Failed"
    ABORTED = "Aborted"


class OperationRisk(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ImpactCeiling(StrEnum):
    OBSERVE = "Observe"
    PROBE = "Probe"
    EXPLOIT = "Exploit"
    DESTRUCT = "Destruct"


class ExecutionPlanVersionState(StrEnum):
    DRAFT = "Draft"
    SIGNED = "Signed"
    SUPERSEDED = "Superseded"
    EXECUTING = "Executing"
    EXECUTED = "Executed"
    ARCHIVED = "Archived"
