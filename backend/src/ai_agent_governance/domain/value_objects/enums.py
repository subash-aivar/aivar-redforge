from __future__ import annotations

from enum import StrEnum


class EnvelopeState(StrEnum):
    DRAFT = "Draft"
    ACTIVE = "Active"
    UNDER_REVISION = "UnderRevision"
    SUSPENDED = "Suspended"
    RETIRED = "Retired"


class AuthorizedActionCategory(StrEnum):
    DATA_READ = "DataRead"
    DATA_WRITE = "DataWrite"
    EXTERNAL_COMMUNICATION = "ExternalCommunication"
    CODE_EXECUTION = "CodeExecution"
    TOOL_INVOCATION = "ToolInvocation"
    FINANCIAL_TRANSACTION = "FinancialTransaction"
    SYSTEM_ADMINISTRATION = "SystemAdministration"


class DataSensitivityClassification(StrEnum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


class DeviationType(StrEnum):
    UNAUTHORIZED_ACTION_CATEGORY = "UnauthorizedActionCategory"
    RESOURCE_SCOPE_VIOLATION = "ResourceScopeViolation"
    DATA_SENSITIVITY_EXCEEDED = "DataSensitivityExceeded"
    RATE_CEILING_EXCEEDED = "RateCeilingExceeded"
    REQUIRED_APPROVAL_BYPASSED = "RequiredApprovalBypassed"


class DeviationSeverity(StrEnum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ReviewState(StrEnum):
    UNREVIEWED = "Unreviewed"
    UNDER_REVIEW = "UnderReview"
    CONFIRMED_DEVIATION = "ConfirmedDeviation"
    CONFIRMED_BENIGN = "ConfirmedBenign"
    ENVELOPE_UPDATED = "EnvelopeUpdated"


class AIPostureRole(StrEnum):
    READER = "ai_posture:reader"
    ANALYST = "ai_posture:analyst"
    ENGINEER = "ai_posture:engineer"
    APPROVER = "ai_posture:approver"
    ADMIN = "ai_posture:admin"
    AUDITOR = "ai_posture:auditor"


_SENSITIVITY_RANK = {
    DataSensitivityClassification.PUBLIC: 0,
    DataSensitivityClassification.INTERNAL: 1,
    DataSensitivityClassification.CONFIDENTIAL: 2,
    DataSensitivityClassification.RESTRICTED: 3,
}


def sensitivity_exceeds(
    observed: DataSensitivityClassification, max_allowed: DataSensitivityClassification
) -> bool:
    return _SENSITIVITY_RANK[observed] > _SENSITIVITY_RANK[max_allowed]
