"""Enums for the Detection Engineering domain."""

from __future__ import annotations

from enum import StrEnum


class RuleLifecycleState(StrEnum):
    DRAFT = "Draft"
    UNDER_REVIEW = "UnderReview"
    TESTED = "Tested"
    STAGED = "Staged"
    ACTIVE = "Active"
    DEPRECATED = "Deprecated"
    ARCHIVED = "Archived"


class RuleSeverity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class RuleConfidence(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class RuleCategory(StrEnum):
    THREAT = "Threat"
    ANOMALY = "Anomaly"
    COMPLIANCE = "Compliance"
    VULNERABILITY = "Vulnerability"
    CONFIGURATION = "Configuration"
    BEHAVIORAL = "Behavioral"


class RuleLogicType(StrEnum):
    CONDITION = "Condition"
    SEQUENCE = "Sequence"
    AGGREGATION = "Aggregation"
    THRESHOLD = "Threshold"
    CORRELATION = "Correlation"


class ConditionOperator(StrEnum):
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    GREATER_THAN = "gt"
    GREATER_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_OR_EQUAL = "lte"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    REGEX = "regex"


class LogicConnector(StrEnum):
    AND = "AND"
    OR = "OR"
    NOT = "NOT"


class TestResultStatus(StrEnum):
    PASS = "Pass"
    FAIL = "Fail"
    ERROR = "Error"


class SourceType(StrEnum):
    CLOUD_TRAIL = "CloudTrail"
    NETWORK_FLOW = "NetworkFlow"
    ENDPOINT_EVENT = "EndpointEvent"
    APPLICATION_LOG = "ApplicationLog"
    KUBERNETES_AUDIT = "KubernetesAudit"
    CONTAINER_RUNTIME = "ContainerRuntime"
    IDENTITY_AUDIT = "IdentityAudit"
    VULNERABILITY_SIGNAL = "VulnerabilitySignal"
    BEHAVIORAL_SIGNAL = "BehavioralSignal"
    CUSTOM_PUSH = "CustomPush"


class SourceLifecycleState(StrEnum):
    ACTIVE = "Active"
    DEACTIVATED = "Deactivated"


class SourceHealthStatus(StrEnum):
    HEALTHY = "Healthy"
    DEGRADED = "Degraded"
    UNAVAILABLE = "Unavailable"
    UNKNOWN = "Unknown"


class SourceTrustLevel(StrEnum):
    AUTHORITATIVE = "Authoritative"
    SECONDARY = "Secondary"
    INFORMATIONAL = "Informational"


class FieldDataType(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"
    IP = "ip"
    OBJECT = "object"
    ARRAY = "array"


class ExecutionState(StrEnum):
    SCHEDULED = "Scheduled"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    TIMEDOUT = "Timedout"
    SKIPPED = "Skipped"


class ExecutionTrigger(StrEnum):
    SCHEDULED = "Scheduled"
    ON_DEMAND = "OnDemand"
    SIMULATION = "Simulation"
    TEST_RUN = "TestRun"
    REPLAY_RUN = "ReplayRun"


class FindingState(StrEnum):
    NEW = "New"
    TRIAGED = "Triaged"
    CONFIRMED = "Confirmed"
    FALSE_POSITIVE = "FalsePositive"
    SUPPRESSED = "Suppressed"
    ESCALATED_TO_INVESTIGATION = "EscalatedToInvestigation"
    CLOSED = "Closed"


class FindingSeverity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class FindingConfidence(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class PackLifecycleState(StrEnum):
    DRAFT = "Draft"
    PUBLISHED = "Published"
    DEPRECATED = "Deprecated"
    ARCHIVED = "Archived"


class PackCategory(StrEnum):
    THREAT_ACTOR_PACK = "ThreatActorPack"
    COMPLIANCE_PACK = "CompliancePack"
    ASSET_CLASS_PACK = "AssetClassPack"
    PLATFORM_PACK = "PlatformPack"
    CUSTOM_PACK = "CustomPack"


class ExceptionType(StrEnum):
    SUPPRESSION = "Suppression"
    FALSE_POSITIVE_ACKNOWLEDGMENT = "FalsePositiveAcknowledgment"
    RISK_ACCEPTED = "RiskAccepted"
    MAINTENANCE_WINDOW = "MaintenanceWindow"
    TUNING_IN_PROGRESS = "TuningInProgress"


class ExceptionState(StrEnum):
    PENDING = "Pending"
    ACTIVE = "Active"
    EXPIRED = "Expired"
    REVOKED = "Revoked"
    REJECTED = "Rejected"


class ExceptionScopeKind(StrEnum):
    FINDING = "Finding"
    RULE = "Rule"


class EvidenceType(StrEnum):
    TELEMETRY_SNAPSHOT = "TelemetrySnapshot"
    ANALYST_ANNOTATION = "AnalystAnnotation"
    SIMULATION_RESULT = "SimulationResult"
    TEST_RESULT = "TestResult"
    FALSE_POSITIVE_ATTESTATION = "FalsePositiveAttestation"
    REMEDIATION_PROOF = "RemediationProof"


class EvidenceIntegrityStatus(StrEnum):
    VERIFIED = "Verified"
    TAMPERED = "Tampered"
    UNKNOWN = "Unknown"


class CorrelationStatus(StrEnum):
    PENDING = "Pending"
    IN_PROGRESS = "InProgress"
    COMPLETED = "Completed"
    PARTIAL = "Partial"
    FAILED = "Failed"
