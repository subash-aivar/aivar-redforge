"""Domain exceptions for the detection context."""

from __future__ import annotations


class DomainException(Exception):
    """Base domain exception."""


class InvalidArgument(DomainException):
    def __init__(self, name: str, message: str) -> None:
        self.name = name
        self.message = message
        super().__init__(f"Invalid {name}: {message}")


class InvalidStateTransition(DomainException):
    def __init__(self, current: str, target: str) -> None:
        self.current = current
        self.target = target
        super().__init__(f"Cannot transition from {current} to {target}")


class TenantMismatch(DomainException):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class DetectionRuleNotFound(DomainException):
    def __init__(self, rule_id: str) -> None:
        super().__init__(f"DetectionRule not found: {rule_id}")


class DetectionRuleAlreadyExists(DomainException):
    def __init__(self, rule_key: str) -> None:
        super().__init__(f"DetectionRule already exists: {rule_key}")


class RuleVersionImmutable(DomainException):
    def __init__(self, version: str) -> None:
        super().__init__(f"RuleVersion {version} is immutable after publication")


class RulePromotionBlocked(DomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Rule promotion blocked: {reason}")


class OptimisticLockConflict(DomainException):
    def __init__(self, aggregate_id: str) -> None:
        super().__init__(f"Optimistic lock conflict for {aggregate_id}")


class TelemetrySourceNotFound(DomainException):
    def __init__(self, source_id: str) -> None:
        super().__init__(f"TelemetrySource not found: {source_id}")


class TelemetrySourceAlreadyExists(DomainException):
    def __init__(self, name: str) -> None:
        super().__init__(f"TelemetrySource already exists: {name}")


class ProviderNotRegistered(DomainException):
    def __init__(self, source_type: str, schema_version: str) -> None:
        self.source_type = source_type
        self.schema_version = schema_version
        super().__init__(
            f"No telemetry provider registered for {source_type}@{schema_version}"
        )


class SchemaVersionMismatch(DomainException):
    def __init__(
        self, source_type: str, expected: str, actual: str
    ) -> None:
        self.source_type = source_type
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Schema version mismatch for {source_type}: "
            f"expected {expected}, got {actual}"
        )


class SchemaValidationFailed(DomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Schema validation failed: {reason}")


class SimulationBlocked(DomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Simulation blocked: {reason}")


class SourceUnavailable(DomainException):
    def __init__(self, source_id: str, detail: str = "") -> None:
        msg = f"Telemetry source unavailable: {source_id}"
        if detail:
            msg = f"{msg} ({detail})"
        super().__init__(msg)


class DetectionExecutionNotFound(DomainException):
    def __init__(self, execution_id: str) -> None:
        super().__init__(f"DetectionExecution not found: {execution_id}")


class DetectionFindingNotFound(DomainException):
    def __init__(self, finding_id: str) -> None:
        super().__init__(f"DetectionFinding not found: {finding_id}")


class ExecutionLifecycleBlocked(DomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Execution lifecycle blocked: {reason}")


class FindingLifecycleBlocked(DomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Finding lifecycle blocked: {reason}")


class FindingDedupConflict(DomainException):
    def __init__(self, finding_key: str) -> None:
        super().__init__(f"Finding deduplicated under key: {finding_key}")


class DetectionPackNotFound(DomainException):
    def __init__(self, pack_id: str) -> None:
        super().__init__(f"DetectionPack not found: {pack_id}")


class DetectionPackAlreadyExists(DomainException):
    def __init__(self, pack_key: str) -> None:
        super().__init__(f"DetectionPack already exists: {pack_key}")


class DetectionExceptionNotFound(DomainException):
    def __init__(self, exception_id: str) -> None:
        super().__init__(f"DetectionException not found: {exception_id}")


class DetectionEvidenceNotFound(DomainException):
    def __init__(self, evidence_id: str) -> None:
        super().__init__(f"DetectionEvidence not found: {evidence_id}")


class PackLifecycleBlocked(DomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Pack lifecycle blocked: {reason}")


class ExceptionLifecycleBlocked(DomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Exception lifecycle blocked: {reason}")


class EvidenceImmutable(DomainException):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Evidence immutable: {reason}")


class ComplianceAcknowledgementRequired(DomainException):
    def __init__(self) -> None:
        super().__init__(
            "ComplianceImpactAcknowledged required for compliance-mapped rules"
        )
