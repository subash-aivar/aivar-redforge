"""Frozen enums for automated_action BC (M35)."""

from __future__ import annotations

from enum import StrEnum


class ActionImpactLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConnectorFailureMode(StrEnum):
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILURE = "AUTH_FAILURE"
    CLIENT_ERROR = "CLIENT_ERROR"
    SERVER_ERROR = "SERVER_ERROR"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"


class ExecutionStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    AWAITING_AUTHORIZATION = "AWAITING_AUTHORIZATION"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    ESCALATED = "ESCALATED"


class ActionRecordStatus(StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"


class ActionOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


class RollbackStatus(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EscalationResolution(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"
