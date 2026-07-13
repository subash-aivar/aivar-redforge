"""Gated Safe Active Validation bounded context (M11).

The first real execution layer behind M10's ExecutionPolicyService
boundary: bounded, non-destructive, real network validation (DNS/TCP/
TLS/HTTP) against an authorized canonical AITarget.
"""

from redforge.domain.validation_execution.entity import ValidationExecution, ValidationStep
from redforge.domain.validation_execution.execution_event import ExecutionEvent
from redforge.domain.validation_execution.repository import (
    ExecutionEventRepository,
    ValidationExecutionRepository,
)
from redforge.domain.validation_execution.value_objects import (
    AddressClass,
    ErrorCategory,
    ExecutionEventType,
    ExecutionLimits,
    ExecutionStatus,
    StepStatus,
    StepType,
    ValidationProfile,
)

__all__ = [
    "AddressClass",
    "ErrorCategory",
    "ExecutionEvent",
    "ExecutionEventRepository",
    "ExecutionEventType",
    "ExecutionLimits",
    "ExecutionStatus",
    "StepStatus",
    "StepType",
    "ValidationExecution",
    "ValidationExecutionRepository",
    "ValidationProfile",
    "ValidationStep",
]
