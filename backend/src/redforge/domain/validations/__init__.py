"""Validation bounded context.

Models the business concept of a Validation Run — a single execution
of security validation against an AI Target. Tracks lifecycle from
scheduling through completion or failure.

Public API:
    - ValidationRun: Aggregate root with lifecycle behavior.
    - ValidationRunRepository: Persistence interface (Protocol).
    - Value objects: ValidationStatus, TriggerType, ValidationSummary.
    - Events: ValidationStarted, ValidationCompleted, etc.
    - Exceptions: ValidationRunNotFoundError, etc.
"""

from redforge.domain.validations.entity import ValidationRun
from redforge.domain.validations.repository import ValidationRunRepository
from redforge.domain.validations.value_objects import (
    TriggerType,
    ValidationStatus,
    ValidationSummary,
)

__all__ = [
    "TriggerType",
    "ValidationRun",
    "ValidationRunRepository",
    "ValidationStatus",
    "ValidationSummary",
]
