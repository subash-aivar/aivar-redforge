"""Execution Engine bounded context.

Orchestrates the transformation of Validation Policies into executable plans.
Coordinates Provider Adapters and manages execution lifecycle including
retries, cancellation, timeouts, and failure strategies.

Public API:
    - ExecutionPlan: Aggregate root with lifecycle behavior.
    - ExecutionPlanRepository: Persistence interface (Protocol).
    - ProviderAdapter: Provider integration interface (Protocol).
    - Value objects: PlanStatus, ExecutionStage, ExecutionStep, etc.
"""

from redforge.domain.execution.entity import ExecutionPlan
from redforge.domain.execution.repository import ExecutionPlanRepository, ProviderAdapter
from redforge.domain.execution.value_objects import (
    ExecutionMode,
    ExecutionStage,
    ExecutionStep,
    FailureStrategy,
    PlanStatus,
    RetryPolicy,
    StepResult,
    StepStatus,
    TimeoutPolicy,
)

__all__ = [
    "ExecutionMode",
    "ExecutionPlan",
    "ExecutionPlanRepository",
    "ExecutionStage",
    "ExecutionStep",
    "FailureStrategy",
    "PlanStatus",
    "ProviderAdapter",
    "RetryPolicy",
    "StepResult",
    "StepStatus",
    "TimeoutPolicy",
]
