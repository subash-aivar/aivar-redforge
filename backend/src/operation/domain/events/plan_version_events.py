"""Domain events for ExecutionPlanVersion."""

from __future__ import annotations

from dataclasses import dataclass

from operation.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanVersionCreated(BaseDomainEvent):
    operation_id: str
    version_number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanVersionSigned(BaseDomainEvent):
    operation_id: str
    version_number: int
    plan_hash: str
    signed_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanVersionSuperseded(BaseDomainEvent):
    operation_id: str
    version_number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanVersionExecuting(BaseDomainEvent):
    operation_id: str
    version_number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanVersionExecuted(BaseDomainEvent):
    operation_id: str
    version_number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionPlanVersionArchived(BaseDomainEvent):
    operation_id: str
    version_number: int
