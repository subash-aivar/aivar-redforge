"""Domain events for the TaskGraph aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from taskgraph.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskGraphCreated(BaseDomainEvent):
    name: str
    tenant_id_str: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskAdded(BaseDomainEvent):
    task_id: str
    task_type: str
    criticality: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskRemoved(BaseDomainEvent):
    task_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class DependencyAdded(BaseDomainEvent):
    predecessor_id: str
    successor_id: str
    predicate: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ConditionalBranchAdded(BaseDomainEvent):
    predecessor_id: str
    successor_id: str
    predicate: str
    objective_ref: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskGraphValidated(BaseDomainEvent):
    task_count: int
    dependency_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskGraphSigned(BaseDomainEvent):
    signed_by: str
    version_str: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskGraphActivated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class TaskGraphDeprecated(BaseDomainEvent):
    pass
