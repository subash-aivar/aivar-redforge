"""DTOs for the TaskGraph application service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class TaskGraphDTO:
    graph_id: UUID
    tenant_id: UUID
    name: str
    description: str
    state: str
    version_str: str
    task_count: int
    dependency_count: int
    engagement_window_seconds: int
    signed_by: str | None
    signed_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class TaskDTO:
    task_id: UUID
    task_type: str
    name: str
    criticality: str
    timeout_seconds: int
    task_group_id: str | None


@dataclass(frozen=True, slots=True)
class ValidationResultDTO:
    is_valid: bool
    errors: list[str]


@dataclass(frozen=True, slots=True)
class ExecutionOrderDTO:
    layers: list[list[str]]
    critical_path_duration_seconds: int
