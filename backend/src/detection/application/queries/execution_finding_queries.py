"""Queries for executions and findings."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetExecution:
    tenant_id: UUID
    execution_id: UUID


@dataclass(frozen=True, slots=True)
class ListExecutions:
    tenant_id: UUID
    limit: int = 100
    offset: int = 0
    state: str | None = None


@dataclass(frozen=True, slots=True)
class GetFinding:
    tenant_id: UUID
    finding_id: UUID


@dataclass(frozen=True, slots=True)
class ListFindings:
    tenant_id: UUID
    limit: int = 100
    offset: int = 0
    open_only: bool = False
    asset_id: str | None = None
