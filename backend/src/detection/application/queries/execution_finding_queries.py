"""Queries for executions and findings."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from detection.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetExecution:
    tenant_id: TenantId
    execution_id: UUID


@dataclass(frozen=True, slots=True)
class ListExecutions:
    tenant_id: TenantId
    limit: int = 100
    offset: int = 0
    state: str | None = None


@dataclass(frozen=True, slots=True)
class GetFinding:
    tenant_id: TenantId
    finding_id: UUID


@dataclass(frozen=True, slots=True)
class ListFindings:
    tenant_id: TenantId
    limit: int = 100
    offset: int = 0
    open_only: bool = False
    asset_id: str | None = None
