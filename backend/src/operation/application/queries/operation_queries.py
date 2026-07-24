"""Queries for operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from operation.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetOperation:
    tenant_id: TenantId
    operation_id: UUID


@dataclass(frozen=True, slots=True)
class ListOperationsByEngagement:
    tenant_id: TenantId
    engagement_id: UUID
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class GetExecutionPlanVersion:
    tenant_id: TenantId
    plan_version_id: UUID


@dataclass(frozen=True, slots=True)
class ListPlanVersionsByOperation:
    tenant_id: TenantId
    operation_id: UUID
