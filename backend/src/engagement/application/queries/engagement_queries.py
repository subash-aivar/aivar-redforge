"""Queries for engagement read use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from engagement.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetEngagementQuery:
    tenant_id: TenantId
    engagement_id: UUID


@dataclass(frozen=True, slots=True)
class ListEngagementsQuery:
    tenant_id: TenantId
    state: str | None = None
    active_only: bool = False


@dataclass(frozen=True, slots=True)
class GetTargetAuthorizationQuery:
    tenant_id: TenantId
    authorization_id: UUID


@dataclass(frozen=True, slots=True)
class ListTargetAuthorizationsQuery:
    tenant_id: TenantId
    engagement_id: UUID
