"""Queries for engagement read use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetEngagementQuery:
    tenant_id: UUID
    engagement_id: UUID


@dataclass(frozen=True, slots=True)
class ListEngagementsQuery:
    tenant_id: UUID
    state: str | None = None
    active_only: bool = False


@dataclass(frozen=True, slots=True)
class GetTargetAuthorizationQuery:
    tenant_id: UUID
    authorization_id: UUID


@dataclass(frozen=True, slots=True)
class ListTargetAuthorizationsQuery:
    tenant_id: UUID
    engagement_id: UUID
