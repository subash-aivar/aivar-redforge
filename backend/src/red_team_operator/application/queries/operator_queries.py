"""Queries for RedTeamOperator read side."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetOperatorQuery:
    tenant_id: UUID
    operator_id: UUID


@dataclass(frozen=True, slots=True)
class ListOperatorsQuery:
    tenant_id: UUID
    include_inactive: bool = False
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class FindAuthorizedApproversQuery:
    tenant_id: UUID
    scope: str
