"""Detection rule query dataclasses (CQRS read side)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GetRule:
    tenant_id: UUID
    rule_id: UUID


@dataclass(frozen=True, slots=True)
class ListRules:
    tenant_id: UUID
    limit: int = 100
    offset: int = 0
    lifecycle_state: str | None = None
