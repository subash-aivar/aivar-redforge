from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
# Phase 1 convergence: no local UUID-backed TenantId type.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class ForecastId:
    value: UUID

    @classmethod
    def generate(cls) -> ForecastId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
