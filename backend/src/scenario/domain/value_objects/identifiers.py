"""Scenario bounded context identifier value objects."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
# Phase 1 convergence: no local UUID-backed TenantId type.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class ScenarioTemplateId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value == UUID(int=0):
            raise ValueError("ScenarioTemplateId may not be the nil UUID")

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ScenarioTemplateId:
        from uuid import uuid4

        return cls(value=uuid4())
