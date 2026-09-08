"""Typed identifiers for intelligence_relationships (M51.4 Phase C1).

`TenantId` reuses the shared platform `EntityId` (ULID-backed) per
ADR-0005 — the same shared-kernel reuse `ioc_intelligence`,
`threat_actor_intel` and `attack_pattern_intel` already established.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class IntelligenceRelationshipId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("IntelligenceRelationshipId must not be nil UUID")

    @classmethod
    def generate(cls) -> IntelligenceRelationshipId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
