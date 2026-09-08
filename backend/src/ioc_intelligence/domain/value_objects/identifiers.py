"""Typed identifiers for ioc_intelligence (M51.2 Phase A).

`TenantId` reuses the shared platform `EntityId` (ULID-backed), the
same shared-kernel reuse `threat_actor_intel.domain.value_objects.
identifiers` already established per ADR-0005 — this is the one
legitimate cross-cutting import (the platform's own shared kernel,
not another bounded context's private domain type).
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class IocId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("IocId must not be nil UUID")

    @classmethod
    def generate(cls) -> IocId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
