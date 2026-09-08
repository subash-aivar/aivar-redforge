"""IAttackPatternRepository — implementation-independent (no ORM/DB
types), M51.3 Phase B1. `tenant_id=None` addresses the global scope; a
real `TenantId` addresses that tenant's own scope only. A concrete
adapter must never return a record whose `tenant_id` does not exactly
match the requested scope, mirroring `IIocRepository`'s exact
not-found-semantics discipline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
    from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus
    from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId, TenantId


class IAttackPatternRepository(ABC):
    @abstractmethod
    async def save(self, pattern: AttackPattern) -> None: ...

    @abstractmethod
    async def get(
        self, tenant_id: TenantId | None, attack_pattern_id: AttackPatternId
    ) -> AttackPattern | None: ...

    @abstractmethod
    async def get_any(self, attack_pattern_id: AttackPatternId) -> AttackPattern | None:
        """Unscoped lookup by ID only — used exclusively to resolve an
        AttackPattern's ownership scope (its `tenant_id`) for the API
        layer's ownership-based authorization decision. The caller
        must authorize before using anything from the returned
        aggregate beyond `.tenant_id`."""
        ...

    @abstractmethod
    async def get_by_technique_id(
        self, tenant_id: TenantId | None, effective_technique_id: str
    ) -> AttackPattern | None: ...

    @abstractmethod
    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: TechniqueLifecycleStatus | None = None,
        tactic_id: str | None = None,
        platform: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackPattern]: ...
