"""Repository protocols for Threat Fusion — M22 Phase 4."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redforge.domain.threat_intel.fusion_entity import FusedIndicator, FusedRelationship
    from redforge.domain.threat_intel.fusion_value_objects import (
        CanonicalIndicatorKey,
        FusedIndicatorType,
        IndicatorLifecycle,
    )
    from redforge.domain.threat_intel.reference_data_value_objects import (
        AttackRelationshipType,
    )


class FusedIndicatorRepository(Protocol):
    async def get_by_id(self, indicator_id: str) -> FusedIndicator | None: ...

    async def get_by_canonical_key(
        self, key: CanonicalIndicatorKey
    ) -> FusedIndicator | None: ...

    async def upsert(self, indicator: FusedIndicator) -> FusedIndicator: ...

    async def list_by_type(
        self,
        indicator_type: FusedIndicatorType,
        *,
        lifecycle: IndicatorLifecycle | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FusedIndicator]: ...

    async def list_all_ids(self) -> set[str]: ...


class FusedRelationshipRepository(Protocol):
    async def upsert(self, relationship: FusedRelationship) -> FusedRelationship: ...

    async def list_for_indicator(
        self, indicator_id: str, *, limit: int = 200
    ) -> list[FusedRelationship]: ...

    async def list_by_type(
        self,
        relationship_type: AttackRelationshipType | None = None,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> list[FusedRelationship]: ...

    async def get_by_stix_id(self, stix_id: str) -> FusedRelationship | None: ...


class FusionConfigRepository(Protocol):
    """Persists admin overrides of default fusion source weights."""

    async def list_weights(self) -> list[tuple[str, float]]: ...

    async def upsert_weight(
        self, source_system: str, weight: float, *, actor_id: str
    ) -> None: ...
