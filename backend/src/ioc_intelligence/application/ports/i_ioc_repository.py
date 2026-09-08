"""IIocRepository — implementation-independent (no ORM/DB types), per
M51.2 Phase A2 scope. `tenant_id=None` addresses the global scope;
a real `TenantId` addresses that tenant's own scope only. A concrete
adapter must never return a record whose `tenant_id` does not exactly
match the requested scope — that mismatch is what gives cross-tenant
reads/mutations established not-found semantics at the application
layer, without the repository itself knowing about authorization."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ioc_intelligence.application.queries.ioc_queries import IocSortField, SortDirection

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from ioc_intelligence.application.queries.ioc_queries import ValidityFilter
    from ioc_intelligence.domain.aggregates.ioc import IOC
    from ioc_intelligence.domain.value_objects.enums import (
        EpistemicState,
        IocLifecycle,
        IocType,
        SourceConfidence,
    )
    from ioc_intelligence.domain.value_objects.identifiers import IocId, TenantId
    from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey


class IIocRepository(ABC):
    @abstractmethod
    async def save(self, ioc: IOC) -> None: ...

    @abstractmethod
    async def get(self, tenant_id: TenantId | None, ioc_id: IocId) -> IOC | None: ...

    @abstractmethod
    async def get_any(self, ioc_id: IocId) -> IOC | None:
        """Unscoped lookup by ID only — used exclusively to resolve an
        IOC's ownership scope (its `tenant_id`) for the API layer's
        ownership-based authorization decision (M51.2 Phase A4.1). The
        caller must authorize before using anything from the returned
        aggregate beyond `.tenant_id`; this method performs no
        authorization itself."""
        ...

    @abstractmethod
    async def get_by_canonical_key(
        self, tenant_id: TenantId | None, canonical_key: IndicatorCanonicalKey
    ) -> IOC | None: ...

    @abstractmethod
    async def list_and_count(
        self,
        tenant_id: TenantId | None,
        *,
        lifecycle: IocLifecycle | None = None,
        epistemic_state: EpistemicState | None = None,
        ioc_type: IocType | None = None,
        search: str | None = None,
        confidence: SourceConfidence | None = None,
        source_system: str | None = None,
        validity: ValidityFilter | None = None,
        sort_by: IocSortField = IocSortField.CREATED_AT,
        sort_dir: SortDirection = SortDirection.DESC,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[IOC], int]:
        """Return exactly one page of IOCs matching every supplied
        filter, ordered by `sort_by`/`sort_dir` with a deterministic
        secondary tiebreaker, alongside the TOTAL number of rows that
        match those same filters across the ENTIRE dataset (computed
        from the same filtered query, before `limit`/`offset` — never
        `len(page)`). `confidence`/`source_system` filter against the
        IOC's child `source_attributions` (an IOC matches if ANY of its
        attributions matches); every other filter is a plain column
        predicate on the IOC row itself. `search` matches the
        indicator's own normalized canonical value only."""
        ...

    @abstractmethod
    async def list_lapsed_active(self, now: datetime, limit: int = 200) -> Sequence[IOC]:
        """Across ALL scopes (tenant and global) — every ACTIVE IOC whose
        `valid_until` has already passed `now`. Used only by the bounded
        expiry-sweep maintenance operation (M51.2 Slice 2); this is the
        one intentional cross-tenant read in this repository, scoped by
        `lifecycle=ACTIVE AND valid_until < now`, not by any client
        input, and it returns full aggregates only for a mutation this
        context itself performs (mark_expired) — never exposed as a
        cross-tenant read to any caller."""
        ...
