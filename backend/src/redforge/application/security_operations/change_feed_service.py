"""SecurityChangeFeedService — M15.

A bounded, filterable, paginated HISTORICAL view over the same
four-source merge `SecurityOperationsStreamService` uses for the live
SSE feed (see stream_service.py's own docstring for why a query-time
merge was chosen). Distinct from the raw per-execution event list: this
is the operator-relevant "what changed" feed — condition/correlation/
drift appear/resolve/reactivate, authorization blocked, validation
failed, protocol validated, runtime unhealthy — not every internal
step. No client-created feed entries are possible; every filter here is
closed/server-controlled (SourceDomain, OperationalImportance enums).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from redforge.application.security_operations.stream_service import fetch_merged_candidates
from redforge.domain.security_operations.value_objects import (
    CHANGE_FEED_MAX_PAGE_SIZE,
    BoundedPeriod,
    OperationalImportance,
    SourceDomain,
    bounded_period_seconds,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.domain.security_operations.operational_event import OperationalEvent


class SecurityChangeFeedService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_changes(
        self,
        organization_id: str,
        period: BoundedPeriod = BoundedPeriod.TWENTY_FOUR_HOURS,
        source_domain: SourceDomain | None = None,
        importance: OperationalImportance | None = None,
        entity_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[OperationalEvent]:
        limit = min(limit, CHANGE_FEED_MAX_PAGE_SIZE)
        since = datetime.now(UTC) - timedelta(seconds=bounded_period_seconds(period))
        # Fetch generously beyond the requested page so that filtering
        # (source_domain/importance/entity_id) + offset/limit still
        # yields a genuinely complete page rather than under-filling it
        # after the fact — bounded by CHANGE_FEED_MAX_PAGE_SIZE either way.
        per_source_limit = (offset + limit) * 4 + 50

        candidates = await fetch_merged_candidates(
            self._session_factory, organization_id, since, per_source_limit,
            apply_visibility_lag=False,
        )
        if source_domain is not None:
            candidates = [e for e in candidates if e.source_domain == source_domain]
        if importance is not None:
            candidates = [e for e in candidates if e.importance == importance]
        if entity_id is not None:
            candidates = [e for e in candidates if e.entity_id == entity_id]

        # Newest first for a historical feed (the live stream orders
        # oldest-first for resumability; this is a distinct, read-only
        # presentation order over the same underlying merge).
        candidates.sort(key=lambda e: e.cursor, reverse=True)
        return candidates[offset : offset + limit]
