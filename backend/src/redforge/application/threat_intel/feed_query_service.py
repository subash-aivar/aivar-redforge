"""Feed query service — M22 Phase 2 (Feed Synchronization Foundation).

Read-only queries over `Feed` and `FeedSyncRun`. No mutation, no audit
logging — mirrors the read-only half of `ReferenceDataAdminService`'s
sibling query services (M22 Phase 1's API layer queries repositories
directly for reads; this service exists instead because Phase 2 has a
second aggregate — `FeedSyncRun` — whose reads need to be composed
with `Feed` reads, e.g. `get_feed_with_active_run`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.core.exceptions import NotFoundError
from redforge.domain.threat_intel.feed_entity import Feed
from redforge.domain.threat_intel.feed_sync_run_entity import FeedSyncRun
from redforge.domain.threat_intel.feed_value_objects import FeedSourceKind, FeedStatus
from redforge.domain.threat_intel.reference_data_value_objects import IngestionScope
from redforge.infrastructure.database.repositories.feed_sync_repository import (
    SqlAlchemyFeedRepository,
    SqlAlchemyFeedSyncRunRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class FeedQueryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_feed(self, feed_id: str) -> Feed:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyFeedRepository(uow.session)
            feed = await repo.get_by_id(feed_id)
        if feed is None:
            raise NotFoundError("Feed", feed_id)
        return feed

    async def list_feeds(
        self,
        *,
        scope: IngestionScope | None = None,
        organization_id: str | None = None,
        status: FeedStatus | None = None,
        source_kind: FeedSourceKind | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[Feed], int]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyFeedRepository(uow.session)
            feeds = await repo.list_all(
                scope=scope,
                organization_id=organization_id,
                status=status,
                source_kind=source_kind,
                limit=limit,
                offset=offset,
            )
            total = await repo.count(scope=scope, organization_id=organization_id, status=status)
        return feeds, total

    async def list_sync_runs(
        self, feed_id: str, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[FeedSyncRun], int]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            feed_repo = SqlAlchemyFeedRepository(uow.session)
            feed = await feed_repo.get_by_id(feed_id)
            if feed is None:
                raise NotFoundError("Feed", feed_id)
            run_repo = SqlAlchemyFeedSyncRunRepository(uow.session)
            runs = await run_repo.list_by_feed(feed_id, limit=limit, offset=offset)
            total = await run_repo.count_by_feed(feed_id)
        return runs, total

    async def get_sync_run(self, feed_id: str, run_id: str) -> FeedSyncRun:
        async with SessionUnitOfWork(self._session_factory) as uow:
            run_repo = SqlAlchemyFeedSyncRunRepository(uow.session)
            run = await run_repo.get_by_id(run_id)
        if run is None or run.feed_id != feed_id:
            raise NotFoundError("FeedSyncRun", run_id)
        return run
