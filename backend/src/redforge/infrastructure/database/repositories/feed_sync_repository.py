"""SQLAlchemy repositories for the Feed Synchronization Foundation
sub-context — M22 Phase 2.

Same conventions as `threat_intel_reference_data_repository.py` (M22
Phase 1): SAVEPOINT (`begin_nested`) + catch-`IntegrityError` for
inserts that race against a unique constraint, translated into the
domain-level conflict exception the caller actually wants
(`DuplicateFeedKeyError`, `FeedSyncAlreadyRunningError`) rather than
leaking a raw `IntegrityError` past the repository boundary.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, TypeVar

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import Select

from redforge.domain.threat_intel.feed_entity import Feed
from redforge.domain.threat_intel.feed_exceptions import (
    DuplicateFeedKeyError,
    FeedSyncAlreadyRunningError,
)
from redforge.domain.threat_intel.feed_sync_run_entity import FeedSyncRun
from redforge.domain.threat_intel.feed_value_objects import (
    FeedKey,
    FeedSourceKind,
    FeedStatus,
    FeedSyncRunStatus,
    FeedSyncTrigger,
    RetryPolicy,
    SyncSchedule,
)
from redforge.domain.threat_intel.reference_data_value_objects import IngestionScope
from redforge.infrastructure.database.models.feed_sync import FeedModel, FeedSyncRunModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_SelectT = TypeVar("_SelectT", bound=Select[Any])


# ─── Mappers: ORM <-> domain aggregate ───────────────────────────────────────


def _feed_to_domain(model: FeedModel) -> Feed:
    return Feed(
        id=model.id,
        feed_key=FeedKey(model.feed_key),
        display_name=model.display_name,
        source_kind=FeedSourceKind(model.source_kind),
        scope=IngestionScope(model.scope),
        organization_id=model.organization_id,
        status=FeedStatus(model.status),
        connector_config=model.connector_config,
        credential_ref=model.credential_ref,
        schedule=SyncSchedule(interval_seconds=model.schedule_interval_seconds),
        retry_policy=RetryPolicy(
            max_attempts=model.retry_max_attempts,
            base_delay_seconds=model.retry_base_delay_seconds,
            max_delay_seconds=model.retry_max_delay_seconds,
            jitter_factor=model.retry_jitter_factor,
        ),
        checkpoint=model.checkpoint,
        consecutive_failure_count=model.consecutive_failure_count,
        last_sync_started_at=model.last_sync_started_at,
        last_sync_completed_at=model.last_sync_completed_at,
        last_sync_status=(
            FeedSyncRunStatus(model.last_sync_status) if model.last_sync_status else None
        ),
        next_sync_due_at=model.next_sync_due_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
        created_by=model.created_by,
        updated_by=model.updated_by,
    )


def _apply_feed_to_model(feed: Feed, model: FeedModel) -> None:
    model.id = feed.id
    model.feed_key = feed.feed_key.value
    model.display_name = feed.display_name
    model.source_kind = feed.source_kind.value
    model.scope = feed.scope.value
    model.organization_id = feed.organization_id
    model.status = feed.status.value
    model.connector_config = feed.connector_config
    model.credential_ref = feed.credential_ref
    model.schedule_interval_seconds = feed.schedule.interval_seconds
    model.retry_max_attempts = feed.retry_policy.max_attempts
    model.retry_base_delay_seconds = feed.retry_policy.base_delay_seconds
    model.retry_max_delay_seconds = feed.retry_policy.max_delay_seconds
    model.retry_jitter_factor = feed.retry_policy.jitter_factor
    model.checkpoint = feed.checkpoint
    model.consecutive_failure_count = feed.consecutive_failure_count
    model.last_sync_started_at = feed.last_sync_started_at
    model.last_sync_completed_at = feed.last_sync_completed_at
    model.last_sync_status = feed.last_sync_status.value if feed.last_sync_status else None
    model.next_sync_due_at = feed.next_sync_due_at
    model.created_at = feed.created_at
    model.updated_at = feed.updated_at
    model.created_by = feed.created_by
    model.updated_by = feed.updated_by


def _run_to_domain(model: FeedSyncRunModel) -> FeedSyncRun:
    return FeedSyncRun(
        id=model.id,
        feed_id=model.feed_id,
        status=FeedSyncRunStatus(model.status),
        trigger=FeedSyncTrigger(model.trigger),
        checkpoint_before=model.checkpoint_before,
        checkpoint_after=model.checkpoint_after,
        items_fetched=model.items_fetched,
        items_processed=model.items_processed,
        items_failed=model.items_failed,
        retry_attempts_used=model.retry_attempts_used,
        error_message=model.error_message,
        started_at=model.started_at,
        finished_at=model.finished_at,
        created_by=model.created_by,
    )


def _apply_run_to_model(run: FeedSyncRun, model: FeedSyncRunModel) -> None:
    model.id = run.id
    model.feed_id = run.feed_id
    model.status = run.status.value
    model.trigger = run.trigger.value
    model.checkpoint_before = run.checkpoint_before
    model.checkpoint_after = run.checkpoint_after
    model.items_fetched = run.items_fetched
    model.items_processed = run.items_processed
    model.items_failed = run.items_failed
    model.retry_attempts_used = run.retry_attempts_used
    model.error_message = run.error_message
    model.started_at = run.started_at
    model.finished_at = run.finished_at
    model.created_by = run.created_by


# ─── Repositories ─────────────────────────────────────────────────────────────


class SqlAlchemyFeedRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, feed: Feed) -> Feed:
        model = FeedModel()
        _apply_feed_to_model(feed, model)
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
        except IntegrityError as exc:
            raise DuplicateFeedKeyError(feed.feed_key.value) from exc
        return _feed_to_domain(model)

    async def update(self, feed: Feed) -> Feed:
        model = await self._session.get(FeedModel, feed.id)
        if model is None:
            raise LookupError(f"Feed {feed.id} does not exist")
        _apply_feed_to_model(feed, model)
        await self._session.flush()
        return _feed_to_domain(model)

    async def get_by_id(self, feed_id: str) -> Feed | None:
        model = await self._session.get(FeedModel, feed_id)
        return _feed_to_domain(model) if model else None

    async def find_by_key(
        self,
        feed_key: str,
        *,
        scope: IngestionScope,
        organization_id: str | None = None,
    ) -> Feed | None:
        stmt = select(FeedModel).where(
            FeedModel.feed_key == feed_key, FeedModel.scope == scope.value
        )
        if scope is IngestionScope.GLOBAL:
            stmt = stmt.where(FeedModel.organization_id.is_(None))
        else:
            stmt = stmt.where(FeedModel.organization_id == organization_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _feed_to_domain(model) if model else None

    async def list_all(
        self,
        *,
        scope: IngestionScope | None = None,
        organization_id: str | None = None,
        status: FeedStatus | None = None,
        source_kind: FeedSourceKind | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Feed]:
        stmt = select(FeedModel).order_by(FeedModel.created_at)
        stmt = self._apply_filters(
            stmt, scope=scope, organization_id=organization_id, status=status
        )
        if source_kind is not None:
            stmt = stmt.where(FeedModel.source_kind == source_kind.value)
        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [_feed_to_domain(m) for m in result.scalars().all()]

    async def count(
        self,
        *,
        scope: IngestionScope | None = None,
        organization_id: str | None = None,
        status: FeedStatus | None = None,
    ) -> int:
        stmt = select(func.count()).select_from(FeedModel)
        stmt = self._apply_filters(
            stmt, scope=scope, organization_id=organization_id, status=status
        )
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def list_due_for_sync(self, *, now: datetime, limit: int = 50) -> list[Feed]:
        stmt = (
            select(FeedModel)
            .where(
                FeedModel.status == FeedStatus.ACTIVE.value,
                FeedModel.next_sync_due_at.is_not(None),
                FeedModel.next_sync_due_at <= now,
            )
            .order_by(FeedModel.next_sync_due_at)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_feed_to_domain(m) for m in result.scalars().all()]

    @staticmethod
    def _apply_filters(
        stmt: _SelectT,
        *,
        scope: IngestionScope | None,
        organization_id: str | None,
        status: FeedStatus | None,
    ) -> _SelectT:
        if scope is not None:
            stmt = stmt.where(FeedModel.scope == scope.value)
        if organization_id is not None:
            stmt = stmt.where(FeedModel.organization_id == organization_id)
        if status is not None:
            stmt = stmt.where(FeedModel.status == status.value)
        return stmt


class SqlAlchemyFeedSyncRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, run: FeedSyncRun) -> FeedSyncRun:
        model = FeedSyncRunModel()
        _apply_run_to_model(run, model)
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
        except IntegrityError as exc:
            raise FeedSyncAlreadyRunningError(run.feed_id) from exc
        return _run_to_domain(model)

    async def update(self, run: FeedSyncRun) -> FeedSyncRun:
        model = await self._session.get(FeedSyncRunModel, run.id)
        if model is None:
            raise LookupError(f"FeedSyncRun {run.id} does not exist")
        _apply_run_to_model(run, model)
        await self._session.flush()
        return _run_to_domain(model)

    async def get_by_id(self, run_id: str) -> FeedSyncRun | None:
        model = await self._session.get(FeedSyncRunModel, run_id)
        return _run_to_domain(model) if model else None

    async def get_active_run_for_feed(self, feed_id: str) -> FeedSyncRun | None:
        stmt = select(FeedSyncRunModel).where(
            FeedSyncRunModel.feed_id == feed_id,
            FeedSyncRunModel.status.in_(
                [FeedSyncRunStatus.PENDING.value, FeedSyncRunStatus.RUNNING.value]
            ),
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _run_to_domain(model) if model else None

    async def list_by_feed(
        self, feed_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[FeedSyncRun]:
        stmt = (
            select(FeedSyncRunModel)
            .where(FeedSyncRunModel.feed_id == feed_id)
            .order_by(FeedSyncRunModel.started_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_run_to_domain(m) for m in result.scalars().all()]

    async def count_by_feed(self, feed_id: str) -> int:
        result = await self._session.execute(
            select(func.count())
            .select_from(FeedSyncRunModel)
            .where(FeedSyncRunModel.feed_id == feed_id)
        )
        return int(result.scalar_one())
