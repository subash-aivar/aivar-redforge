"""Feed sync orchestration service — M22 Phase 2 (Feed Synchronization
Foundation).

The one application service that actually *runs* a synchronization
attempt for a `Feed`, coordinating:

- a PostgreSQL advisory lock (per-feed, SHA-256-derived key — same
  pattern as `application.ddos.incident_service._advisory_lock_key`)
  serializing concurrent `trigger_sync` calls for the same feed across
  every application process;
- the database-level idempotency backstop (`ux_fsr_feed_active_run`,
  migration 0036) that still holds even if the advisory lock is ever
  bypassed by a bug;
- `RetryExecutor` (application.platform.retry_strategy) applying the
  feed's own `RetryPolicy` as exponential backoff across connector
  attempts — never a hand-rolled backoff loop here;
- the `FeedConnectorRegistry` seam — this service never imports,
  names, or special-cases a concrete connector; it only knows
  `FeedSyncExecutor` the Protocol.

Deliberately split into three separate short-lived transactions
(`_start_run`, connector execution, `_finalize_run`) rather than one
transaction spanning the whole sync: a connector call is external I/O
of unbounded duration (Phase 3's actual STIX/TAXII/HTTP fetch), and
holding a database connection — or the advisory lock — open for that
duration would starve the connection pool and serialize unrelated
feeds' syncs behind one slow external endpoint.
"""

from __future__ import annotations

import hashlib
import struct
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import text

from redforge.application.platform.retry_strategy import RetryConfig, RetryExecutor
from redforge.application.threat_intel.feed_connector import (
    FeedConnectorRegistry,
    FeedSyncContext,
    FeedSyncExecutor,
    FeedSyncOutcome,
)
from redforge.core.exceptions import NotFoundError
from redforge.domain.threat_intel.feed_exceptions import (
    FeedNotActiveError,
    FeedSyncAlreadyRunningError,
    UnknownFeedConnectorError,
)
from redforge.domain.threat_intel.feed_sync_run_entity import FeedSyncRun
from redforge.domain.threat_intel.feed_value_objects import FeedSyncTrigger
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.feed_sync_repository import (
    SqlAlchemyFeedRepository,
    SqlAlchemyFeedSyncRunRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _advisory_lock_key(feed_id: str) -> int:
    """Stable 32-bit advisory lock key for one `feed_id`.

    SHA-256 keeps the value deterministic across Python processes
    (`hash()` is per-process-randomized); `pg_advisory_xact_lock`
    accepts a 64-bit signed integer, so the first 4 bytes interpreted
    as an unsigned int always fits without overflow. Same derivation
    `application.ddos.incident_service._advisory_lock_key` uses.
    """
    digest = hashlib.sha256(f"feed_sync:{feed_id}".encode()).digest()
    return int(struct.unpack(">I", digest[:4])[0])


class FeedSyncOrchestrationService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        connector_registry: FeedConnectorRegistry,
    ) -> None:
        self._session_factory = session_factory
        self._connector_registry = connector_registry

    async def trigger_sync(
        self,
        *,
        feed_id: str,
        trigger: FeedSyncTrigger,
        actor_id: str,
    ) -> FeedSyncRun:
        """Run exactly one synchronization attempt (including its
        internal retry/backoff cycle) for `feed_id`, end to end, and
        return the finalized `FeedSyncRun`.

        Raises `NotFoundError` (no such feed), `FeedNotActiveError`
        (feed is not ACTIVE), `FeedSyncAlreadyRunningError` (a run is
        already in flight), or `UnknownFeedConnectorError` (no
        connector registered for this feed's `source_kind` — expected
        for every feed until a Phase 3 connector registers) before any
        external call is attempted.
        """
        run, context, retry_config, executor = await self._start_run(
            feed_id=feed_id, trigger=trigger, actor_id=actor_id
        )
        outcome, error, attempts_used = await self._execute_with_retry(
            executor=executor, context=context, retry_config=retry_config
        )
        return await self._finalize_run(
            run_id=run.id,
            feed_id=feed_id,
            actor_id=actor_id,
            outcome=outcome,
            error=error,
            attempts_used=attempts_used,
        )

    # ── Phase 1: acquire lock, validate, start the run ──────────────────

    async def _start_run(
        self,
        *,
        feed_id: str,
        trigger: FeedSyncTrigger,
        actor_id: str,
    ) -> tuple[FeedSyncRun, FeedSyncContext, RetryConfig, FeedSyncExecutor]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            await uow.session.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _advisory_lock_key(feed_id)},
            )

            feed_repo = SqlAlchemyFeedRepository(uow.session)
            feed = await feed_repo.get_by_id(feed_id)
            if feed is None:
                raise NotFoundError("Feed", feed_id)
            if not feed.is_syncable:
                raise FeedNotActiveError(feed_id, feed.status.value)

            run_repo = SqlAlchemyFeedSyncRunRepository(uow.session)
            if await run_repo.get_active_run_for_feed(feed_id) is not None:
                raise FeedSyncAlreadyRunningError(feed_id)

            executor = self._connector_registry.get(feed.source_kind)
            if executor is None:
                raise UnknownFeedConnectorError(feed.source_kind.value)

            run = FeedSyncRun.start(
                id=str(EntityId.generate()),
                feed_id=feed_id,
                trigger=trigger,
                checkpoint_before=feed.checkpoint,
                created_by=actor_id,
            )
            run.collect_events()
            run = await run_repo.add(run)

            feed.record_sync_started()
            feed = await feed_repo.update(feed)

            context = FeedSyncContext(
                feed_id=feed.id,
                feed_key=feed.feed_key.value,
                source_kind=feed.source_kind,
                connector_config=feed.connector_config,
                credential_ref=feed.credential_ref,
                checkpoint=feed.checkpoint,
            )
            retry_config = RetryConfig(
                max_attempts=feed.retry_policy.max_attempts,
                base_delay_s=feed.retry_policy.base_delay_seconds,
                max_delay_s=feed.retry_policy.max_delay_seconds,
                jitter_factor=feed.retry_policy.jitter_factor,
            )
            await uow.commit()
        return run, context, retry_config, executor

    # ── Phase 2: run the connector, outside any open transaction ────────

    async def _execute_with_retry(
        self,
        *,
        executor: FeedSyncExecutor,
        context: FeedSyncContext,
        retry_config: RetryConfig,
    ) -> tuple[FeedSyncOutcome | None, BaseException | None, int]:
        result, outcome = await RetryExecutor(retry_config).execute_with_outcome(
            lambda: executor.execute(context),
            retryable_exceptions=(Exception,),
        )
        return result, outcome.last_error, outcome.attempts

    # ── Phase 3: finalize — new transaction, feed + run updated together ─

    async def _finalize_run(
        self,
        *,
        run_id: str,
        feed_id: str,
        actor_id: str,
        outcome: FeedSyncOutcome | None,
        error: BaseException | None,
        attempts_used: int,
    ) -> FeedSyncRun:
        async with SessionUnitOfWork(self._session_factory) as uow:
            run_repo = SqlAlchemyFeedSyncRunRepository(uow.session)
            feed_repo = SqlAlchemyFeedRepository(uow.session)

            run = await run_repo.get_by_id(run_id)
            feed = await feed_repo.get_by_id(feed_id)
            if run is None or feed is None:  # pragma: no cover - should be unreachable
                raise NotFoundError("FeedSyncRun", run_id)

            now = datetime.now(UTC)
            if outcome is not None:
                run.mark_succeeded(
                    checkpoint_after=outcome.checkpoint,
                    items_fetched=outcome.items_fetched,
                    items_processed=outcome.items_processed,
                    items_failed=outcome.items_failed,
                    retry_attempts_used=attempts_used,
                    now=now,
                )
                feed.record_sync_succeeded(checkpoint=outcome.checkpoint, now=now)
                audit_status = "succeeded"
            else:
                run.mark_failed(
                    error_message=str(error) if error else "sync failed",
                    retry_attempts_used=attempts_used,
                    now=now,
                )
                feed.record_sync_failed(now=now)
                audit_status = "failed"
            run.collect_events()

            run = await run_repo.update(run)
            await feed_repo.update(feed)

            await PostgresPlatformAuditLog(uow.session).record(
                AuditEntry(
                    action=AuditAction.FEED_SYNC_TRIGGERED,
                    actor_id=actor_id,
                    resource_type="feed",
                    resource_id=feed_id,
                    metadata={
                        "run_id": run_id,
                        "status": audit_status,
                        "retry_attempts_used": str(attempts_used),
                    },
                )
            )
            await uow.commit()
        return run
