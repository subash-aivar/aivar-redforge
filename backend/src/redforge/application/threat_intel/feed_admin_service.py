"""Feed admin service — M22 Phase 2 (Feed Synchronization Foundation).

CRUD-level application service for registering and managing the
lifecycle/configuration of a `Feed`. Deliberately contains NO
synchronization orchestration — see `feed_sync_orchestration_service
.py` for that. Mirrors the exact `SessionUnitOfWork` + repository +
audit + commit shape `ReferenceDataAdminService` (M22 Phase 1) and
`InvestigationCaseService` (M21) already establish.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from redforge.core.exceptions import NotFoundError
from redforge.domain.threat_intel.feed_entity import Feed
from redforge.domain.threat_intel.feed_value_objects import (
    FeedKey,
    FeedSourceKind,
    RetryPolicy,
    SyncSchedule,
)
from redforge.domain.threat_intel.reference_data_value_objects import IngestionScope
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.feed_sync_repository import (
    SqlAlchemyFeedRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class FeedAdminService:
    """Commands: register, configure, and transition the lifecycle of a
    `Feed`. Every method commits exactly one `Feed` mutation inside a
    single transaction and records a platform audit entry."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def register_feed(
        self,
        *,
        actor_id: str,
        feed_key: str,
        display_name: str,
        source_kind: str,
        interval_seconds: int,
        scope: IngestionScope = IngestionScope.GLOBAL,
        organization_id: str | None = None,
        connector_config: dict[str, Any] | None = None,
        credential_ref: str | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> Feed:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyFeedRepository(uow.session)
            feed = Feed.register(
                id=str(EntityId.generate()),
                feed_key=FeedKey(feed_key),
                display_name=display_name,
                source_kind=FeedSourceKind(source_kind),
                schedule=SyncSchedule(interval_seconds=interval_seconds),
                actor_id=actor_id,
                scope=scope,
                organization_id=organization_id,
                connector_config=connector_config,
                credential_ref=credential_ref,
                retry_policy=retry_policy,
            )
            feed.collect_events()
            feed = await repo.add(feed)
            await self._audit(
                uow.session, action=AuditAction.FEED_REGISTERED, actor_id=actor_id, feed=feed
            )
            await uow.commit()
        return feed

    async def update_configuration(
        self,
        *,
        actor_id: str,
        feed_id: str,
        display_name: str | None = None,
        connector_config: dict[str, Any] | None = None,
        credential_ref: str | None = None,
        interval_seconds: int | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> Feed:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyFeedRepository(uow.session)
            feed = await repo.get_by_id(feed_id)
            if feed is None:
                raise NotFoundError("Feed", feed_id)
            schedule = (
                SyncSchedule(interval_seconds=interval_seconds)
                if interval_seconds is not None
                else None
            )
            feed.update_configuration(
                actor_id=actor_id,
                display_name=display_name,
                connector_config=connector_config,
                credential_ref=credential_ref,
                schedule=schedule,
                retry_policy=retry_policy,
            )
            feed = await repo.update(feed)
            await self._audit(
                uow.session,
                action=AuditAction.FEED_CONFIGURATION_UPDATED,
                actor_id=actor_id,
                feed=feed,
            )
            await uow.commit()
        return feed

    async def activate_feed(self, *, actor_id: str, feed_id: str) -> Feed:
        return await self._transition(
            actor_id=actor_id,
            feed_id=feed_id,
            action=AuditAction.FEED_ACTIVATED,
            transition=lambda feed: feed.activate(actor_id=actor_id),
        )

    async def pause_feed(self, *, actor_id: str, feed_id: str) -> Feed:
        return await self._transition(
            actor_id=actor_id,
            feed_id=feed_id,
            action=AuditAction.FEED_PAUSED,
            transition=lambda feed: feed.pause(actor_id=actor_id),
        )

    async def disable_feed(self, *, actor_id: str, feed_id: str) -> Feed:
        return await self._transition(
            actor_id=actor_id,
            feed_id=feed_id,
            action=AuditAction.FEED_DISABLED,
            transition=lambda feed: feed.disable(actor_id=actor_id),
        )

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _transition(
        self,
        *,
        actor_id: str,
        feed_id: str,
        action: AuditAction,
        transition: Any,
    ) -> Feed:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyFeedRepository(uow.session)
            feed = await repo.get_by_id(feed_id)
            if feed is None:
                raise NotFoundError("Feed", feed_id)
            transition(feed)
            feed.collect_events()
            feed = await repo.update(feed)
            await self._audit(uow.session, action=action, actor_id=actor_id, feed=feed)
            await uow.commit()
        return feed

    async def _audit(
        self,
        session: AsyncSession,
        *,
        action: AuditAction,
        actor_id: str,
        feed: Feed,
    ) -> None:
        await PostgresPlatformAuditLog(session).record(
            AuditEntry(
                action=action,
                actor_id=actor_id,
                resource_type="feed",
                resource_id=feed.id,
                metadata={
                    "feed_key": feed.feed_key.value,
                    "source_kind": feed.source_kind.value,
                    "scope": feed.scope.value,
                    "status": feed.status.value,
                },
            )
        )
