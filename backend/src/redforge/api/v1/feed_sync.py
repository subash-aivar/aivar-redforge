"""Feed Synchronization Foundation — internal administration API.

M22 Phase 2 only. Lets a platform administrator register, configure,
lifecycle-manage, and manually trigger synchronization for a `Feed`,
plus inspect its execution history (`FeedSyncRun`). Every endpoint
requires a `PlatformPermission`, never a tenant `Permission` — a
future TENANT-scoped feed subscription is still administered
platform-side in Phase 2 (no tenant-facing endpoint exists).

Deliberately excluded from Phase 2 (per the explicit scope in this
milestone's implementation request): STIX parsing, a TAXII client,
Threat Fusion, the Attack Path Engine, Investigation integration, and
any frontend. `POST /feeds/{feed_id}/sync` will raise
`UnknownFeedConnectorError` (HTTP 422) for every feed until a later
phase registers a `FeedSyncExecutor` for its `source_kind`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from redforge.api.security import PlatformContext, require_platform_permission
from redforge.domain.platform_identity.value_objects import PlatformPermission
from redforge.domain.threat_intel.feed_value_objects import (
    FeedSourceKind,
    FeedStatus,
    FeedSyncTrigger,
    RetryPolicy,
)
from redforge.domain.threat_intel.reference_data_value_objects import IngestionScope

if TYPE_CHECKING:
    from redforge.domain.threat_intel.feed_entity import Feed
    from redforge.domain.threat_intel.feed_sync_run_entity import FeedSyncRun

router = APIRouter(prefix="/threat-intel/feeds", tags=["threat-intel-feed-sync"])


def _get_session_factory() -> object:
    from redforge.api.dependencies import get_session_factory

    return get_session_factory()


def _get_feed_connector_registry(request: Request) -> object:
    from redforge.api.dependencies import get_feed_connector_registry

    return get_feed_connector_registry(request)


# ─── Request models ─────────────────────────────────────────────────────────


class RegisterFeedRequest(BaseModel):
    feed_key: str = Field(..., min_length=3, max_length=64)
    display_name: str = Field(..., min_length=1, max_length=200)
    source_kind: str
    interval_seconds: int = Field(..., ge=1)
    scope: str = Field(default=IngestionScope.GLOBAL.value)
    organization_id: str | None = None
    connector_config: dict[str, Any] = Field(default_factory=dict)
    credential_ref: str | None = Field(default=None, max_length=200)
    retry_max_attempts: int = Field(default=3, ge=1)
    retry_base_delay_seconds: float = Field(default=1.0, ge=0.0)
    retry_max_delay_seconds: float = Field(default=30.0, ge=0.0)
    retry_jitter_factor: float = Field(default=0.25, ge=0.0, le=1.0)


class UpdateFeedConfigRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    connector_config: dict[str, Any] | None = None
    credential_ref: str | None = Field(default=None, max_length=200)
    interval_seconds: int | None = Field(default=None, ge=1)
    retry_max_attempts: int | None = Field(default=None, ge=1)
    retry_base_delay_seconds: float | None = Field(default=None, ge=0.0)
    retry_max_delay_seconds: float | None = Field(default=None, ge=0.0)
    retry_jitter_factor: float | None = Field(default=None, ge=0.0, le=1.0)


# ─── Response models ────────────────────────────────────────────────────────


class RetryPolicyResponse(BaseModel):
    max_attempts: int
    base_delay_seconds: float
    max_delay_seconds: float
    jitter_factor: float

    @classmethod
    def from_domain(cls, policy: RetryPolicy) -> RetryPolicyResponse:
        return cls(
            max_attempts=policy.max_attempts,
            base_delay_seconds=policy.base_delay_seconds,
            max_delay_seconds=policy.max_delay_seconds,
            jitter_factor=policy.jitter_factor,
        )


class FeedResponse(BaseModel):
    id: str
    feed_key: str
    display_name: str
    source_kind: str
    scope: str
    organization_id: str | None
    status: str
    connector_config: dict[str, Any]
    credential_ref: str | None
    schedule_interval_seconds: int
    retry_policy: RetryPolicyResponse
    checkpoint: str | None
    consecutive_failure_count: int
    last_sync_started_at: str | None
    last_sync_completed_at: str | None
    last_sync_status: str | None
    next_sync_due_at: str | None
    created_at: str
    updated_at: str
    created_by: str
    updated_by: str

    @classmethod
    def from_domain(cls, feed: Feed) -> FeedResponse:
        return cls(
            id=feed.id,
            feed_key=feed.feed_key.value,
            display_name=feed.display_name,
            source_kind=feed.source_kind.value,
            scope=feed.scope.value,
            organization_id=feed.organization_id,
            status=feed.status.value,
            connector_config=feed.connector_config,
            credential_ref=feed.credential_ref,
            schedule_interval_seconds=feed.schedule.interval_seconds,
            retry_policy=RetryPolicyResponse.from_domain(feed.retry_policy),
            checkpoint=feed.checkpoint,
            consecutive_failure_count=feed.consecutive_failure_count,
            last_sync_started_at=(
                feed.last_sync_started_at.isoformat() if feed.last_sync_started_at else None
            ),
            last_sync_completed_at=(
                feed.last_sync_completed_at.isoformat() if feed.last_sync_completed_at else None
            ),
            last_sync_status=feed.last_sync_status.value if feed.last_sync_status else None,
            next_sync_due_at=(
                feed.next_sync_due_at.isoformat() if feed.next_sync_due_at else None
            ),
            created_at=feed.created_at.isoformat(),
            updated_at=feed.updated_at.isoformat(),
            created_by=feed.created_by,
            updated_by=feed.updated_by,
        )


class FeedListResponse(BaseModel):
    items: list[FeedResponse]
    total: int


class FeedSyncRunResponse(BaseModel):
    id: str
    feed_id: str
    status: str
    trigger: str
    checkpoint_before: str | None
    checkpoint_after: str | None
    items_fetched: int
    items_processed: int
    items_failed: int
    retry_attempts_used: int
    error_message: str | None
    started_at: str
    finished_at: str | None
    created_by: str

    @classmethod
    def from_domain(cls, run: FeedSyncRun) -> FeedSyncRunResponse:
        return cls(
            id=run.id,
            feed_id=run.feed_id,
            status=run.status.value,
            trigger=run.trigger.value,
            checkpoint_before=run.checkpoint_before,
            checkpoint_after=run.checkpoint_after,
            items_fetched=run.items_fetched,
            items_processed=run.items_processed,
            items_failed=run.items_failed,
            retry_attempts_used=run.retry_attempts_used,
            error_message=run.error_message,
            started_at=run.started_at.isoformat(),
            finished_at=run.finished_at.isoformat() if run.finished_at else None,
            created_by=run.created_by,
        )


class FeedSyncRunListResponse(BaseModel):
    items: list[FeedSyncRunResponse]
    total: int


# ─── Feed registration and configuration ────────────────────────────────────


@router.post("", response_model=FeedResponse, status_code=status.HTTP_201_CREATED)
async def register_feed(
    body: RegisterFeedRequest,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> FeedResponse:
    from redforge.application.threat_intel.feed_admin_service import FeedAdminService

    try:
        scope = IngestionScope(body.scope)
        source_kind = FeedSourceKind(body.source_kind)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    service = FeedAdminService(session_factory)  # type: ignore[arg-type]
    feed = await service.register_feed(
        actor_id=platform.user_id,
        feed_key=body.feed_key,
        display_name=body.display_name,
        source_kind=source_kind.value,
        interval_seconds=body.interval_seconds,
        scope=scope,
        organization_id=body.organization_id,
        connector_config=body.connector_config,
        credential_ref=body.credential_ref,
        retry_policy=RetryPolicy(
            max_attempts=body.retry_max_attempts,
            base_delay_seconds=body.retry_base_delay_seconds,
            max_delay_seconds=body.retry_max_delay_seconds,
            jitter_factor=body.retry_jitter_factor,
        ),
    )
    return FeedResponse.from_domain(feed)


@router.get("", response_model=FeedListResponse)
async def list_feeds(
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_READ)),
    ],
    scope: str | None = Query(default=None),
    organization_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    source_kind: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session_factory: object = Depends(_get_session_factory),
) -> FeedListResponse:
    from redforge.application.threat_intel.feed_query_service import FeedQueryService

    try:
        parsed_scope = IngestionScope(scope) if scope is not None else None
        parsed_status = FeedStatus(status_filter) if status_filter is not None else None
        parsed_source_kind = FeedSourceKind(source_kind) if source_kind is not None else None
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    service = FeedQueryService(session_factory)  # type: ignore[arg-type]
    feeds, total = await service.list_feeds(
        scope=parsed_scope,
        organization_id=organization_id,
        status=parsed_status,
        source_kind=parsed_source_kind,
        limit=limit,
        offset=offset,
    )
    return FeedListResponse(items=[FeedResponse.from_domain(f) for f in feeds], total=total)


@router.get("/{feed_id}", response_model=FeedResponse)
async def get_feed(
    feed_id: str,
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_READ)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> FeedResponse:
    from redforge.application.threat_intel.feed_query_service import FeedQueryService

    service = FeedQueryService(session_factory)  # type: ignore[arg-type]
    feed = await service.get_feed(feed_id)
    return FeedResponse.from_domain(feed)


@router.patch("/{feed_id}", response_model=FeedResponse)
async def update_feed_configuration(
    feed_id: str,
    body: UpdateFeedConfigRequest,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> FeedResponse:
    from redforge.application.threat_intel.feed_admin_service import FeedAdminService
    from redforge.application.threat_intel.feed_query_service import FeedQueryService

    query_service = FeedQueryService(session_factory)  # type: ignore[arg-type]
    current = await query_service.get_feed(feed_id)

    retry_policy = None
    if any(
        value is not None
        for value in (
            body.retry_max_attempts,
            body.retry_base_delay_seconds,
            body.retry_max_delay_seconds,
            body.retry_jitter_factor,
        )
    ):
        current_policy = current.retry_policy
        retry_policy = RetryPolicy(
            max_attempts=body.retry_max_attempts or current_policy.max_attempts,
            base_delay_seconds=(
                body.retry_base_delay_seconds
                if body.retry_base_delay_seconds is not None
                else current_policy.base_delay_seconds
            ),
            max_delay_seconds=(
                body.retry_max_delay_seconds
                if body.retry_max_delay_seconds is not None
                else current_policy.max_delay_seconds
            ),
            jitter_factor=(
                body.retry_jitter_factor
                if body.retry_jitter_factor is not None
                else current_policy.jitter_factor
            ),
        )

    service = FeedAdminService(session_factory)  # type: ignore[arg-type]
    feed = await service.update_configuration(
        actor_id=platform.user_id,
        feed_id=feed_id,
        display_name=body.display_name,
        connector_config=body.connector_config,
        credential_ref=body.credential_ref,
        interval_seconds=body.interval_seconds,
        retry_policy=retry_policy,
    )
    return FeedResponse.from_domain(feed)


# ─── Lifecycle transitions ───────────────────────────────────────────────────


@router.post("/{feed_id}/activate", response_model=FeedResponse)
async def activate_feed(
    feed_id: str,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> FeedResponse:
    from redforge.application.threat_intel.feed_admin_service import FeedAdminService

    service = FeedAdminService(session_factory)  # type: ignore[arg-type]
    feed = await service.activate_feed(actor_id=platform.user_id, feed_id=feed_id)
    return FeedResponse.from_domain(feed)


@router.post("/{feed_id}/pause", response_model=FeedResponse)
async def pause_feed(
    feed_id: str,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> FeedResponse:
    from redforge.application.threat_intel.feed_admin_service import FeedAdminService

    service = FeedAdminService(session_factory)  # type: ignore[arg-type]
    feed = await service.pause_feed(actor_id=platform.user_id, feed_id=feed_id)
    return FeedResponse.from_domain(feed)


@router.post("/{feed_id}/disable", response_model=FeedResponse)
async def disable_feed(
    feed_id: str,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> FeedResponse:
    from redforge.application.threat_intel.feed_admin_service import FeedAdminService

    service = FeedAdminService(session_factory)  # type: ignore[arg-type]
    feed = await service.disable_feed(actor_id=platform.user_id, feed_id=feed_id)
    return FeedResponse.from_domain(feed)


# ─── Synchronization trigger and history ────────────────────────────────────


@router.post(
    "/{feed_id}/sync",
    response_model=FeedSyncRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_feed_sync(
    feed_id: str,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
    connector_registry: object = Depends(_get_feed_connector_registry),
) -> FeedSyncRunResponse:
    from redforge.application.threat_intel.feed_sync_orchestration_service import (
        FeedSyncOrchestrationService,
    )

    service = FeedSyncOrchestrationService(
        session_factory,  # type: ignore[arg-type]
        connector_registry,  # type: ignore[arg-type]
    )
    run = await service.trigger_sync(
        feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id=platform.user_id
    )
    return FeedSyncRunResponse.from_domain(run)


@router.get("/{feed_id}/runs", response_model=FeedSyncRunListResponse)
async def list_feed_sync_runs(
    feed_id: str,
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_READ)),
    ],
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session_factory: object = Depends(_get_session_factory),
) -> FeedSyncRunListResponse:
    from redforge.application.threat_intel.feed_query_service import FeedQueryService

    service = FeedQueryService(session_factory)  # type: ignore[arg-type]
    runs, total = await service.list_sync_runs(feed_id, limit=limit, offset=offset)
    return FeedSyncRunListResponse(
        items=[FeedSyncRunResponse.from_domain(r) for r in runs], total=total
    )


@router.get("/{feed_id}/runs/{run_id}", response_model=FeedSyncRunResponse)
async def get_feed_sync_run(
    feed_id: str,
    run_id: str,
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_FEED_SYNC_READ)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> FeedSyncRunResponse:
    from redforge.application.threat_intel.feed_query_service import FeedQueryService

    service = FeedQueryService(session_factory)  # type: ignore[arg-type]
    run = await service.get_sync_run(feed_id, run_id)
    return FeedSyncRunResponse.from_domain(run)
