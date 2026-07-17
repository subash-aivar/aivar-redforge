"""Threat-intel sync orchestration — M22 Phase 6.

Reuses Phase 2 feed orchestration + Phase 4 fusion. Does not introduce
new feed source kinds or re-parse STIX outside the registered connector.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.domain.threat_intel.feed_value_objects import (
    FeedSourceKind,
    FeedStatus,
    FeedSyncTrigger,
)
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.feed_sync_repository import (
    SqlAlchemyFeedRepository,
)
from redforge.infrastructure.database.repositories.threat_intel_sync_repository import (
    SqlAlchemyThreatIntelSyncStateRepository,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.threat_intel.feed_sync_orchestration_service import (
        FeedSyncOrchestrationService,
    )
    from redforge.application.threat_intel.threat_fusion_service import ThreatFusionService

JOB_ATTACK_TECHNIQUE = "attack_technique_sync"
JOB_VULNERABILITY = "vulnerability_sync"
JOB_INDICATOR_REFRESH = "indicator_refresh"

_SYNC_ACTOR = "system:ti_sync_worker"  # 20 chars ≤ 26


@dataclass(frozen=True, slots=True)
class SyncJobStatus:
    job_key: str
    last_status: str
    last_started_at: str | None
    last_finished_at: str | None
    last_error: str | None
    last_result: dict[str, Any]


class ThreatIntelSyncOrchestrationService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        feed_orchestration: FeedSyncOrchestrationService | None = None,
        fusion_service: ThreatFusionService | None = None,
        audit_factory: Callable[[AsyncSession], PostgresPlatformAuditLog] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._feed_orchestration = feed_orchestration
        self._fusion_service = fusion_service
        self._audit_factory = audit_factory or (
            lambda session: PostgresPlatformAuditLog(session)
        )

    async def list_status(self) -> list[SyncJobStatus]:
        async with self._session_factory() as session, session.begin():
            repo = SqlAlchemyThreatIntelSyncStateRepository(session)
            rows = await repo.list_all()
            known = {JOB_ATTACK_TECHNIQUE, JOB_VULNERABILITY, JOB_INDICATOR_REFRESH}
            by_key = {r.job_key: r for r in rows}
            out: list[SyncJobStatus] = []
            for key in sorted(known):
                row = by_key.get(key)
                if row is None:
                    out.append(
                        SyncJobStatus(
                            job_key=key,
                            last_status="idle",
                            last_started_at=None,
                            last_finished_at=None,
                            last_error=None,
                            last_result={},
                        )
                    )
                    continue
                out.append(
                    SyncJobStatus(
                        job_key=row.job_key,
                        last_status=row.last_status,
                        last_started_at=(
                            row.last_started_at.isoformat() if row.last_started_at else None
                        ),
                        last_finished_at=(
                            row.last_finished_at.isoformat()
                            if row.last_finished_at
                            else None
                        ),
                        last_error=row.last_error,
                        last_result=dict(row.last_result or {}),
                    )
                )
            return out

    async def run_attack_technique_sync(self, *, actor_id: str = _SYNC_ACTOR) -> dict[str, Any]:
        return await self._run_catalog_sync(
            JOB_ATTACK_TECHNIQUE,
            actor_id=actor_id,
            preferred_kinds={FeedSourceKind.STIX_TAXII_PULL},
        )

    async def run_vulnerability_sync(self, *, actor_id: str = _SYNC_ACTOR) -> dict[str, Any]:
        # Vulnerabilities arrive via the same Phase 3 STIX/TAXII catalog path;
        # this job reuses that connector and then re-fuses.
        return await self._run_catalog_sync(
            JOB_VULNERABILITY,
            actor_id=actor_id,
            preferred_kinds={FeedSourceKind.STIX_TAXII_PULL},
        )

    async def _run_catalog_sync(
        self,
        job_key: str,
        *,
        actor_id: str,
        preferred_kinds: set[FeedSourceKind],
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        async with self._session_factory() as session, session.begin():
            state_repo = SqlAlchemyThreatIntelSyncStateRepository(session)
            await state_repo.mark_started(job_key, now=now)

        feeds_triggered = 0
        feeds_succeeded = 0
        feeds_failed = 0
        errors: list[str] = []

        if self._feed_orchestration is not None:
            async with self._session_factory() as session, session.begin():
                feed_repo = SqlAlchemyFeedRepository(session)
                due = await feed_repo.list_due_for_sync(now=now, limit=25)
                active = await feed_repo.list_all(
                    status=FeedStatus.ACTIVE,
                    limit=50,
                )
            candidates = []
            seen: set[str] = set()
            for feed in list(due) + list(active):
                if feed.id in seen:
                    continue
                if feed.source_kind not in preferred_kinds:
                    continue
                seen.add(feed.id)
                candidates.append(feed)

            for feed in candidates[:10]:
                feeds_triggered += 1
                try:
                    await self._feed_orchestration.trigger_sync(
                        feed_id=feed.id,
                        trigger=FeedSyncTrigger.MANUAL,
                        actor_id=actor_id[:26],
                    )
                    feeds_succeeded += 1
                except Exception as exc:
                    feeds_failed += 1
                    errors.append(f"{feed.feed_key.value}:{type(exc).__name__}")

        fusion_result: dict[str, Any] = {}
        if self._fusion_service is not None:
            try:
                result = await self._fusion_service.fuse_reference_catalog(
                    actor_id=actor_id[:26]
                )
                fusion_result = {
                    "indicators_created": result.indicators_created,
                    "indicators_updated": result.indicators_updated,
                    "relationships_upserted": result.relationships_upserted,
                }
            except Exception as exc:
                errors.append(f"fusion:{type(exc).__name__}:{exc}")

        if not errors:
            status = "succeeded"
        elif feeds_succeeded == 0 and not fusion_result:
            status = "failed"
        else:
            status = "succeeded"
        payload = {
            "feeds_triggered": feeds_triggered,
            "feeds_succeeded": feeds_succeeded,
            "feeds_failed": feeds_failed,
            "fusion": fusion_result,
            "errors": errors[:20],
        }
        finished = datetime.now(UTC)
        async with self._session_factory() as session, session.begin():
            state_repo = SqlAlchemyThreatIntelSyncStateRepository(session)
            await state_repo.mark_finished(
                job_key,
                status=status,
                result=payload,
                error="; ".join(errors[:5]) if errors and status == "failed" else None,
                now=finished,
            )
            await self._audit_factory(session).record(
                AuditEntry(
                    action=AuditAction.THREAT_INTEL_SYNC_TRIGGERED,
                    actor_id=actor_id[:26],
                    resource_type="threat_intel_sync",
                    resource_id=str(EntityId.generate()),
                    metadata={"job_key": job_key, "status": status},
                )
            )
        return payload
