"""IndicatorRefreshWorker — M22 Phase 6.

Re-enriches aging IP indicators linked to active investigations,
prioritized by investigation recency (hardening: avoid MAX_ORGS head
starvation).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, text

from redforge.infrastructure.database.repositories.threat_intel_sync_repository import (
    SqlAlchemyThreatIntelSyncStateRepository,
)

if TYPE_CHECKING:
    from redforge.application.threat_intel.enrichment_service import (
        IndicatorEnrichmentService,
    )

log = logging.getLogger(__name__)

DEFAULT_POLL_SECONDS = 15 * 60
MAX_INVESTIGATIONS_PER_CYCLE = 50
MAX_INDICATORS_PER_INVESTIGATION = 5
_WORKER_LOCK_HASH = 0x4D32324952524601  # M22 IRFR
JOB_KEY = "indicator_refresh"


class IndicatorRefreshWorker:
    def __init__(
        self,
        session_factory: Any,
        enrichment_service: IndicatorEnrichmentService,
        *,
        poll_seconds: int = DEFAULT_POLL_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._enrichment_service = enrichment_service
        self._poll_seconds = poll_seconds
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._stats: dict[str, Any] = {
            "cycles": 0,
            "investigations_touched": 0,
            "indicators_refreshed": 0,
            "errors": 0,
            "started_at": None,
            "last_cycle_at": None,
        }

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stats["started_at"] = datetime.now(UTC).isoformat()
        self._task = asyncio.create_task(self._loop(), name="indicator_refresh_worker")
        log.info("IndicatorRefreshWorker started")

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        log.info("IndicatorRefreshWorker stopped — stats: %s", self._stats)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    async def run_once(self) -> dict[str, Any]:
        from redforge.infrastructure.database.models.investigation import (
            InvestigationEvidenceLinkModel,
            InvestigationModel,
        )
        from redforge.infrastructure.database.models.threat_intel import (
            ThreatIntelIndicatorModel,
        )

        now = datetime.now(UTC)
        async with self._session_factory() as session, session.begin():
            locked = await session.execute(
                text("SELECT pg_try_advisory_xact_lock(:h)"),
                {"h": _WORKER_LOCK_HASH},
            )
            if not locked.scalar():
                return {"skipped": True, "reason": "lock_not_acquired"}
            state_repo = SqlAlchemyThreatIntelSyncStateRepository(session)
            await state_repo.mark_started(JOB_KEY, now=now)

            cases = await session.execute(
                select(InvestigationModel)
                .where(InvestigationModel.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"]))
                .order_by(InvestigationModel.updated_at.desc())
                .limit(MAX_INVESTIGATIONS_PER_CYCLE)
            )
            case_rows = list(cases.scalars().all())

        refreshed = 0
        touched = 0
        errors: list[str] = []
        for case in case_rows:
            touched += 1
            async with self._session_factory() as session, session.begin():
                links = await session.execute(
                    select(InvestigationEvidenceLinkModel)
                    .where(
                        InvestigationEvidenceLinkModel.organization_id
                        == case.organization_id,
                        InvestigationEvidenceLinkModel.case_id == case.id,
                        InvestigationEvidenceLinkModel.source_domain == "threat_intel",
                    )
                    .limit(MAX_INDICATORS_PER_INVESTIGATION)
                )
                link_rows = list(links.scalars().all())
                indicator_ids: list[str] = []
                for link in link_rows:
                    snap = link.evidence_snapshot or {}
                    ind_id = snap.get("indicator_id")
                    if isinstance(ind_id, str):
                        indicator_ids.append(ind_id)
                if not indicator_ids:
                    # Fall back: IP anchors from involved entities
                    for ent in case.involved_entities or []:
                        if ent.get("type") == "IP_ADDRESS" and isinstance(
                            ent.get("id"), str
                        ):
                            ind = await session.execute(
                                select(ThreatIntelIndicatorModel).where(
                                    ThreatIntelIndicatorModel.organization_id
                                    == case.organization_id,
                                    ThreatIntelIndicatorModel.indicator_type == "ip",
                                    ThreatIntelIndicatorModel.indicator == ent["id"],
                                ).limit(1)
                            )
                            model = ind.scalar_one_or_none()
                            if model is not None:
                                indicator_ids.append(model.id)
                ind_models = []
                if indicator_ids:
                    result = await session.execute(
                        select(ThreatIntelIndicatorModel).where(
                            ThreatIntelIndicatorModel.organization_id
                            == case.organization_id,
                            ThreatIntelIndicatorModel.id.in_(indicator_ids[:5]),
                        )
                    )
                    ind_models = list(result.scalars().all())

            for model in ind_models:
                if model.indicator_type != "ip":
                    continue
                try:
                    await self._enrichment_service.enrich_ip(
                        model.organization_id, model.indicator
                    )
                    refreshed += 1
                except Exception as exc:
                    errors.append(f"{model.id}:{type(exc).__name__}")

        payload = {
            "investigations_touched": touched,
            "indicators_refreshed": refreshed,
            "errors": errors[:20],
        }
        async with self._session_factory() as session, session.begin():
            state_repo = SqlAlchemyThreatIntelSyncStateRepository(session)
            await state_repo.mark_finished(
                JOB_KEY,
                status="succeeded" if len(errors) < refreshed or refreshed > 0 else (
                    "failed" if errors else "succeeded"
                ),
                result=payload,
                error="; ".join(errors[:3]) if errors and refreshed == 0 else None,
                now=datetime.now(UTC),
            )
        self._stats["investigations_touched"] += touched
        self._stats["indicators_refreshed"] += refreshed
        return payload

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.run_once()
                self._stats["cycles"] += 1
                self._stats["last_cycle_at"] = datetime.now(UTC).isoformat()
            except Exception:
                log.exception("IndicatorRefreshWorker cycle failed")
                self._stats["errors"] += 1
            await asyncio.sleep(self._poll_seconds)
