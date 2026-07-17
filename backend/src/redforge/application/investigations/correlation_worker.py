"""Cross-Domain Correlation Background Worker — M21.

Follows the exact BehaviorDetectionWorker pattern from M20:
asyncio poll loop, bounded batch, exception isolation, start()/stop()/stats().

Incremental processing:
  Per-source cursor stored in investigation_correlation_cursors table.
  Only events newer than the cursor are processed each cycle.

Duplicate-worker safety:
  pg_try_advisory_xact_lock prevents two instances from processing
  simultaneously. Individual case creation is also safe under concurrency
  via the advisory-lock + partial-unique-index pattern in the repository.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

log = logging.getLogger(__name__)

MAX_ORGS_PER_CYCLE = 50
DEFAULT_POLL_SECONDS = 120  # 2-minute correlation cycles
DEFAULT_BATCH_SIZE = 100
# Global lock for duplicate-worker safety (unique to M21 worker)
_WORKER_LOCK_HASH = 0x4D32314D43524C01  # M21MCR (correlation worker)
# Lookback window for the initial cursor (first run)
_INITIAL_LOOKBACK_HOURS = 24


class CorrelationWorker:
    """Background asyncio worker for cross-domain security correlation."""

    def __init__(
        self,
        session_factory: Any,
        poll_seconds: int = DEFAULT_POLL_SECONDS,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> None:
        self._session_factory = session_factory
        self._poll_seconds = poll_seconds
        self._batch_size = batch_size
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._stats: dict[str, Any] = {
            "cycles": 0,
            "candidates_processed": 0,
            "cases_opened": 0,
            "evidence_attached": 0,
            "errors": 0,
            "started_at": None,
            "last_cycle_at": None,
        }

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stats["started_at"] = datetime.now(UTC).isoformat()
        self._task = asyncio.create_task(self._loop(), name="correlation_worker")
        log.info("CorrelationWorker started (poll_seconds=%d)", self._poll_seconds)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        log.info("CorrelationWorker stopped — stats: %s", self._stats)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._run_cycle()
            except Exception:
                log.exception("CorrelationWorker: unhandled exception in cycle")
                self._stats["errors"] += 1
            await asyncio.sleep(self._poll_seconds)

    async def _run_cycle(self) -> None:
        from sqlalchemy import select, text

        from redforge.infrastructure.database.models.organization import OrganizationModel

        now = datetime.now(UTC)

        async with self._session_factory() as session, session.begin():
            # Global advisory lock: skip cycle if another instance is running
            lock_result = await session.execute(
                text("SELECT pg_try_advisory_xact_lock(:h)"),
                {"h": _WORKER_LOCK_HASH},
            )
            if not lock_result.scalar():
                log.debug("CorrelationWorker: lock not acquired, skipping cycle")
                return

            result = await session.execute(
                select(OrganizationModel.id)
                .where(OrganizationModel.status == "active")
                .limit(MAX_ORGS_PER_CYCLE)
            )
            org_ids = [row[0] for row in result.all()]

        for org_id in org_ids:
            try:
                stats = await self._process_org(org_id, now)
                self._stats["candidates_processed"] += stats.get("candidates", 0)
                self._stats["cases_opened"] += stats.get("cases_opened", 0)
                self._stats["evidence_attached"] += stats.get("evidence_attached", 0)
            except Exception:
                log.exception("CorrelationWorker: org error org=%s", org_id)
                self._stats["errors"] += 1

        self._stats["cycles"] += 1
        self._stats["last_cycle_at"] = now.isoformat()

    async def _process_org(self, org_id: str, now: datetime) -> dict[str, int]:
        """Process new evidence candidates for one organization."""
        from sqlalchemy import select

        from redforge.application.investigations.case_service import InvestigationCaseService
        from redforge.application.investigations.correlation_engine import evaluate_recurrence
        from redforge.application.investigations.source_adapters import (
            adapt_behavior_detection,
            adapt_ddos_incident,
            adapt_threat_intel_enrichment,
        )
        from redforge.infrastructure.database.models.behavior import (
            BehaviorDetectionModel,
        )
        from redforge.infrastructure.database.models.ddos import DDoSIncidentModel
        from redforge.infrastructure.database.models.threat_intel import (
            ThreatIntelIndicatorModel,
        )
        from redforge.infrastructure.database.repositories.investigations.case_repository import (
            SqlAlchemyCorrelationCursorRepository,
            SqlAlchemyEvidenceLinkRepository,
            SqlAlchemyInvestigationEventRepository,
            SqlAlchemyInvestigationRepository,
        )
        from redforge.infrastructure.database.repositories.threat_intel_repository import (
            SqlAlchemyThreatIntelEnrichmentRepository,
        )

        stats = {"candidates": 0, "cases_opened": 0, "evidence_attached": 0}

        async with self._session_factory() as session, session.begin():
            cursor_repo = SqlAlchemyCorrelationCursorRepository(session)
            case_repo = SqlAlchemyInvestigationRepository(session)
            evidence_repo = SqlAlchemyEvidenceLinkRepository(session)
            event_repo = SqlAlchemyInvestigationEventRepository(session)
            svc = InvestigationCaseService(session, case_repo, evidence_repo, event_repo)
            ti_enrichment_repo = SqlAlchemyThreatIntelEnrichmentRepository(session)

            # Get cursors
            behavior_since, _ = await cursor_repo.get_cursor("behavior")
            ddos_since, _ = await cursor_repo.get_cursor("ddos")
            ti_since, _ = await cursor_repo.get_cursor("threat_intel")
            default_since = now - timedelta(hours=_INITIAL_LOOKBACK_HOURS)
            behavior_since = behavior_since or default_since
            ddos_since = ddos_since or default_since
            ti_since = ti_since or default_since

            # Fetch recent behavior detections (opened or updated)
            behavior_result = await session.execute(
                select(BehaviorDetectionModel)
                .where(
                    BehaviorDetectionModel.organization_id == org_id,
                    BehaviorDetectionModel.detected_at > behavior_since,
                    BehaviorDetectionModel.status.not_in(["RESOLVED", "CLOSED"]),
                )
                .order_by(BehaviorDetectionModel.detected_at.asc())
                .limit(self._batch_size)
            )
            behavior_rows = list(behavior_result.scalars().all())

            # Fetch recent DDoS incidents
            ddos_result = await session.execute(
                select(DDoSIncidentModel)
                .where(
                    DDoSIncidentModel.organization_id == org_id,
                    DDoSIncidentModel.first_detected_at > ddos_since,
                    DDoSIncidentModel.status.not_in(["RESOLVED", "CLOSED"]),
                )
                .order_by(DDoSIncidentModel.first_detected_at.asc())
                .limit(self._batch_size)
            )
            ddos_rows = list(ddos_result.scalars().all())

            # Adapt to candidates
            behavior_candidates = []
            for row in behavior_rows:
                candidate = adapt_behavior_detection(
                    org_id=org_id,
                    detection_id=row.id,
                    correlation_key=row.correlation_key,
                    entity_type=row.entity_type,
                    entity_id=row.entity_id,
                    detection_type=row.detection_type,
                    severity=row.severity,
                    status=row.status,
                    evidence=row.evidence or {},
                    secondary_entity_id=row.secondary_entity_id,
                    detected_at=row.detected_at,
                )
                if candidate:
                    behavior_candidates.append(candidate)

            ddos_candidates = []
            for row in ddos_rows:
                candidate = adapt_ddos_incident(
                    org_id=org_id,
                    incident_id=row.id,
                    resource_id=row.resource_id,
                    resource_name=row.resource_name,
                    scope_type="any",
                    scope_value=None,
                    severity=row.severity,
                    status=row.status,
                    attack_classification=row.classification,
                    opening_evidence=row.opening_evidence or {},
                    detected_at=row.first_detected_at,
                )
                if candidate:
                    ddos_candidates.append(candidate)

            # M22 Phase 6 — fresh threat-intel enrichments
            enrichment_rows = await ti_enrichment_repo.list_since(
                org_id,
                since=ti_since,
                kinds=["reputation", "ioc_match"],
                limit=self._batch_size,
            )
            indicator_ids = {row.indicator_id for row in enrichment_rows}
            indicators_by_id: dict[str, ThreatIntelIndicatorModel] = {}
            if indicator_ids:
                ind_result = await session.execute(
                    select(ThreatIntelIndicatorModel).where(
                        ThreatIntelIndicatorModel.organization_id == org_id,
                        ThreatIntelIndicatorModel.id.in_(indicator_ids),
                    )
                )
                indicators_by_id = {
                    m.id: m for m in ind_result.scalars().all()
                }

            ti_candidates = []
            for row in enrichment_rows:
                indicator = indicators_by_id.get(row.indicator_id)
                if indicator is None:
                    continue
                candidate = adapt_threat_intel_enrichment(
                    org_id,
                    indicator_id=indicator.id,
                    indicator=indicator.indicator,
                    indicator_type=indicator.indicator_type,
                    enrichment_id=row.id,
                    provider_name=row.provider_name,
                    kind=row.kind,
                    success=row.success,
                    data=row.data or {},
                    fetched_at=row.fetched_at,
                    expires_at=row.expires_at,
                    now=now,
                )
                if candidate:
                    ti_candidates.append(candidate)

            stats["candidates"] = (
                len(behavior_candidates) + len(ddos_candidates) + len(ti_candidates)
            )

            # Cross-domain correlation: behavior x ddos, TI x behavior, TI x ddos
            pair_groups = (
                (behavior_candidates, ddos_candidates),
                (ti_candidates, behavior_candidates),
                (ti_candidates, ddos_candidates),
            )
            for left_group, right_group in pair_groups:
                for left in left_group:
                    for right in right_group:
                        try:
                            result_dict = await svc.correlate_pair(left, right)
                            if result_dict:
                                if result_dict["created"]:
                                    stats["cases_opened"] += 1
                                stats["evidence_attached"] += 1
                        except Exception:
                            log.exception(
                                "CorrelationWorker: pair correlation error "
                                "org=%s left=%s right=%s",
                                org_id,
                                left.source_entity_id,
                                right.source_entity_id,
                            )

            # Recurrence: check each new candidate against existing active cases
            all_candidates = behavior_candidates + ddos_candidates + ti_candidates
            for candidate in all_candidates:
                try:
                    # Find active cases with shared entities
                    active_cases = await case_repo.list_cases(
                        org_id, status=None, limit=50
                    )
                    active_cases = [
                        c for c in active_cases if c.status != "RESOLVED"
                    ]

                    for case in active_cases:
                        # Check if this candidate's entities overlap
                        case_entity_ids = [
                            f"{e.get('type', '')}:{e.get('id', '')}"
                            for e in (case.involved_entities or [])
                        ]
                        rec_decision = evaluate_recurrence(
                            candidate,
                            existing_case_entity_ids=case_entity_ids,
                            existing_case_source_domains=case.source_domains or [],
                            existing_case_domain_count=len(case.source_domains or []),
                        )
                        if rec_decision:
                            # Don't re-attach already-attached evidence
                            from sqlalchemy import select as sa_select

                            from redforge.infrastructure.database.models.investigation import (
                                InvestigationEvidenceLinkModel,
                            )

                            ev_exists_result = await session.execute(
                                sa_select(InvestigationEvidenceLinkModel.id)
                                .where(
                                    InvestigationEvidenceLinkModel.organization_id == org_id,
                                    InvestigationEvidenceLinkModel.case_id == case.id,
                                    InvestigationEvidenceLinkModel.dedup_key == candidate.dedup_key,
                                )
                                .limit(1)
                            )
                            already_linked = ev_exists_result.scalar_one_or_none() is not None
                            if not already_linked:
                                await svc.attach_to_existing(
                                    candidate,
                                    case.id,
                                    rec_decision.reason,
                                    rec_decision.rule_id,
                                )
                                stats["evidence_attached"] += 1
                            break  # one case per candidate per cycle
                except Exception:
                    log.exception(
                        "CorrelationWorker: recurrence check error "
                        "org=%s candidate=%s",
                        org_id, candidate.source_entity_id,
                    )

            # Update cursors
            if behavior_rows:
                latest_behavior = max(r.detected_at for r in behavior_rows)
                await cursor_repo.set_cursor(
                    "behavior", latest_behavior, behavior_rows[-1].id
                )
            if ddos_rows:
                latest_ddos = max(r.first_detected_at for r in ddos_rows)
                await cursor_repo.set_cursor(
                    "ddos", latest_ddos, ddos_rows[-1].id
                )
            if enrichment_rows:
                latest_ti = max(r.fetched_at for r in enrichment_rows)
                await cursor_repo.set_cursor(
                    "threat_intel", latest_ti, enrichment_rows[-1].id
                )

        return stats
