"""AttackTechniqueSyncWorker — M22 Phase 6.

Weekly-oriented background worker. Reuses Phase 2 feed orchestration for
STIX/TAXII pulls and Phase 4 fusion. Global advisory lock prevents
duplicate concurrent sync across horizontally scaled instances.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

if TYPE_CHECKING:
    from redforge.application.threat_intel.sync_orchestration_service import (
        ThreatIntelSyncOrchestrationService,
    )

log = logging.getLogger(__name__)

DEFAULT_POLL_SECONDS = 6 * 60 * 60  # 6 hours (weekly intent; admin can trigger)
_WORKER_LOCK_HASH = 0x4D32324154535901  # M22 ATSY


class AttackTechniqueSyncWorker:
    def __init__(
        self,
        sync_service: ThreatIntelSyncOrchestrationService,
        *,
        poll_seconds: int = DEFAULT_POLL_SECONDS,
        session_factory: Any | None = None,
    ) -> None:
        self._sync_service = sync_service
        self._poll_seconds = poll_seconds
        self._session_factory = session_factory
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._stats: dict[str, Any] = {
            "cycles": 0,
            "errors": 0,
            "started_at": None,
            "last_cycle_at": None,
            "last_result": None,
        }

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stats["started_at"] = datetime.now(UTC).isoformat()
        self._task = asyncio.create_task(self._loop(), name="attack_technique_sync_worker")
        log.info("AttackTechniqueSyncWorker started")

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        log.info("AttackTechniqueSyncWorker stopped — stats: %s", self._stats)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    async def run_once(self) -> dict[str, Any]:
        if self._session_factory is not None:
            async with self._session_factory() as session, session.begin():
                locked = await session.execute(
                    text("SELECT pg_try_advisory_xact_lock(:h)"),
                    {"h": _WORKER_LOCK_HASH},
                )
                if not locked.scalar():
                    return {"skipped": True, "reason": "lock_not_acquired"}
        result = await self._sync_service.run_attack_technique_sync()
        self._stats["last_result"] = result
        return result

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.run_once()
                self._stats["cycles"] += 1
                self._stats["last_cycle_at"] = datetime.now(UTC).isoformat()
            except Exception:
                log.exception("AttackTechniqueSyncWorker cycle failed")
                self._stats["errors"] += 1
            await asyncio.sleep(self._poll_seconds)
