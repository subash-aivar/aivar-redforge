"""Daily poll scheduler stub for ThreatActorMatchCache refresh (Phase 3)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from exposure.application.services.threat_actor_match_sync_service import (
        ThreatActorMatchSyncService,
    )


class ThreatActorPollScheduler:
    """Invoked by ops/cron at 02:00 UTC per tenant shard (Finalization D3)."""

    def __init__(self, sync_service: ThreatActorMatchSyncService) -> None:
        self._sync = sync_service
        self._last_run_at: str | None = None

    async def run_for_tenant(self, tenant_id: UUID) -> dict[str, object]:
        result = await self._sync.poll_and_refresh(tenant_id)
        from datetime import UTC, datetime

        self._last_run_at = datetime.now(UTC).isoformat()
        return {**result, "last_run_at": self._last_run_at}

    @property
    def last_run_at(self) -> str | None:
        return self._last_run_at
