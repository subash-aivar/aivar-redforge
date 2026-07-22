"""Generic periodic background runner for per-tenant or tenant-agnostic
bounded-context scheduler ticks.

Several bounded contexts (analytics, automated_action, autonomous_intelligence,
exposure_reporting, incident, playbook, posture_forecasting,
regulatory_notification, reporting, threat_hunt, integration_hub) define a
`Scheduler.tick()` / `Scheduler.tick_all()` / `Scheduler.tick_all(tenant_id)`
entry point but, unlike `ContinuousValidationSchedulerWorker` and
`DLQReplayWorker`, have no internal claim-based poll loop — they expect an
external driver to invoke them on an interval. This class is that driver,
mirroring the start()/stop()/is_running/stats() lifecycle shape already
established by those two workers.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from redforge.application.platform_identity.query_service import PlatformQueryService

logger = logging.getLogger(__name__)

TenantTickFn = Callable[[UUID], Awaitable[object]]
GlobalTickFn = Callable[[], Awaitable[object]]


class TenantPeriodicRunner:
    """Drives a per-tenant or tenant-agnostic tick function on an interval."""

    def __init__(
        self,
        name: str,
        tick_fn: TenantTickFn | GlobalTickFn,
        *,
        per_tenant: bool,
        tenant_query_service: PlatformQueryService | None = None,
        poll_interval_s: float = 60.0,
        tenant_page_size: int = 200,
    ) -> None:
        if per_tenant and tenant_query_service is None:
            raise ValueError(f"{name}: per_tenant runner requires tenant_query_service")
        self._name = name
        self._tick_fn = tick_fn
        self._per_tenant = per_tenant
        self._tenant_query_service = tenant_query_service
        self._poll_interval_s = poll_interval_s
        self._tenant_page_size = tenant_page_size
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._cycles = 0
        self._failures = 0

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._loop(), name=f"{self._name}-periodic-runner")

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    def stats(self) -> dict[str, int | str]:
        return {
            "cycles": self._cycles,
            "failures": self._failures,
            "state": "running" if self.is_running else "stopped",
        }

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._run_once()
                self._cycles += 1
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("%s: periodic tick cycle failed", self._name)
                self._failures += 1
            await asyncio.sleep(self._poll_interval_s)

    async def _run_once(self) -> None:
        if not self._per_tenant:
            await self._tick_fn()  # type: ignore[call-arg]
            return
        assert self._tenant_query_service is not None
        offset = 0
        while True:
            orgs = await self._tenant_query_service.list_organizations(
                self._tenant_page_size, offset
            )
            if not orgs:
                break
            for org in orgs:
                try:
                    await self._tick_fn(UUID(org.id))  # type: ignore[call-arg]
                except Exception:
                    logger.exception("%s: tick failed for tenant %s", self._name, org.id)
                    self._failures += 1
            if len(orgs) < self._tenant_page_size:
                break
            offset += self._tenant_page_size
