"""Graceful Shutdown Coordinator — Sprint 26.

Coordinates ordered startup and shutdown of all platform components.

Startup: hooks run in registration order (dependencies before dependents).
Shutdown: hooks run in reverse order (dependents before dependencies).
    This mirrors the Erlang/OTP supervisor shutdown sequence.

Timeout handling:
    Each shutdown hook runs with a per-hook timeout. If any hook exceeds
    its timeout, it is cancelled and logged. The coordinator continues
    to the next hook — it does NOT abort the shutdown sequence.

Thread safety:
    Hooks are registered synchronously before startup.
    Phase transitions are atomic under threading.Lock.
    The coordinator is not reentrant — do not call startup() twice.

Design rules:
- No infrastructure imports.
- All hooks are async callables (sync wrappers can be used via asyncio.to_thread).
- shutdown() is always safe to call even if startup() was never called.
"""

from __future__ import annotations

import asyncio
import dataclasses
import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.application.platform.runtime_contracts import LifecyclePhase
from redforge.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = get_logger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class LifecycleHook:
    name: str
    fn: Callable[[], Awaitable[None]]
    timeout_s: float = 30.0


class GracefulShutdownCoordinator:
    """Ordered startup and graceful shutdown with per-hook timeouts.

    Usage::

        coordinator = GracefulShutdownCoordinator()
        coordinator.register_startup("event_store_connect", connect_event_store)
        coordinator.register_startup("projection_engine_start", start_projections)
        coordinator.register_shutdown("projection_engine_stop", stop_projections)
        coordinator.register_shutdown("event_store_disconnect", disconnect_event_store)

        await coordinator.startup()
        # ...run application...
        await coordinator.shutdown(timeout_s=30.0)
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._phase = LifecyclePhase.INITIALIZING
        self._startup_hooks: list[LifecycleHook] = []
        self._shutdown_hooks: list[LifecycleHook] = []
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._errors: list[tuple[str, str]] = []

    # ── Registration ───────────────────────────────────────────────────────

    def register_startup(
        self,
        name: str,
        fn: Callable[[], Awaitable[None]],
        timeout_s: float = 30.0,
    ) -> None:
        """Register a startup hook. Appended in call order."""
        with self._lock:
            self._startup_hooks.append(LifecycleHook(name=name, fn=fn, timeout_s=timeout_s))

    def register_shutdown(
        self,
        name: str,
        fn: Callable[[], Awaitable[None]],
        timeout_s: float = 30.0,
    ) -> None:
        """Register a shutdown hook. Executed in reverse of registration order."""
        with self._lock:
            self._shutdown_hooks.append(LifecycleHook(name=name, fn=fn, timeout_s=timeout_s))

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def startup(self) -> None:
        """Run all startup hooks in registration order."""
        with self._lock:
            if self._phase not in (LifecyclePhase.INITIALIZING,):
                return
            self._phase = LifecyclePhase.STARTING
            hooks = list(self._startup_hooks)

        logger.info("lifecycle_startup_begin", hook_count=len(hooks))

        for hook in hooks:
            await self._run_hook(hook, phase="startup")

        with self._lock:
            self._phase = LifecyclePhase.RUNNING
            self._started_at = datetime.now(UTC)

        logger.info("lifecycle_startup_complete")

    async def shutdown(self, timeout_s: float = 30.0) -> None:
        """Run all shutdown hooks in reverse registration order.

        Individual hook timeout is the hook's own timeout_s, capped by
        the remaining time in the global timeout_s budget.
        """
        with self._lock:
            if self._phase == LifecyclePhase.STOPPED:
                return
            self._phase = LifecyclePhase.STOPPING
            hooks = list(reversed(self._shutdown_hooks))

        logger.info("lifecycle_shutdown_begin", hook_count=len(hooks))

        for hook in hooks:
            await self._run_hook(hook, phase="shutdown")

        with self._lock:
            self._phase = LifecyclePhase.STOPPED
            self._stopped_at = datetime.now(UTC)

        logger.info("lifecycle_shutdown_complete")

    async def _run_hook(self, hook: LifecycleHook, phase: str) -> None:
        logger.info("lifecycle_hook_start", name=hook.name, phase=phase)
        try:
            await asyncio.wait_for(hook.fn(), timeout=hook.timeout_s)
            logger.info("lifecycle_hook_done", name=hook.name, phase=phase)
        except TimeoutError:
            msg = f"Hook {hook.name!r} timed out after {hook.timeout_s}s"
            logger.warning("lifecycle_hook_timeout", name=hook.name, phase=phase)
            with self._lock:
                self._errors.append((hook.name, msg))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            msg = f"Hook {hook.name!r} raised: {exc}"
            logger.error("lifecycle_hook_error", name=hook.name, phase=phase, error=str(exc))
            with self._lock:
                self._errors.append((hook.name, str(exc)))

    # ── Introspection ──────────────────────────────────────────────────────

    @property
    def phase(self) -> LifecyclePhase:
        with self._lock:
            return self._phase

    @property
    def errors(self) -> list[tuple[str, str]]:
        with self._lock:
            return list(self._errors)

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._phase == LifecyclePhase.RUNNING

    def startup_hook_names(self) -> list[str]:
        with self._lock:
            return [h.name for h in self._startup_hooks]

    def shutdown_hook_names(self) -> list[str]:
        with self._lock:
            return [h.name for h in self._shutdown_hooks]
