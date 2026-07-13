"""Runtime Health Engine — Sprint 26.

Aggregates health status across all platform subsystems:
projection, worker, replay, queue, persistence, knowledge graph,
connector, campaign, conversation, validation.

Health aggregation rules:
- UNHEALTHY if ANY component is UNHEALTHY.
- DEGRADED if ANY component is DEGRADED (and none UNHEALTHY).
- HEALTHY only if ALL components are HEALTHY.

Checkers are registered by component_id. The engine calls all checkers
concurrently (asyncio.gather) with a per-check timeout to prevent a slow
check from blocking the health endpoint.

Design rules:
- No infrastructure imports.
- Thread-safe registration (checkers registered before startup).
- Timeout per check prevents cascade blocking.
- Each check failure surfaces as UNHEALTHY, not a raised exception.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from redforge.application.platform.runtime_contracts import (
    AggregatedHealth,
    ComponentHealth,
    HealthStatus,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


HealthCheckerFn = Callable[[], Coroutine[Any, Any, ComponentHealth]]


class RuntimeHealthEngine:
    """Concurrent health aggregator for all platform subsystems.

    Usage::

        engine = RuntimeHealthEngine(check_timeout_s=5.0)
        engine.register("projection:campaign_summary", check_campaign_projection)
        engine.register("persistence:event_store", check_event_store)

        health = await engine.aggregate_health()
        if health.overall_status == HealthStatus.UNHEALTHY:
            ...
    """

    def __init__(self, check_timeout_s: float = 5.0) -> None:
        self._check_timeout_s = check_timeout_s
        self._lock = threading.Lock()
        self._checkers: dict[str, HealthCheckerFn] = {}

    def register(self, component_id: str, checker: HealthCheckerFn) -> None:
        """Register a health checker for a component.

        The checker is an async callable returning ComponentHealth.
        Call before startup; re-registration replaces the previous checker.
        """
        with self._lock:
            self._checkers[component_id] = checker

    def deregister(self, component_id: str) -> None:
        with self._lock:
            self._checkers.pop(component_id, None)

    def registered_components(self) -> list[str]:
        with self._lock:
            return list(self._checkers.keys())

    async def check_component(self, component_id: str) -> ComponentHealth:
        """Run a single component check with timeout protection."""
        with self._lock:
            checker = self._checkers.get(component_id)
        if checker is None:
            return ComponentHealth(
                component_id=component_id,
                component_type="unknown",
                status=HealthStatus.UNHEALTHY,
                message=f"No health checker registered for {component_id!r}",
                checked_at=_utc_now(),
            )
        return await self._run_with_timeout(component_id, checker)

    async def aggregate_health(self) -> AggregatedHealth:
        """Run all registered checks concurrently and aggregate results."""
        with self._lock:
            snapshot = dict(self._checkers)

        if not snapshot:
            now = _utc_now()
            return AggregatedHealth(
                overall_status=HealthStatus.HEALTHY,
                components=(),
                checked_at=now,
            )

        tasks = [
            self._run_with_timeout(cid, checker)
            for cid, checker in snapshot.items()
        ]
        results: list[ComponentHealth] = list(await asyncio.gather(*tasks))

        overall = _aggregate_status(results)
        return AggregatedHealth(
            overall_status=overall,
            components=tuple(results),
            checked_at=_utc_now(),
        )

    async def _run_with_timeout(
        self,
        component_id: str,
        checker: HealthCheckerFn,
    ) -> ComponentHealth:
        try:
            return await asyncio.wait_for(checker(), timeout=self._check_timeout_s)
        except TimeoutError:
            return ComponentHealth(
                component_id=component_id,
                component_type="unknown",
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {self._check_timeout_s}s",
                checked_at=_utc_now(),
            )
        except Exception as exc:
            return ComponentHealth(
                component_id=component_id,
                component_type="unknown",
                status=HealthStatus.UNHEALTHY,
                message=f"Health check raised: {exc}",
                checked_at=_utc_now(),
            )


def _aggregate_status(results: list[ComponentHealth]) -> HealthStatus:
    statuses = {r.status for r in results}
    if HealthStatus.UNHEALTHY in statuses:
        return HealthStatus.UNHEALTHY
    if HealthStatus.DEGRADED in statuses:
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY


# ── Built-in simple health checkers ───────────────────────────────────────


def make_static_health_checker(
    component_id: str,
    component_type: str,
    status: HealthStatus = HealthStatus.HEALTHY,
    message: str = "ok",
) -> HealthCheckerFn:
    """Factory for a static health checker (useful in tests and stubs)."""
    async def _check() -> ComponentHealth:
        return ComponentHealth(
            component_id=component_id,
            component_type=component_type,
            status=status,
            message=message,
            checked_at=_utc_now(),
        )
    return _check


def make_callable_health_checker(
    component_id: str,
    component_type: str,
    fn: Callable[[], bool],
    healthy_msg: str = "ok",
    unhealthy_msg: str = "check failed",
) -> HealthCheckerFn:
    """Factory that wraps a sync bool-returning function as a health checker."""
    async def _check() -> ComponentHealth:
        ok = fn()
        return ComponentHealth(
            component_id=component_id,
            component_type=component_type,
            status=HealthStatus.HEALTHY if ok else HealthStatus.UNHEALTHY,
            message=healthy_msg if ok else unhealthy_msg,
            checked_at=_utc_now(),
        )
    return _check
