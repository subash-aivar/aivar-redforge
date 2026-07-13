"""Tests for RuntimeHealthEngine — Sprint 26."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from redforge.application.platform.health_engine import (
    RuntimeHealthEngine,
    make_callable_health_checker,
    make_static_health_checker,
)
from redforge.application.platform.runtime_contracts import (
    ComponentHealth,
    HealthStatus,
)


def _now() -> datetime:
    return datetime.now(UTC)


class TestRuntimeHealthEngine:
    async def test_empty_engine_is_healthy(self) -> None:
        engine = RuntimeHealthEngine()
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.HEALTHY
        assert health.components == ()

    async def test_all_healthy(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("db", make_static_health_checker("db", "persistence"))
        engine.register("kg", make_static_health_checker("kg", "knowledge_graph"))
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.HEALTHY
        assert len(health.components) == 2

    async def test_one_degraded_makes_aggregate_degraded(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("db", make_static_health_checker("db", "persistence", HealthStatus.HEALTHY))
        engine.register("kg", make_static_health_checker("kg", "knowledge_graph", HealthStatus.DEGRADED))
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.DEGRADED

    async def test_one_unhealthy_overrides_degraded(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("a", make_static_health_checker("a", "svc", HealthStatus.DEGRADED))
        engine.register("b", make_static_health_checker("b", "svc", HealthStatus.UNHEALTHY))
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.UNHEALTHY

    async def test_check_times_out_returns_unhealthy(self) -> None:
        async def _slow_check() -> ComponentHealth:
            await asyncio.sleep(10)
            return ComponentHealth("slow", "svc", HealthStatus.HEALTHY, "ok", _now())

        engine = RuntimeHealthEngine(check_timeout_s=0.05)
        engine.register("slow", _slow_check)
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.UNHEALTHY
        comp = health.component("slow")
        assert comp is not None
        assert "timed out" in comp.message

    async def test_check_raises_returns_unhealthy(self) -> None:
        async def _bad_check() -> ComponentHealth:
            raise RuntimeError("connection refused")

        engine = RuntimeHealthEngine()
        engine.register("db", _bad_check)
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.UNHEALTHY

    async def test_component_lookup(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("db", make_static_health_checker("db", "persistence"))
        health = await engine.aggregate_health()
        comp = health.component("db")
        assert comp is not None
        assert comp.component_id == "db"

    async def test_deregister(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("db", make_static_health_checker("db", "persistence", HealthStatus.UNHEALTHY))
        engine.deregister("db")
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.HEALTHY

    async def test_registered_components(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("db", make_static_health_checker("db", "persistence"))
        engine.register("kg", make_static_health_checker("kg", "knowledge_graph"))
        assert set(engine.registered_components()) == {"db", "kg"}

    async def test_callable_checker_true_is_healthy(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("q", make_callable_health_checker("q", "queue", fn=lambda: True))
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.HEALTHY

    async def test_callable_checker_false_is_unhealthy(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("q", make_callable_health_checker("q", "queue", fn=lambda: False))
        health = await engine.aggregate_health()
        assert health.overall_status == HealthStatus.UNHEALTHY

    async def test_check_component_direct(self) -> None:
        engine = RuntimeHealthEngine()
        engine.register("db", make_static_health_checker("db", "persistence"))
        comp = await engine.check_component("db")
        assert comp.status == HealthStatus.HEALTHY

    async def test_check_component_unregistered(self) -> None:
        engine = RuntimeHealthEngine()
        comp = await engine.check_component("missing")
        assert comp.status == HealthStatus.UNHEALTHY
