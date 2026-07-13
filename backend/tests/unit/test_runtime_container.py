"""Tests for RuntimeContainer construction and configuration — Sprint 27."""

from __future__ import annotations

from redforge.application.platform.backpressure import WatermarkBackpressureController
from redforge.application.platform.bulkhead import BulkheadRegistry
from redforge.application.platform.circuit_breaker import CircuitBreakerRegistry
from redforge.application.platform.dead_letter_queue import (
    InMemoryDeadLetterQueue,
    PoisonEventDetector,
)
from redforge.application.platform.health_engine import RuntimeHealthEngine
from redforge.application.platform.heartbeat import HeartbeatMonitor
from redforge.application.platform.lifecycle import GracefulShutdownCoordinator
from redforge.application.platform.metrics_abstraction import InMemoryMetricsCollector
from redforge.application.platform.runtime_container import (
    CB_CONNECTOR,
    CB_DATABASE,
    CB_EVENT_STORE,
    CB_KNOWLEDGE_GRAPH,
    RuntimeContainer,
    build_runtime_container,
)
from redforge.application.platform.runtime_contracts import LifecyclePhase
from redforge.core.config import Settings


def _test_settings(**overrides: object) -> Settings:
    return Settings(
        environment="test",
        database_url="postgresql+asyncpg://x:x@localhost/x",
        **overrides,  # type: ignore[arg-type]
    )


class TestBuildRuntimeContainer:
    def test_returns_runtime_container(self) -> None:
        s = _test_settings()
        c = build_runtime_container(s)
        assert isinstance(c, RuntimeContainer)

    def test_all_fields_populated(self) -> None:
        c = build_runtime_container(_test_settings())
        assert isinstance(c.coordinator, GracefulShutdownCoordinator)
        assert isinstance(c.health_engine, RuntimeHealthEngine)
        assert isinstance(c.dlq, InMemoryDeadLetterQueue)
        assert isinstance(c.poison_detector, PoisonEventDetector)
        assert isinstance(c.metrics, InMemoryMetricsCollector)
        assert isinstance(c.circuit_registry, CircuitBreakerRegistry)
        assert isinstance(c.bulkhead_registry, BulkheadRegistry)
        assert isinstance(c.heartbeat_monitor, HeartbeatMonitor)
        assert isinstance(c.backpressure, WatermarkBackpressureController)

    def test_standard_circuit_breakers_registered(self) -> None:
        c = build_runtime_container(_test_settings())
        names = c.circuit_registry.list_names()
        assert CB_EVENT_STORE in names
        assert CB_KNOWLEDGE_GRAPH in names
        assert CB_CONNECTOR in names
        assert CB_DATABASE in names

    def test_dlq_max_size_from_settings(self) -> None:
        c = build_runtime_container(_test_settings(runtime_dlq_max_size=500))
        assert c.dlq._max_size == 500

    def test_metrics_max_samples_from_settings(self) -> None:
        c = build_runtime_container(_test_settings(runtime_metrics_max_samples=200))
        assert c.metrics._max_samples == 200

    def test_poison_detector_threshold_from_settings(self) -> None:
        c = build_runtime_container(_test_settings(runtime_dlq_poison_threshold=7))
        assert c.poison_detector._poison_threshold == 7

    def test_coordinator_starts_in_initializing_phase(self) -> None:
        c = build_runtime_container(_test_settings())
        assert c.coordinator.phase == LifecyclePhase.INITIALIZING

    def test_circuit_breaker_failure_threshold_from_settings(self) -> None:
        c = build_runtime_container(
            _test_settings(runtime_circuit_breaker_failure_threshold=3)
        )
        cb = c.circuit_registry.get(CB_EVENT_STORE)
        assert cb is not None
        assert cb._failure_threshold == 3

    def test_circuit_breaker_window_size_from_settings(self) -> None:
        c = build_runtime_container(
            _test_settings(runtime_circuit_breaker_window_size=20)
        )
        cb = c.circuit_registry.get(CB_DATABASE)
        assert cb is not None
        assert cb._window_size == 20

    def test_backpressure_watermarks_from_settings(self) -> None:
        c = build_runtime_container(
            _test_settings(
                runtime_backpressure_high_watermark=0.9,
                runtime_backpressure_low_watermark=0.4,
            )
        )
        assert c.backpressure._cfg.high_watermark == 0.9
        assert c.backpressure._cfg.low_watermark == 0.4

    def test_each_call_returns_independent_container(self) -> None:
        s = _test_settings()
        c1 = build_runtime_container(s)
        c2 = build_runtime_container(s)
        assert c1 is not c2
        assert c1.coordinator is not c2.coordinator
        assert c1.health_engine is not c2.health_engine


class TestRuntimeSettings:
    def test_default_runtime_settings(self) -> None:
        s = _test_settings()
        assert s.runtime_circuit_breaker_failure_threshold == 5
        assert s.runtime_circuit_breaker_recovery_timeout_s == 30.0
        assert s.runtime_dlq_max_size == 10_000
        assert s.runtime_dlq_poison_threshold == 3
        assert s.runtime_health_check_timeout_s == 5.0
        assert s.runtime_heartbeat_interval_s == 30.0
        assert s.runtime_metrics_max_samples == 10_000
        assert s.runtime_shutdown_timeout_s == 30.0

    def test_runtime_settings_env_prefix(self) -> None:
        # Validates that the env_prefix is REDFORGE_ (all runtime_ fields match)
        s = _test_settings(
            runtime_dlq_max_size=99,
            runtime_health_check_timeout_s=2.5,
        )
        assert s.runtime_dlq_max_size == 99
        assert s.runtime_health_check_timeout_s == 2.5

    def test_backpressure_defaults_valid(self) -> None:
        s = _test_settings()
        assert s.runtime_backpressure_low_watermark > 0.0
        assert s.runtime_backpressure_low_watermark < s.runtime_backpressure_high_watermark
        assert s.runtime_backpressure_high_watermark <= 1.0


class TestLifecycleCoordinatorHooks:
    async def test_startup_transitions_to_running(self) -> None:
        c = build_runtime_container(_test_settings())
        called: list[str] = []

        async def hook_a() -> None:
            called.append("a")

        c.coordinator.register_startup("hook_a", hook_a)
        await c.coordinator.startup()
        assert c.coordinator.phase == LifecyclePhase.RUNNING
        assert "a" in called

    async def test_shutdown_transitions_to_stopped(self) -> None:
        c = build_runtime_container(_test_settings())
        await c.coordinator.startup()
        await c.coordinator.shutdown()
        assert c.coordinator.phase == LifecyclePhase.STOPPED

    async def test_hook_registration_reflected(self) -> None:
        c = build_runtime_container(_test_settings())

        async def noop() -> None:
            pass

        c.coordinator.register_startup("s1", noop)
        c.coordinator.register_shutdown("d1", noop)
        assert "s1" in c.coordinator.startup_hook_names()
        assert "d1" in c.coordinator.shutdown_hook_names()
